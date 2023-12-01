package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	types "github.com/secureworks/atomic-harness/pkg/types"
	utils "github.com/secureworks/atomic-harness/pkg/utils"
)

var SupportedExecutors = []string{"bash", "sh", "command_prompt", "powershell"}

func Execute(test *types.AtomicTest, runSpec *types.RunSpec) (*types.AtomicTest, error, types.TestStatus) {
	tid := runSpec.Technique
	env := []string{} // TODO

	fmt.Println()

	fmt.Println("****** EXECUTION PLAN ******")
	fmt.Println(" Technique: " + tid)
	fmt.Println(" Test:      " + test.Name)

	stage := runSpec.Stage
	if stage != "" {
		fmt.Println(" Stage:     " + stage)
	}

	if len(runSpec.Inputs) == 0 {
		fmt.Println(" Inputs:    <none>")
	} else {
		fmt.Println(" Inputs:    ", runSpec.Inputs)
	}
	/*
		if env == nil {
			fmt.Println(" Env:       <none>")
		} else {
			fmt.Println(" Env:       " + strings.Join(env, "\n            "))
		}
	*/
	fmt.Println(" * Use at your own risk :) *")
	fmt.Println("****************************")

	args, err := checkArgsAndGetDefaults(test, runSpec)
	if err != nil {
		return nil, err, types.StatusInvalidArguments
	}

	// overwrite with actual args used
	test.ArgsUsed = args

	if err := checkPlatform(test); err != nil {
		return nil, err, types.StatusInvalidArguments
	}

	//var results string

	stages := []string{"prereq", "test", "cleanup"}
	if "" != stage {
		stages = []string{stage}
	}

	status := types.StatusUnknown
	for _, stage = range stages {
		switch stage {
		case "cleanup":
			_, err = executeStage(stage, test.Executor.CleanupCommand, test.Executor.Name, test.BaseDir, args, env, tid, test.Name, runSpec)
			if err != nil {
				fmt.Println("WARNING. Cleanup command failed", err)
			} else {
				test.IsCleanedUp = true
			}

		case "prereq":
			if len(test.Dependencies) != 0 {
				executorName := test.DependencyExecutorName
				if len(executorName) == 0 {
					executorName = test.Executor.Name
				}
				if IsUnsupportedExecutor(executorName) {
					return nil, fmt.Errorf("dependency executor %s (%s) is not supported", test.DependencyExecutorName, test.Executor.Name), types.StatusInvalidArguments
				}

				fmt.Printf("\nChecking dependencies...\n")

				for i, dep := range test.Dependencies {
					fmt.Printf("  - %s", dep.Description)

					_, err := executeStage(fmt.Sprintf("checkPrereq%d", i), dep.PrereqCommand, executorName, test.BaseDir, args, env, tid, test.Name, runSpec)

					if err == nil {
						fmt.Printf("   * OK - dependency check succeeded!\n")
						continue
					}

					result, err := executeStage(fmt.Sprintf("getPrereq%d", i), dep.GetPrereqCommand, executorName, test.BaseDir, args, env, tid, test.Name, runSpec)

					if err != nil {
						if result == "" {
							result = "no details provided"
						}

						fmt.Printf("   * XX - dependency check failed: %s\n", result)

						return nil, fmt.Errorf("not all dependency checks passed"), types.StatusPreReqFail
					}
				}
			}
		case "test":
			if test.Executor == nil {
				return nil, fmt.Errorf("test has no executor"), types.StatusInvalidArguments
			}

			if IsUnsupportedExecutor(test.Executor.Name) {
				return nil, fmt.Errorf("executor %s is not supported", test.Executor.Name), types.StatusInvalidArguments
			}
			test.StartTime = time.Now().UnixNano()

			results, err := executeStage(stage, test.Executor.Command, test.Executor.Name, test.BaseDir, args, env, tid, test.Name, runSpec)

			test.EndTime = time.Now().UnixNano()

			errstr := ""
			if err != nil {
				fmt.Println("****** EXECUTOR FAILED ******")
				status = types.StatusTestFail
				errstr = fmt.Sprint(err)
			} else {
				fmt.Println("****** EXECUTOR RESULTS ******")
				status = types.StatusTestSuccess
			}
			if results != "" {
				fmt.Println(results)
				fmt.Println("******************************")
			}

			// save state

			for k, v := range test.InputArugments {
				v.ExpectedValue = args[k]
				test.InputArugments[k] = v
			}

			test.Executor.ExecutedCommand = map[string]interface{}{
				"command": test.Executor.Command, /* command */
				"results": results,
				"err":     errstr,
			}

		default:
			fmt.Printf("Unknown stage:" + stage)
			return nil, nil, types.StatusRunnerFailure
		}
	}
	return test, nil, status

}

func IsUnsupportedExecutor(executorName string) bool {
	for _, e := range SupportedExecutors {
		if executorName == e {
			return false
		}
	}
	return true
}

func getTest(tid, name string, index int, runSpec *types.RunSpec) (*types.AtomicTest, error) {
	fmt.Printf("\nGetting Atomic Tests technique %s from %s\n", tid, runSpec.AtomicsDir)

	technique, err := utils.LoadAtomicsTechniqueYaml(tid, runSpec.AtomicsDir)
	if err != nil {
		return nil, fmt.Errorf("getting Atomic Tests technique: %w", err)
	}

	fmt.Printf("  - technique has %d tests\n", len(technique.AtomicTests))

	var test *types.AtomicTest

	if index >= 0 && index < len(technique.AtomicTests) {
		test = &technique.AtomicTests[index]
	} else {
		for _, t := range technique.AtomicTests {
			if t.Name == name {
				test = &t
				break
			}
		}
	}

	if test == nil {
		return nil, fmt.Errorf("could not find test %s/%s", tid, name)
	}

	test.BaseDir = technique.BaseDir
	test.TempDir = runSpec.TempDir

	fmt.Printf("  - found test named %s\n", test.Name)

	return test, nil
}

func checkArgsAndGetDefaults(test *types.AtomicTest, runSpec *types.RunSpec) (map[string]string, error) {
	var (
		updated = make(map[string]string)
	)

	if len(test.InputArugments) == 0 {
		return updated, nil
	}

	keys := []string{}
	for k := range runSpec.Inputs {
		keys = append(keys, k)
	}

	fmt.Println("\nChecking arguments...")

	if len(keys) > 0 {
		fmt.Println("  - supplied in config/flags: " + strings.Join(keys, ", "))
	}

	for k, v := range test.InputArugments {
		fmt.Println("  - checking for argument " + k)

		val, ok := runSpec.Inputs[k] //args[k]

		if ok {
			fmt.Println("   * OK - found argument in supplied args")
		} else {
			fmt.Println("   * XX - not found, trying default arg")

			val = v.Default

			if val == "" {
				return nil, fmt.Errorf("argument [%s] is required but not set and has no default", k)
			} else {
				fmt.Println("   * OK - found argument in defaults")
			}
		}

		updated[k] = val
	}

	return updated, nil
}

func checkPlatform(test *types.AtomicTest) error {
	var platform string

	switch runtime.GOOS {
	case "linux", "freebsd", "netbsd", "openbsd", "solaris":
		platform = "linux"
	case "darwin":
		platform = "macos"
	case "windows":
		platform = "windows"
	}

	if platform == "" {
		return fmt.Errorf("unable to detect our platform")
	}

	fmt.Printf("\nChecking platform vs our platform (%s)...\n", platform)

	var found bool

	for _, p := range test.SupportedPlatforms {
		if p == platform {
			found = true
			break
		}
	}

	if found {
		fmt.Println("  - OK - our platform is supported!")
	} else {
		return fmt.Errorf("unable to run test that supports platforms %v because we are on %s", test.SupportedPlatforms, platform)
	}

	return nil
}

func executeStage(stage, cmds, executorName, base string, args map[string]string, env []string, technique, testName string, runSpec *types.RunSpec) (string, error) {
	quiet := true

	if stage == "test" {
		quiet = false
	}

	if cmds == "" {
		fmt.Println("Test does not have " + stage + " stage defined")
		return "", nil
	}

	command, err := interpolateWithArgs(cmds, base, args, quiet)
	if err != nil {
		fmt.Println("    * FAIL - "+stage+" failed", err)
		return "", err
	}

	if 0 == len(executorName) {
		if "windows" == runtime.GOOS {
			fmt.Println("no", stage, "executor specified. Using powershell")
			executorName = "powershell"
		} else {
			fmt.Println("no", stage, "executor specified. Using sh")
			executorName = "sh"
		}
	}

	var results string
	switch executorName {
	case "bash":
		results, err = executeShell("bash", command, env, stage, technique, testName, runSpec)
	case "sh":
		results, err = executeShell("sh", command, env, stage, technique, testName, runSpec)
	case "command_prompt":
		results, err = executeCMD("CMD", command, env, stage, technique, testName, runSpec)
	case "powershell":
		results, err = executePS("POWERSHELL", command, env, stage, technique, testName, runSpec)
	default:
		err = fmt.Errorf("unknown executor: " + executorName)
	}

	if err != nil {
		fmt.Printf("   * FAIL - "+stage+" failed!\n", err)
		return results, err
	}
	fmt.Printf("   * OK - " + stage + " succeeded!\n")
	return results, nil
}

func interpolateWithArgs(interpolatee, base string, args map[string]string, quiet bool) (string, error) {
	interpolated := strings.TrimSpace(interpolatee)

	// replace folder path if present in script

	interpolated = strings.ReplaceAll(interpolated, "$PathToAtomicsFolder", base)
	interpolated = strings.ReplaceAll(interpolated, "PathToAtomicsFolder", base)

	if len(args) == 0 {
		return interpolated, nil
	}

	if !quiet {
		fmt.Println("\nInterpolating command with input arguments...")
	}

	for k, v := range args {
		if !quiet {
			fmt.Printf("  - interpolating [#{%s}] => [%s]\n", k, v)
		}
		if !strings.HasPrefix(v, "http") { // No modification of slashes in case of URLs
			if AtomicsFolderRegex.MatchString(v) {
				v = AtomicsFolderRegex.ReplaceAllString(v, "")
				v = strings.ReplaceAll(v, `\`, `/`)
				v = strings.TrimSuffix(base, "/") + "/" + v
			}

			v = filepath.FromSlash(v)
		}
		interpolated = strings.ReplaceAll(interpolated, "#{"+k+"}", v)
	}

	return interpolated, nil
}

func executeShell(shellName string, command string, env []string, stage string, technique string, testName string, runSpec *types.RunSpec) (string, error) {
	fmt.Printf("\nExecuting executor=%s command=[%s]\n", shellName, command)

	f, err := os.Create(runSpec.TempDir + "/goart-" + technique + "-" + stage + "." + shellName)

	if err != nil {
		return "", fmt.Errorf("creating temporary file: %w", err)
	}

	if _, err := f.Write([]byte(command)); err != nil {
		f.Close()

		return "", fmt.Errorf("writing command to file: %w", err)
	}

	if err := f.Close(); err != nil {
		return "", fmt.Errorf("closing %s script: %w", shellName, err)
	}

	// guard against hanging tests - kill after a timeout

	timeoutSec := 30 * time.Second
	if stage != "test" {
		timeoutSec = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec)
	defer cancel()

	cmd := exec.CommandContext(ctx, shellName, f.Name())

	cmd.Env = append(os.Environ(), env...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if context.DeadlineExceeded == ctx.Err() {
			return string(output), fmt.Errorf("TIMED OUT: script %w", err)
		}
		return string(output), fmt.Errorf("executing %s script: %w", shellName, err)
	}
	/*
		err = ctx.Err()
		if err != nil {

			if context.DeadlineExceeded == err {
				return string(output), fmt.Errorf("TIMED OUT: script %w", err)
			} else {
				return string(output), fmt.Errorf("ERROR: script %w", err)
			}
		}*/

	return string(output), nil
}

func executeCMD(shellName string, command string, env []string, stage string, technique string, testName string, runSpec *types.RunSpec) (string, error) {
	fmt.Printf("\nExecuting executor=%s command=[%s]\n", shellName, command)

	f, err := os.Create(runSpec.TempDir + "\\goart-" + technique + "-" + stage + ".bat")

	if err != nil {
		return "", fmt.Errorf("creating temporary file: %w", err)
	}

	if _, err := f.Write([]byte(command)); err != nil {
		f.Close()

		return "", fmt.Errorf("writing command to file: %w", err)
	}

	if err := f.Close(); err != nil {
		return "", fmt.Errorf("closing %s script: %w", shellName, err)
	}

	// guard against hanging tests - kill after a timeout

	timeoutSec := 30 * time.Second
	if stage != "test" {
		timeoutSec = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec)
	defer cancel()

	cmd := exec.CommandContext(ctx, shellName, "/c", f.Name())

	cmd.Env = append(os.Environ(), env...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if context.DeadlineExceeded == ctx.Err() {
			return string(output), fmt.Errorf("TIMED OUT: script %w", err)
		}
		return string(output), fmt.Errorf("executing %s script: %w", shellName, err)
	}

	return string(output), nil
}

func executePS(shellName string, command string, env []string, stage string, technique string, testName string, runSpec *types.RunSpec) (string, error) {
	fmt.Printf("\nExecuting executor=%s command=[%s]\n", shellName, command)

	f, err := os.Create(runSpec.TempDir + "\\goart-" + technique + "-" + stage + ".ps1")

	if err != nil {
		return "", fmt.Errorf("creating temporary file: %w", err)
	}

	if _, err := f.Write([]byte(command)); err != nil {
		f.Close()

		return "", fmt.Errorf("writing command to file: %w", err)
	}

	if err := f.Close(); err != nil {
		return "", fmt.Errorf("closing %s script: %w", shellName, err)
	}

	// guard against hanging tests - kill after a timeout

	timeoutSec := 30 * time.Second
	if stage != "test" {
		timeoutSec = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec)
	defer cancel()

	cmd := exec.CommandContext(ctx, shellName, "-ExecutionPolicy", "Bypass", "-NoProfile", f.Name())

	cmd.Env = append(os.Environ(), env...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if context.DeadlineExceeded == ctx.Err() {
			return string(output), fmt.Errorf("TIMED OUT: script %w", err)
		}
		return string(output), fmt.Errorf("executing %s script: %w", shellName, err)
	}

	return string(output), nil
}
