package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

var SupportedExecutors = []string{"bash", "sh", "command_prompt", "powershell"}

func Execute(runSpec *types.RunSpec, timeout int) (*types.ScriptResults, error, types.TestStatus) {
    retval := &types.ScriptResults{}
    retval.Spec = *runSpec

	fmt.Println()

	fmt.Println("****** EXECUTION PLAN ******")
	fmt.Println(" ", runSpec.Label)

	stage := runSpec.Stage
	if stage != "" {
		fmt.Println(" Stage:     " + stage)
	}

	stages := []string{"prereq", "test", "cleanup"}
	if "" != stage {
		stages = []string{stage}
	}

    if 0 == len(runSpec.Script.Name) {
        if "windows" == runtime.GOOS {
                fmt.Println("no executor specified. Using powershell")
                runSpec.Script.Name = "powershell"
        } else {
                fmt.Println("no executor specified. Using sh")
                runSpec.Script.Name = "sh"
        }
    }

    for name,val := range runSpec.EnvOverrides {
        fmt.Println("ENV override", name)
        os.Setenv(name, val)
    }

    var err error
	status := types.StatusUnknown
	for _, stage = range stages {
		switch stage {
		case "cleanup":
			_, err = executeStage(stage, runSpec.Script.Name, runSpec.Script.CleanupCommand, runSpec.ID, runSpec.Label, runSpec, timeout)
			if err != nil {
				fmt.Println("WARNING. Cleanup command failed", err)
			} else {
				retval.IsCleanedUp = true
			}

		case "prereq":
			if len(runSpec.Dependencies) != 0 {
				executorName := runSpec.DependencyExecutorName
				if len(executorName) == 0 {
					executorName = runSpec.Script.Name
				}
				if IsUnsupportedExecutor(executorName) {
					return nil, fmt.Errorf("dependency executor %s (%s) is not supported", runSpec.DependencyExecutorName, runSpec.Script.Name), types.StatusInvalidArguments
				}

				fmt.Printf("\nChecking dependencies...\n")

				for i, dep := range runSpec.Dependencies {
					fmt.Printf("  - %s", dep.Description)

					_, err := executeStage(fmt.Sprintf("checkPrereq%d", i), executorName, dep.PrereqCommand, runSpec.ID, runSpec.Label, runSpec, timeout)

					if err == nil {
						fmt.Printf("   * OK - dependency check succeeded!\n")
						continue
					}

					result, err := executeStage(fmt.Sprintf("getPrereq%d", i), executorName, dep.GetPrereqCommand, runSpec.ID, runSpec.Label, runSpec, timeout)

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
			if runSpec.Script == nil {
				return nil, fmt.Errorf("test has no executor"), types.StatusInvalidArguments
			}

			if IsUnsupportedExecutor(runSpec.Script.Name) {
				return nil, fmt.Errorf("executor %s is not supported", runSpec.Script.Name), types.StatusInvalidArguments
			}
			retval.StartTime = time.Now().UnixNano()

			results, err := executeStage(stage, runSpec.Script.Name, runSpec.Script.Command, runSpec.ID, runSpec.Label, runSpec, timeout)

			retval.EndTime = time.Now().UnixNano()

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

			retval.CommandStdout = results
			retval.ErrorMsg = errstr

		default:
			fmt.Printf("Unknown stage:" + stage)
			return nil, nil, types.StatusRunnerFailure
		}
	}
	return retval, nil, status

}

func IsUnsupportedExecutor(executorName string) bool {
	for _, e := range SupportedExecutors {
		if executorName == e {
			return false
		}
	}
	return true
}

func executeStage(stage, executorName, command string, technique, testName string, runSpec *types.RunSpec, timeout int) (string, error) {
	if command == "" {
		fmt.Println("Test does not have " + stage + " stage defined")
		return "", nil
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
	var err error
	switch executorName {
	case "bash":
		results, err = executeShell("bash", command, stage, technique, testName, runSpec, timeout)
	case "sh":
		results, err = executeShell("sh", command, stage, technique, testName, runSpec, timeout)
	case "command_prompt":
		results, err = executeCMD("CMD", command, stage, technique, testName, runSpec, timeout)
	case "powershell":
		results, err = executePS("POWERSHELL", command, stage, technique, testName, runSpec, timeout)
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

func executeShell(shellName string, command string, stage string, technique string, testName string, runSpec *types.RunSpec, timeout int) (string, error) {
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

	timeoutSec := time.Duration(timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec)
	defer cancel()

	cmd := exec.CommandContext(ctx, shellName, f.Name())

	//cmd.Env = append(os.Environ(), env...)

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

func executeCMD(shellName string, command string, stage string, technique string, testName string, runSpec *types.RunSpec, timeout int) (string, error) {
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

	timeoutSec := time.Duration(timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec)
	defer cancel()

	cmd := exec.CommandContext(ctx, shellName, "/c", f.Name())

	output, err := cmd.CombinedOutput()
	if err != nil {
		if context.DeadlineExceeded == ctx.Err() {
			return string(output), fmt.Errorf("TIMED OUT: script %w", err)
		}
		return string(output), fmt.Errorf("executing %s script: %w", shellName, err)
	}

	return string(output), nil
}

func executePS(shellName string, command string, stage string, technique string, testName string, runSpec *types.RunSpec, timeout int) (string, error) {
	command = "$ErrorActionPreference = \"Stop\"\n" + command // If a command fails then subsequent commands will not be executed
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

	timeoutSec := time.Duration(timeout) * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), timeoutSec)
	defer cancel()

	cmd := exec.CommandContext(ctx, shellName, "-ExecutionPolicy", "Bypass", "-NoProfile", f.Name())

	output, err := cmd.CombinedOutput()
	if err != nil {
		if context.DeadlineExceeded == ctx.Err() {
			return string(output), fmt.Errorf("TIMED OUT: script %w", err)
		}
		return string(output), fmt.Errorf("executing %s script: %w", shellName, err)
	}

	return string(output), nil
}
