package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"runtime"
	"strings"

	types "github.com/secureworks/atomic-harness/pkg/types"

	"gopkg.in/yaml.v3"
)

var flagTestStage string
var flagTempDir string
var flagRunSpecPath string
var flagResultsFormat string
var flagResultsDir string

func init() {

	flag.StringVar(&flagTestStage, "stage", "", "single stage (checkprereq, getprereq, test, cleanup)")
	flag.StringVar(&flagTempDir, "tempdir", "", "path to working folder to use for test. Will be random if not set")
	flag.StringVar(&flagRunSpecPath, "config", "", "path to RunSpec config. Use - for stdin")
	flag.StringVar(&flagResultsFormat, "resultsformat", "json", "json or yaml output summary file")
	flag.StringVar(&flagResultsDir, "resultsdir", "", "location to save output")
}

func LoadRunSpec(path string, runSpec *types.RunSpec) error {
	var err error
	data := []byte{}

	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, runSpec); err != nil {
		fmt.Println("Error parsing RunSpec", path, err)
		return err
	}
	return nil
}

func FillRunSpecFromFlags(runSpec *types.RunSpec) {
	runSpec.TempDir = flagTempDir
	runSpec.ResultsDir = flagResultsDir
}

func main() {
	flag.Parse()
	runSpec := &types.RunSpec{}
	var err error

	if flagRunSpecPath != "" {
		err = LoadRunSpec(flagRunSpecPath, runSpec)
	} else {
		FillRunSpecFromFlags(runSpec)
	}
	timeout := runSpec.Timeout
	// TODO: check for required params

	if runSpec.TempDir == "" {
		runSpec.TempDir, err = os.MkdirTemp("", "goart-")
		if err != nil {
			fmt.Println("Error making temp dir", err)
			os.Exit(int(types.StatusRunnerFailure))
		}
		os.Chmod(runSpec.TempDir, 0777)
	} else {
		// TODO check if exists
		err = os.MkdirAll(runSpec.TempDir, 0777)
		if err != nil {
			fmt.Println("Error making temp dir", runSpec.TempDir, err)
			os.Exit(int(types.StatusRunnerFailure))
		}
	}
	defer os.RemoveAll(runSpec.TempDir)

	if runSpec.ResultsDir != "" {
		err = os.MkdirAll(runSpec.ResultsDir, 0777)
		if err != nil {
			fmt.Println("Error making results dir", runSpec.ResultsDir, err)
			os.Exit(int(types.StatusRunnerFailure))
		}
	}

	if runtime.GOOS != "windows" {
		ManagePrivilege(runSpec)
	}

	retval, err, status := Execute(runSpec, int(timeout))
	if err != nil {
		fmt.Println("error occurred:", err)
		if retval == nil {
			os.Exit(int(status))
		}
	}
	retval.Status = int(status)

	var (
		plan []byte
		ext  = strings.ToLower(flagResultsFormat)
	)

	err = nil
	switch ext {
	case "json":
		plan, err = json.MarshalIndent(retval, "", "  ")
		if err != nil {
			fmt.Println("failed to marshal report", err)
		}
	case "yaml":
		plan, _ = yaml.Marshal(retval)
		if err != nil {
			fmt.Println("failed to marshal report", err)
		}
	default:
		fmt.Println("unknown results format provided", ext)
		os.Exit(int(types.StatusInvalidArguments))
	}

	if len(plan) > 0 {
		if runSpec.ResultsDir == "" {
			fmt.Println(string(plan))
		} else {
			resultsFilePath := runSpec.ResultsDir + "/run_summary." + ext
			err = ioutil.WriteFile(resultsFilePath, plan, 0644)
			if err != nil {
				fmt.Println("ERROR: unable to write results file", resultsFilePath, err)
			}
		}
	}

	fmt.Println("done")
	os.Exit(int(status))
}
