package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"regexp"
	"runtime"
	"strings"

	types "github.com/secureworks/atomic-harness/pkg/types"

	"gopkg.in/yaml.v3"
)

var flagTechniqueId string
var flagTestName    string
var flagTestIndex   int
var flagTestStage   string
var flagAtomicsPath string
var flagTempDir     string
var flagRunSpecPath string
var flagResultsFormat string
var flagResultsDir string

var AtomicsFolderRegex = regexp.MustCompile(`PathToAtomicsFolder(\\|\/)`)
var BlockQuoteRegex    = regexp.MustCompile(`<\/?blockquote>`)

func init() {
        flag.StringVar(&flagTechniqueId, "t", "", "technique ID")
        flag.StringVar(&flagTestName, "n", "", "test name")
        flag.IntVar(&flagTestIndex, "i", -1, "0-based test index")

        flag.StringVar(&flagTestStage, "stage", "", "single stage (checkprereq, getprereq, test, cleanup)")
        flag.StringVar(&flagAtomicsPath, "atomicsdir", "", "path to atomics folder (required)")
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
	runSpec.Technique = flagTechniqueId
	runSpec.TestName = flagTestName
	runSpec.TestIndex = flagTestIndex
	runSpec.AtomicsDir = flagAtomicsPath
	runSpec.TempDir = flagTempDir
	runSpec.ResultsDir = flagResultsDir

	// TODO: get input args
	/*
	for _, arg := range flag.Args() {
		// get input settings and env variables

	}*/

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

	// TODO: check for required params

	atomicTest, err := getTest(runSpec.Technique, runSpec.TestName, runSpec.TestIndex, runSpec)
	if err != nil {
		fmt.Println("Unable to find AtomicTest for ", runSpec)
		os.Exit(int(types.StatusRunnerFailure))
	}

	if runSpec.TempDir == "" {
		runSpec.TempDir, err = os.MkdirTemp("", "goart-")
		if err != nil {
			fmt.Println("Error making temp dir", err)
			os.Exit(int(types.StatusRunnerFailure))
		}
		os.Chmod(runSpec.TempDir, 0777)
	} else {
		// TODO check if exists
		err = os.MkdirAll(runSpec.TempDir,0777)
		if err != nil {
			fmt.Println("Error making temp dir", runSpec.TempDir, err)
			os.Exit(int(types.StatusRunnerFailure))
		}
	}
	defer os.RemoveAll(runSpec.TempDir)

	if runSpec.ResultsDir != "" {
		err = os.MkdirAll(runSpec.ResultsDir,0777)
		if err != nil {
			fmt.Println("Error making results dir", runSpec.ResultsDir, err)
			os.Exit(int(types.StatusRunnerFailure))
		}
	}

	if runtime.GOOS != "windows" {
		ManagePrivilege(atomicTest, runSpec)
	}

	test, err, status := Execute(atomicTest, runSpec)
	if err != nil {
		fmt.Println("error occurred:", err)
		if test == nil {
			os.Exit(int(status))
		}
	}
	test.Status = int(status)

	var (
		plan []byte
		ext  = strings.ToLower(flagResultsFormat)
	)

	err = nil
	switch ext {
	case "json":
		plan, err = json.MarshalIndent(test,"","  ")
		if err != nil {
			fmt.Println("failed to marshal report", err)
		}
	case "yaml":
		plan, _ = yaml.Marshal(test)
		if err != nil {
			fmt.Println("failed to marshal report", err)
		}
	default:
		fmt.Println("unknown results format provided", ext)
		os.Exit(int(types.StatusInvalidArguments))
	}

	if len(plan) > 0 {
		if runSpec.ResultsDir == "" {
			fmt.Println(plan)
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
