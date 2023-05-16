package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil" // TODO: shouldn't need this anymore
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	types "github.com/secureworks/atomic-harness/pkg/types"
	utils "github.com/secureworks/atomic-harness/pkg/utils"
)

type SingleTestRun struct {
    state      types.TestState
    exitCode   int
    status     types.TestStatus
    matchString string       // output from telemetry tool shows which expected event types matched

    criteria   *types.AtomicTestCriteria

    resultsDir string
    workingDir string

    StartTime         int64  // timestamps returned by goartrun for test
    EndTime           int64

    TimeOfParentShell int64  // determined using IsGoArtStage()
    TimeOfNextStage   int64
    ShellPid          int64
    TimeWorkDirCreate int64
    TimeWorkDirDelete int64
}

var kTestRunTimeoutSeconds = 10*time.Second
var kWaitTelemetrySeconds = 35
var VarSubRegex = regexp.MustCompile(`#{.*}`)

var flagCriteriaPath  string
var flagAtomicsPath  string
var flagResultsPath  string

var flagGoArtRunnerPath  string
var flagTelemetryToolPath string
var flagTechniquesFilePath string
var flagServerConfigsCsvPath string
var flagRegularRunUser string
var flagRetryFailed string
var flagClearTelemetryCache bool
var flagFilterByGoartrunShell bool
var flagFilterFileEventsTmp bool

var gTestSpecs []*types.TestSpec = []*types.TestSpec{}
var gRecs []*types.AtomicTestCriteria = []*types.AtomicTestCriteria{} // our detection rules
var gSysInfo = &types.SysInfoVars{}
var gVerbose = false
var gDebug = false
var gServerConfigs = map[string]string{}
var gTechniquesMissingTests = []string{}
var gMitreTechniqueNames = map[string]string{} // loaded from data/linux_techniques.csv
var gFlagNoRun = false
var gKeepRunning = true
var gAtomicTests = map[string][]*types.TestSpec{} // tid -> tests

func init() {
	flag.StringVar(&flagCriteriaPath, "criteriapath", "", "path to folder containing CSV files used to validate telemetry")
	flag.StringVar(&flagAtomicsPath, "atomicspath", "", "path to local atomics folder")
	flag.StringVar(&flagResultsPath, "resultspath", "", "path to folder holding results. Will be generated relative to current dir if empty")

	flag.StringVar(&flagGoArtRunnerPath, "goartpath", "", "path to runner binary")
	flag.StringVar(&flagTelemetryToolPath, "telemetrytoolpath", "", "path to telemetry tool binary")
	flag.StringVar(&flagTechniquesFilePath, "runlist", "", "path to file containing list of techniques to run. CSV or newline-delimited text")
	flag.StringVar(&flagServerConfigsCsvPath, "serverscsv", "", "path to CSV file containing list of servers referenced in detection rules")
	flag.StringVar(&flagRegularRunUser, "username", "", "Optional username for running unpriviledged tests")
	flag.BoolVar(&gVerbose, "verbose", false, "print more details")
	flag.BoolVar(&gDebug, "debug", false, "print debugging details")
	flag.BoolVar(&gFlagNoRun, "norun", false, "exit without running any tests")
	flag.StringVar(&flagRetryFailed, "retryfailed","","path to previous resultsdir, re-run tests not Validated or Skipped")
	flag.BoolVar(&flagClearTelemetryCache, "telemetryclear", false, "if true, will call telemetry tool to clear cache")
	flag.BoolVar(&flagFilterByGoartrunShell, "filtergoartsh", true, "if true, do not validate events before/after goartrun test shell")
	flag.BoolVar(&flagFilterFileEventsTmp, "filtergoartdir", true, "if true, do not validate events before/after create and delete of goartrun working dir. Working dir is in /tmp, so if that is not in the file monitoring paths of endpoint agent, set this to false.")
}

/*
	T1027.001#1

	"T1027,Decode base64 Data into Script"

	T1027.002#2

	"T1027.002,Binary packed by UPX, with modified headers (linux)""
*/
func ParseTestSpecs(techniques []string) bool {
	if len(techniques) == 0 {
		return false
	}

	for _,str := range techniques {
		if len(str) < 4 || str[0] != 'T' {
			fmt.Println("ERROR unknown test spec format:", str)
			return false
		}

		if strings.Contains(str,"..") {
			a := strings.SplitN(str,"..",2)
			AddTestRange(a[0],a[1])
			continue
		}

		if strings.Contains(str,"#") {
			a := strings.SplitN(str,"#",2)
			spec := &types.TestSpec{}
			spec.Technique = a[0]
			spec.TestIndex = a[1]
			// TODO: validate TestIndex is uint >= 1
			gTestSpecs = append(gTestSpecs, spec)

		} else if strings.Contains(str,",") {

			a := strings.SplitN(str,",",2)
			spec := &types.TestSpec{}
			spec.Technique = a[0]
			spec.TestName = a[1]
			gTestSpecs = append(gTestSpecs, spec)

		} else {
			spec := &types.TestSpec{}
			spec.Technique = str
			gTestSpecs = append(gTestSpecs, spec)
		}
	}
	return true
}

// use relative paths for dependencies if not provided
func FillInToolPathDefaults() {
	cwd,_ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	if flagCriteriaPath == "" {
		flagCriteriaPath = cwd + "/../atomic-validation-criteria/"
		if runtime.GOOS == "darwin" { // macOS 
			flagCriteriaPath += "macos"
		} else {
			flagCriteriaPath += "linux"
		}
	}
	if flagAtomicsPath == "" {
		flagAtomicsPath = cwd + "/../atomic-red-team/atomics"
	}
	if flagGoArtRunnerPath == "" {
		flagGoArtRunnerPath = cwd + "/../goartrun/bin/goartrun"
	}
	if flagTelemetryToolPath == "" {
		flagTelemetryToolPath = "./telemtool"  // symlink to path of actual binary ?
	}	
}

func MissingCmdlineArgs() bool {

	// check criteria path

	if len(flagCriteriaPath) == 0 {
		fmt.Println("ERROR: missing criteriapath argument")
		return true
	}

	info, err := os.Stat(flagCriteriaPath)
	if os.IsNotExist(err) {
		fmt.Println("criteriapath does not exist", flagCriteriaPath)
		return true
	} else if err != nil {
		fmt.Println("IO error",err," file:", flagCriteriaPath)
		return true
	}

	if false == info.IsDir() {
		fmt.Println("should be a directory:", flagCriteriaPath)
		return true
	}

	// check atomics path

	if len(flagAtomicsPath) > 0 {
		info, err := os.Stat(flagAtomicsPath)
		if os.IsNotExist(err) {
			fmt.Println("atomicspath does not exist", flagAtomicsPath)
			return true
		} else if err != nil {
			fmt.Println("IO error",err," file:", flagAtomicsPath)
			return true
		}

		if false == info.IsDir() {
			fmt.Println("should be a directory:", flagAtomicsPath)
			return true
		}
	}

	// check goart runner path

	if len(flagGoArtRunnerPath) == 0 {
		fmt.Println("ERROR: missing goartpath argument")
		return true
	}

	info, err = os.Stat(flagGoArtRunnerPath)
	if os.IsNotExist(err) {
		fmt.Println("goartpath does not exist", flagGoArtRunnerPath)
		return true
	} else if err != nil {
		fmt.Println("IO error",err," file:", flagGoArtRunnerPath)
		return true
	}

	if true == info.IsDir() {
		fmt.Println("should be a file:", flagGoArtRunnerPath)
		return true
	}

	return false
}

func LoadCriteriaFiles(dirPath string) bool {
	allfiles, err := ioutil.ReadDir(dirPath)
	if err != nil {
		fmt.Println("ERROR: unable to list files in " + dirPath, err)
		return false
	}
	for _,f := range allfiles {
		if !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}

		if gVerbose {
			fmt.Println("Loading " + f.Name())
		}

		err := LoadFile(dirPath + "/" + f.Name())
		if err != nil {
			fmt.Println("ERROR:", err);
			return false
		}
	}

	return true
}


func AddTestRange(from string, to string) int {
	num := 0
	for _,rec := range gRecs {
		if rec.Technique >= from && rec.Technique <= to {

			spec := &types.TestSpec{}
			spec.Technique = rec.Technique
			spec.TestIndex = fmt.Sprintf("%d",rec.TestIndex)
			spec.TestName = rec.TestName

			gTestSpecs = append(gTestSpecs, spec)
			num += 1
		}
	}
	return num
}

func SpecAlreadyExists(tid string, testIndex string, testName string) bool {
	for _,entry := range gTestSpecs {
		if entry.Technique == tid {
			if entry.TestIndex != "" {
				if entry.TestIndex == testIndex {
					return true
				}
			} else if entry.TestName != "" {
				if entry.TestName == testName {
					return true
				}
			} else {
				return true
			}
		}
	}
	return false
}

/*
 * Add All tests for which we have criteria for the technique ID
 */
func AddTestsForTechniqueUsingCriteria(tid string) int {
	num := 0
	for _,rec := range gRecs {
		if !strings.HasPrefix(rec.Technique, tid) {
			continue
		}

		if rec.Technique != tid && gVerbose {
			fmt.Println("using",rec.Technique,"for",tid)
		}

		if SpecAlreadyExists(rec.Technique, fmt.Sprintf("%d",rec.TestIndex), rec.TestName) {
			if gVerbose {
				fmt.Println(rec.Id(),"already added")
			}
			num += 1
			continue
		}

		spec := &types.TestSpec{}
		spec.Technique = rec.Technique
		spec.TestIndex = fmt.Sprintf("%d",rec.TestIndex)
		spec.TestName = rec.TestName

		gTestSpecs = append(gTestSpecs, spec)
		num += 1
	}
	return num
}

/*
 * Add All tests for which there are atomic tests in the Indexes-CSV
 */
func AddTestsForTechniqueUsingAtomicsIndex(targetTid string) int {
	num := 0
	for tid,specs := range gAtomicTests {
		if !strings.HasPrefix(tid, targetTid) {
			continue
		}

		if targetTid != tid && gVerbose {
			fmt.Println("Using",tid,"for",targetTid)
		}

		for _,spec := range specs {
			if SpecAlreadyExists(spec.Technique, spec.TestIndex, spec.TestName) {
				if gVerbose {
					fmt.Println(spec,"already added")
				}
				num += 1
				continue
			}

			gTestSpecs = append(gTestSpecs, spec)
			num += 1
		}
	}
	return num
}


func AddOnce(spec *types.TestSpec, entry *types.AtomicTestCriteria) {
	for i,_ := range spec.Criteria {
		if spec.Criteria[i].Id() == entry.Id() {
			return
		}
	}

	if gVerbose {
		fmt.Printf("Add criteria %s for spec %s\n",entry.Id(), spec)
	}

	spec.Criteria = append(spec.Criteria, entry)
}

/*
 * gTestSpecs is usually just a techniqueId
 *
 */
func FindCriteriaForTestSpecs() bool {
	for _,spec := range gTestSpecs {
		for _,rec := range gRecs {
			if rec.Technique != spec.Technique  {
				continue
			}

			//fmt.Println("Compare:", rec.Id(), spec)

			if spec.TestIndex == "" {
				if spec.TestName != "" {
					if spec.TestName == rec.TestName {
						AddOnce(spec, rec)
					}
				} else {
					// not specified, so take any and all
					AddOnce(spec, rec)
				}
			} else {
				if spec.TestIndex == fmt.Sprintf("%d",rec.TestIndex) {
					if spec.TestName != "" && spec.TestName != rec.TestName {
						fmt.Println("WARN: detection name does not match:", spec.TestName)
						fmt.Println("  Det Rule:",rec.Technique,rec.TestIndex,rec.TestName)
					}
					AddOnce(spec, rec)
				}
			}

		}
	}

	isMissing := false
	for _,spec := range gTestSpecs {
		if len(spec.Criteria) == 0 {
			if spec.TestIndex == "" && spec.TestName == "" {
				gTechniquesMissingTests = append(gTechniquesMissingTests, spec.Technique)
				continue
			}
			fmt.Println("FAIL to find criteria for ", spec)
			isMissing = true
		}
	}
	return !isMissing
}


/*
 * @return true if all substitutions were met
 */
func SubstituteVarsInCriteria(criteria *types.AtomicTestCriteria) bool {

	for key,val := range criteria.Args {
		needle := "#{" + key + "}"
		for i,exp := range criteria.ExpectedEvents {
			for j,f := range exp.FieldChecks {
				if strings.Contains(f.Value, needle) {
					old := f.Value
					criteria.ExpectedEvents[i].FieldChecks[j].Value = strings.ReplaceAll(f.Value,needle,val)
					if gVerbose {
						fmt.Println("  criteria substitute",old,criteria.ExpectedEvents[i].FieldChecks[j].Value)
					}
				}
			}
			if strings.ToUpper(exp.EventType) == "NETFLOW" { // TODO: this is awkward, move from subtype to fieldcheck?
				if strings.Contains(exp.SubType, needle) {
					old := exp.SubType
					criteria.ExpectedEvents[i].SubType = strings.ReplaceAll(exp.SubType,needle,val)
					if gVerbose {
						fmt.Println("  criteria substitute",old,criteria.ExpectedEvents[i].SubType)
					}
				}
			}
		}
	}

	// TODO: check for special items like $HOME (different on linux,macos) and privilege level

	// run through again to see if any remain

	for _,exp := range criteria.ExpectedEvents {
		for _,f := range exp.FieldChecks {
			if VarSubRegex.MatchString(f.Value) {
				fmt.Println("MISSING criteria variable",f.Value)
				return false
			}
		}
		if strings.ToUpper(exp.EventType) == "NETFLOW" {
			if VarSubRegex.MatchString(exp.SubType) {
				fmt.Println("MISSING criteria variable",exp.SubType)
				return false
			}
		}
	}
	return true
}

func ClearTelemetryCache() {
	// TODO: build command-line from config
	cmd := exec.Command(flagTelemetryToolPath,"--clearcache")

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("Failed to clear telemetry cache", err)
		return
	}
	if len(output) != 0 {
		fmt.Println("  " + string(output))
	}
}

func LaunchTelemetryExtractor(testRun *SingleTestRun) {

	outPath := testRun.resultsDir + "/validate_spec.json"

	// open file to write
	fileHandle, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		fmt.Println("ERROR: unable to write file", outPath, err)
	}
	
	enc := json.NewEncoder(fileHandle)
	enc.SetEscapeHTML(false)
	enc.SetIndent("","  ")

	// write test criteria to file
	err = enc.Encode(testRun.criteria)
	if err != nil {
		fmt.Println("ERROR:", err);
		return
	}
	fileHandle.Close()


	// TODO: build command-line from config

	cmd := exec.Command(flagTelemetryToolPath,"--fetch", "--resultsdir", testRun.resultsDir, "--ts", fmt.Sprintf("%d,%d", testRun.StartTime, testRun.EndTime))

	fmt.Println("launching ",cmd.String())
	output, err := cmd.CombinedOutput()

	exitCode := cmd.ProcessState.ExitCode()
	status := types.TestStatus(exitCode)

	//look for StateValidateSuccess, etc.
	fmt.Println("telemetry tool exit code:",exitCode, status)

	if exitCode >= int(types.StatusTelemetryToolFailure) && exitCode <= int(types.StatusValidateSuccess) {
		testRun.status = status
	}

	if err != nil && exitCode <= int(types.StatusValidateFail) {
		fmt.Println("  telemetry tool err:", err)
	}
	if len(output) != 0 {
		outPath := testRun.resultsDir + "/telemetry_tool_output.txt"
		err = os.WriteFile(outPath, output, 0644)
		if err != nil {
			fmt.Println("ERROR: unable to write file", outPath, err)
		}
	}

	if int(types.StatusDelegateValidation) == exitCode {
		// read `simple_telemetry.json` and validate
		ValidateSimpleTelemetry(testRun)
	}
}

func UpdateTimestampsFromRunSummary(testRun *SingleTestRun) {
	path := testRun.resultsDir + "/run_summary.json"
	data, err := os.ReadFile(path)
	if err != nil {
		if gVerbose {
			fmt.Println("unable to read run_summary", err)
		}
		return
	}
	runSpec := &types.AtomicTest{}
	if err = json.Unmarshal(data, runSpec); err != nil {
		fmt.Println("Error parsing run_summary.json", path, err)
		return
	}

	testRun.StartTime = runSpec.StartTime
	testRun.EndTime = runSpec.EndTime
}

// echo runSpecJson | ./bin/goart --config - 

func GoArtRunTest(testRun *SingleTestRun, runSpecJson string) {

	fmt.Printf("Running test %s #%d \"%s\"\n",testRun.criteria.Technique, testRun.criteria.TestIndex, testRun.criteria.TestName)

	cmd := exec.Command(flagGoArtRunnerPath,"--config","-")

	dest, err := cmd.StdinPipe()
	if err != nil {
		fmt.Errorf("executing runner: %w", err)
		return
	}
	_,err = io.WriteString(dest, runSpecJson)
	dest.Close()

	//TODO : cmd.Env = append(os.Environ(), env...)

	// launch shell

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Errorf("  runner error: %w", err)
	} else {
		fmt.Println("  runner finished without error")
	}

	// write shell stdout to file

	outPath := testRun.resultsDir + "/runner-stdout.txt"
	err = os.WriteFile(outPath, output, 0644)
	if err != nil {
		fmt.Println("ERROR: unable to write file", outPath, err)
	}


	testRun.exitCode = cmd.ProcessState.ExitCode()
	testRun.status = types.TestStatus(testRun.exitCode)
	fmt.Printf("runner exited with code %d %s\n",testRun.exitCode,testRun.status)
}

/**
 * Look at test Inputs (from criteria []ARG) and
 * substitute any that begin with '$' character
 * @return true if all substituions were met
 */
func SubstituteSysInfoArgs(spec *types.AtomicTestCriteria) bool {
	for key,val := range spec.Args {
		if len(val) == 0 || val[0] != '$' {
			continue
		}

		if strings.Contains(val,"$SERVER[") {
			for svrkey,svrval := range gServerConfigs {
				if strings.Contains(val, svrkey) {
					val = strings.ReplaceAll(val, svrkey, svrval)
					spec.Args[key] = val
					fmt.Println("  subtitute",key,val,"->",spec.Args[key])
				}
			}
			continue
		}
		switch val {
		case "$hostname":
			spec.Args[key] = gSysInfo.Hostname
		case "$ipaddr4":
			spec.Args[key] = gSysInfo.Ipaddr4
		case "$ipaddr6":
			spec.Args[key] = gSysInfo.Ipaddr6
		case "$ipaddr":
			spec.Args[key] = gSysInfo.Ipaddr
		case "$username":
			spec.Args[key] = gSysInfo.Username
		case "$subnet":
			spec.Args[key] = gSysInfo.Subnet
		case "$gateway":
			spec.Args[key] = gSysInfo.Gateway
		case "$netif":
			spec.Args[key] = gSysInfo.Netif
		default:
			fmt.Println("ERROR unknown ARG variable", key,val)
			return false
		}
		fmt.Println("  subtitute",key,val,"->",spec.Args[key])
	}
	return true
}

/*
   Technique  string
   TestName   string
   TestIndex  int

   AtomicsDir string
   TempDir    string
   ResultsDir string

   Inputs     map[string]string
 */
func BuildRunSpec(spec *types.AtomicTestCriteria, atomicTempDir string, resultsDir string) string {
	obj := types.RunSpec{}
	obj.Technique = spec.Technique
	obj.TestIndex = int(spec.TestIndex - 1)
	obj.TempDir = atomicTempDir
	obj.AtomicsDir,_ = filepath.Abs(flagAtomicsPath)
	obj.ResultsDir,_ = filepath.Abs(resultsDir)
	obj.Inputs = spec.Args
	obj.Username = flagRegularRunUser

	os.Mkdir(obj.ResultsDir, 0777)

	j,err := json.MarshalIndent(obj,"","  ")
	if err != nil {
		fmt.Println("ERROR:", err);
		return ""
	}

	outPath := resultsDir + "/runspec.json"
	err = os.WriteFile(outPath, j, 0644)
	if err != nil {
		fmt.Println("ERROR: unable to write file", outPath, err)
	}

	return string(j)
}

func ShouldBeSkipped(atc *types.AtomicTestCriteria) bool {
	return len(atc.Warnings) > 0
}


func WriteTestRunStatusFile(testRun *SingleTestRun) {

	// load match string written by telemetry tool and update testRun object

	inPath := testRun.resultsDir + "/match_string.txt"
	matchString,_ := os.ReadFile(inPath)
	testRun.matchString = string(matchString)

	// save status file

	outPath := testRun.resultsDir + "/status.txt"
	s := fmt.Sprintf("%d\n%s",testRun.status, testRun.status)
	err := os.WriteFile(outPath, []byte(s), 0644)
	if err != nil {
		fmt.Println("ERROR: unable to write file", outPath, err)
	}
}

func MarkAsSkipped(testRun *SingleTestRun) {
	testRun.status = types.StatusSkipped
	testRun.state = types.StateDone
	WriteTestRunStatusFile(testRun)
}

func SaveState(tests []*SingleTestRun) {

	progress := []types.TestProgress{}
	for _,t := range tests {
		obj := types.TestProgress{t.criteria.Technique, fmt.Sprintf("%d",t.criteria.TestIndex), t.criteria.TestName, t.state, t.exitCode, t.status}
		progress = append(progress, obj)
	}
	j,err := json.MarshalIndent(progress,"","  ")
	if err != nil {
		fmt.Println("ERROR:", err);
		return
	}

	outPath := flagResultsPath + "/status.json"

	err = os.WriteFile(outPath, j, 0644)
	if err != nil {
		fmt.Println("ERROR: unable to write file", outPath, err)
	}

	// now a plain text version

	s := SPrintState(tests, true)
	outPath = flagResultsPath + "/status.txt"

	err = os.WriteFile(outPath, []byte(s), 0644)
	if err != nil {
		fmt.Println("ERROR: unable to write file", outPath, err)
	}

}

func SPrintState(tests []*SingleTestRun, byCategory bool) string {
	numValidated := 0
	numPartial := 0
	numValidateFail := 0
	numSkipped := 0
	numRunErrors := 0 
	numMissingDeps := 0

	s := ""
	for _,tid := range gTechniquesMissingTests {
		name,_ := gMitreTechniqueNames[tid]
	   s += fmt.Sprintf("-%9s %2d %s %-12s \"%s\"\n",tid, 0, "Skip", "MissingTests", name)
	}


	byState := map[string][]string {}
	for _,t := range tests {
		switch t.status {
		case types.StatusValidateSuccess:
			numValidated += 1
		case types.StatusValidateFail:
			numValidateFail += 1
		case types.StatusValidatePartial:
			numPartial += 1
		case types.StatusPreReqFail:
			numMissingDeps += 1
		case types.StatusSkipped:
			numSkipped += 1
		default:
			numRunErrors += 1
		}

		strState := fmt.Sprintf("%s%s",t.state,t.status)
	   line := fmt.Sprintf("-%9s %2d %s %-12s %-16s \"%s\"\n",t.criteria.Technique, t.criteria.TestIndex, t.state, t.status, t.matchString, t.criteria.TestName)
	   a,ok := byState[strState]
	   if !ok {
	   	a = []string{}
	   }
	   a = append(a,line)
	   byState[strState] = a
	}

	for _,a := range byState {
		for _,line := range a {
			s += line
		}
	}

	s += fmt.Sprintf("=== Validated:%d Partial:%d NoTelemetry:%d Skipped:%d RunErrors:%d MissingDeps:%d NoTests:%d\n", 
		numValidated, numPartial, numValidateFail, numSkipped, numRunErrors, numMissingDeps, len(gTechniquesMissingTests))

	return s
}

func LoadFile(filename string) (error) {
	var cur *types.AtomicTestCriteria

	data, err := ioutil.ReadFile(filename);
	if err != nil {
		return err
	}

	r := csv.NewReader(bytes.NewReader(data))
	r.LazyQuotes = true
	r.Comment = '#'
	r.FieldsPerRecord = -1 // no validation on num columns per row

	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	for _,row := range records {

		if 3 != len(row[0]) {

			if len(row[0]) < 3 {
				continue
			}
			if row[0][0] == '#' {
				continue
			}
			if row[0][0] == 'T' {
				// new test
				//fmt.Println("new test", row[0], )
				if len(row) != 4 {
					fmt.Println("ERROR: Expected 4 columns for T row", row)
					continue
				}
				cur = utils.AtomicTestCriteriaNew(row[0], row[1], row[2], row[3])
				gRecs = append(gRecs , cur)
				//cur = gRecs[len(gRecs)-1]
			} else {
				fmt.Println("UNKNOWN", row[0])
			}
		} else {
			switch row[0] {
			case "_E_":
				evt := utils.EventFromRow(len(cur.ExpectedEvents),row)
				//fmt.Println("_E_", evt)
				cur.ExpectedEvents = append(cur.ExpectedEvents, &evt)
			case "_?_":
				evt := utils.EventFromRow(len(cur.ExpectedEvents),row)
				evt.IsMaybe = true
				//fmt.Println("_E_", evt)
				cur.ExpectedEvents = append(cur.ExpectedEvents, &evt)
			case "_C_":
				cur.ExpectedCorrelations = append(cur.ExpectedCorrelations, utils.CorrelationFromRow(row))
			case "ARG":
				cur.Args[row[1]] = row[2]
			case "FYI":
				cur.Infos = append(cur.Infos,row[1])
			case "!!!":
				cur.Warnings = append(cur.Warnings,row[1])
			default:
				fmt.Println("ENTRY", row[0])
			}
		}
	}
	return nil
}

func LoadTechniquesList(filename string) (error) {

	data, err := ioutil.ReadFile(filename);
	if err != nil {
		return err
	}

	r := csv.NewReader(bytes.NewReader(data))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1 // no validation on num columns per row

	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	for _,row := range records {
		//fmt.Println(row)

		tid := row[0]
		if len(tid) == 0 || tid[0] != 'T' {
			continue
		}

		num := AddTestsForTechniqueUsingAtomicsIndex(tid)
		if num == 0 {
			if gVerbose {
				fmt.Println("ERROR: no tests found for technique",tid)
			}
			gTechniquesMissingTests = append(gTechniquesMissingTests, tid)
		}
	}

	return nil
}



func RunTests() {
	testRuns := []*SingleTestRun{}

	for _,spec := range gTestSpecs {

		for _, rec := range spec.Criteria {

			resultsDir := flagResultsPath + "/" + rec.Technique + "_" + fmt.Sprintf("%d",rec.TestIndex)
			err := os.MkdirAll(resultsDir, 0777)
			if err != nil {
				fmt.Println("unable to make results dir", err)
				os.Exit(1)
			}

			testRun := &SingleTestRun{}
			testRun.criteria = rec
			testRun.resultsDir = resultsDir
			testRun.state = types.StateCriteriaLoaded
			testRuns = append(testRuns, testRun)

			SaveState(testRuns)

			if ShouldBeSkipped(rec) {
				fmt.Println("Test Warning - skipping", testRun.criteria.Technique, testRun.criteria.TestName)
				fmt.Println("   " + testRun.criteria.Warnings[0])
				MarkAsSkipped(testRun)
				SaveState(testRuns)
				continue
			}

			workingDir, err := os.MkdirTemp("", "artwork-" + spec.Technique + "_" + fmt.Sprintf("%d",testRun.criteria.TestIndex) + "-")
			if err != nil {
				fmt.Println("unable to make working dir", err)
				os.Exit(1)
			}

			testRun.workingDir = workingDir

			// load atomic to get default args
			utils.LoadAtomicDefaultArgs(rec, flagAtomicsPath, gVerbose)

			// some test Args and field checks need variable substitutions

			if false == SubstituteSysInfoArgs(rec) || false == SubstituteVarsInCriteria(testRun.criteria) {
				MarkAsSkipped(testRun)
				SaveState(testRuns)
				continue
			}

			runConfig := BuildRunSpec(rec, workingDir, resultsDir)
			if runConfig == "" {
				fmt.Println("empty runconfig!, skipping", rec)
				continue
			}

			os.Chmod(workingDir, 0777)  // runner cleans up workingDir
			os.Chmod(resultsDir, 0777)

			if !gFlagNoRun	{
				testRun.state = types.StateRunnerLaunched
				SaveState(testRuns)

				GoArtRunTest(testRun, runConfig)

				testRun.state = types.StateRunnerFinished

				UpdateTimestampsFromRunSummary(testRun)

				SaveState(testRuns)
			}

			// fix permissions after run

			os.Chmod(resultsDir, 0755)

			// runner will try to clean up, but may not be able to with lowered privs
			err = os.RemoveAll(workingDir)
			if err != nil {
				fmt.Println("Failed to delete working dir",workingDir,err)
			}

			if false == gKeepRunning {
				break
			}

			// sleep a few seconds in-between tests
			// want to avoid confusing telemetry of one test with the other
			// TODO: careful with netflows, they are batched. telemetry tool filter by process?

			if !gFlagNoRun {
				time.Sleep(3*time.Second)
			}
		}
		if false == gKeepRunning {
			break
		}
	}

	// fix ownership of results dirs

	username := os.Getenv("SUDO_USER")
	if username == "" {
		username = os.Getenv("USER")
	}
	if username != "" && username != "root" {
		cmd := exec.Command("chown","-R", username + ":" + username, flagResultsPath)
		_,err := cmd.CombinedOutput()
		if err != nil {
			fmt.Println("failed to chown resultsdir", err)
		}
	}

	os.Chmod(flagResultsPath, 0755)

	// now get telemetry
	if false == gFlagNoRun && true == gKeepRunning {
		for _,testRun := range testRuns {
			if testRun.status == types.StatusTestSuccess {
				//spec *AtomicTestCriteria, workingDir string, resultsDir string
				testRun.state = types.StateWaitForTelemetry
				SaveState(testRuns)

				LaunchTelemetryExtractor(testRun)

				testRun.state = types.StateDone
			}
			WriteTestRunStatusFile(testRun)
			SaveState(testRuns)
		}
	}

	fmt.Println("Done. Output in", flagResultsPath)
	fmt.Println(SPrintState(testRuns,true))
}

func RunSignalHandler() {
	c := make(chan os.Signal, 2)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// Block until a signal is received.
	// Unfortunately, this does not prevent runner CMD from getting
	// interrupted and closing without waiting for script to exit

	s := <-c
	fmt.Println("*** Received SIGINT:", s," ***")
	fmt.Println(" skipping the rest of tests and telemetry")
	gKeepRunning = false
}

func main() {

	flag.Parse()
	flagTechniques := flag.Args()

	FillInToolPathDefaults()


	var err error
	if runtime.GOOS == "darwin" { // macOS
		err = GetSysInfoMacOS(gSysInfo)
	} else {
		err = GetSysInfo(gSysInfo)
	}

	if err != nil {
		fmt.Println("ERROR getting system info", err)
		os.Exit(1)
	}
	
	if gVerbose {
		fmt.Println(gSysInfo)
	}

	if flagClearTelemetryCache {
		ClearTelemetryCache()
	}

	if "" == flagResultsPath {

		var err error
		os.MkdirAll("./testruns",0777)
		flagResultsPath, err = os.MkdirTemp("./testruns", "harness-results-")
		if err != nil {
			fmt.Println("unable to make results dir", err)
			os.Exit(1)
		}
		os.Chmod(flagResultsPath,0777)
	}

	err = utils.LoadAtomicsIndexCsv(flagAtomicsPath, &gAtomicTests)
	if err != nil {
		fmt.Println("Unable to load Indexes-CSV file for Atomics", err)
		os.Exit(1)
	}

	utils.LoadMitreTechniqueCsv("./data/linux_techniques.csv", &gMitreTechniqueNames)

	if false == LoadCriteriaFiles(flagCriteriaPath) {
		return
	}

	if len(flagTechniquesFilePath) != 0 {
		err := LoadTechniquesList(flagTechniquesFilePath)
		if err != nil {
			fmt.Println("unable to read runlist file", err)
			os.Exit(1)
		}
	} else if flagRetryFailed != "" {
		err := utils.LoadFailedTechniquesList(flagRetryFailed, &gTestSpecs)
		if err != nil {
			fmt.Println("unable to load status.json")
			os.Exit(2)
		}
	}

	if false == ParseTestSpecs(flagTechniques) {
		//return
	}

	if len(gTestSpecs) == 0 {
		fmt.Println("No test specs specified. exiting")
		return
	}

	if MissingCmdlineArgs() {
		return
	}

	if flagServerConfigsCsvPath != "" {
		utils.LoadServerConfigsCsv(flagServerConfigsCsvPath, &gServerConfigs)
	}

	if false == FindCriteriaForTestSpecs() {
                // TODO: optionally support cmdline flag to exit if any criteria files missing
		//return
	}

	if gFlagNoRun {
		fmt.Println("--norun specified. exiting without running tests")
	} else {
		go RunSignalHandler()
	}
	RunTests()

}

