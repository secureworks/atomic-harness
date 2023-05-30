package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	types "github.com/secureworks/atomic-harness/pkg/types"
	utils "github.com/secureworks/atomic-harness/pkg/utils"
)

type ExtractState struct {
	StartTime   uint64                  `json:"start_time"`
	EndTime     uint64                  `json:"end_time"`
	TestData    types.MitreTestCriteria `json:"test_data"`
	TotalEvents uint64                  `json:"total_events"`
	NumMatches  uint64                  `json:"num_matches"`
	Coverage    float64                 `json:"coverage"`
	MatchingTag string                  `json:"matching_tag",omitempty`
}

var (
	gValidateState = ExtractState{}

	// sh /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash
	gRxGoArtStage = regexp.MustCompile(`sh /tmp/(artwork-T[\w-_\.\d]+)/goart-(T[\d\._]+)-(\w+)`)

	// CMD /c C:\\Users\\admin\\AppData\\Local\\Temp\\artwork-T1047_1-2854796409\\goart-T1047-test.bat
	// POWERSHELL -NoProfile C:\\Users\\admin\\AppData\\Local\\Temp\\artwork-T1027_2-3400567469\\goart-T1027-test.ps1
	gRxGoArtStageWin = regexp.MustCompile(`(POWERSHELL |CMD /c |pwsh ).*\\(artwork-T[\w-_\.\d]+)\\goart-(T[\d\._]+)-(\w+)`)
)

func CheckMatch(haystack, op, needle string) bool {
	if gDebug {
		fmt.Println("CheckMatch", op, "\""+haystack+"\"", needle)
	}
	switch op {
	case "=":
		return haystack == needle
	case "~=":
		return strings.Contains(haystack, needle)
	case "*=":
		// TODO: only want to compile this once
		rx, err := regexp.Compile(needle)
		if err != nil {
			fmt.Println("invalid regex", needle, err)
			return false
		}
		return rx.MatchString(haystack)
	default:
		fmt.Println("ERROR: unsupported operator", op)
	}
	return false
}

func AddMatchingEvent(testRun *SingleTestRun, exp *types.ExpectedEvent, event *types.SimpleEvent) {
	exp.Matches = append(exp.Matches, event)
	gValidateState.NumMatches += 1
	UpdateCoverage()
}

func CheckProcessEvent(testRun *SingleTestRun, evt *types.SimpleEvent, nativeJsonStr string) bool {
	retval := false

	// by default, filter out anything that is not in the actual ATR test
	// by looking for goartrun 'test' shell process event

	if flagFilterByGoartrunShell {
		if IsGoArtStage(testRun, evt.ProcessFields.Cmdline, evt.Timestamp) {
			testRun.ShellPid = evt.ProcessFields.Pid
			return retval
		}
		if 0 == testRun.TimeOfParentShell || 0 != testRun.TimeOfNextStage {
			if gVerbose {
				fmt.Println("Ignoring event before/after ATR test", nativeJsonStr)
			}
			return retval
		}
	}

	// pull out expected process event criteria and match

	for _, exp := range testRun.criteria.ExpectedEvents {
		if exp.EventType != "Process" {
			continue
		}
		numMatchingChecks := 0
		for _, fc := range exp.FieldChecks {
			isMatch := false
			switch fc.FieldName {
			case "cmdline":
				isMatch = CheckMatch(evt.ProcessFields.Cmdline, fc.Op, fc.Value)
			case "exepath":
				isMatch = CheckMatch(evt.ProcessFields.ExePath, fc.Op, fc.Value)
			case "env":
				isMatch = CheckMatch(evt.ProcessFields.Env, fc.Op, fc.Value)
			case "is_elevated":
				isMatch = CheckMatch(BoolAsString(evt.ProcessFields.IsElevated), fc.Op, fc.Value)
			default:
				fmt.Println("ERROR: unknown FieldName", fc)
			}
			if isMatch {
				if gDebug {
					fmt.Printf("Field Match '%s' '%s'\n", fc.FieldName, fc.Value)
				}
				numMatchingChecks += 1
			}
		}
		if numMatchingChecks == len(exp.FieldChecks) {
			AddMatchingEvent(testRun, exp, evt)
			retval = true
		} else if numMatchingChecks > 0 {
			fmt.Printf("ONLY %d of %d FieldChecks satisfied\n%s\n", numMatchingChecks, len(exp.FieldChecks), nativeJsonStr)
		}
	}
	return retval
}

func CheckFileEvent(testRun *SingleTestRun, evt *types.SimpleEvent, nativeJsonStr string) bool {
	retval := false
	if flagFilterFileEventsTmp {
		if IsGoArtWorkDirEvent(testRun, evt) {
			return retval
		}
		if 0 == testRun.TimeWorkDirCreate || 0 != testRun.TimeWorkDirDelete {
			if gVerbose {
				fmt.Println("Ignoring event before/after goartrun working dir event", nativeJsonStr)
			}
			return retval
		}
	}

	for _, exp := range testRun.criteria.ExpectedEvents {
		if exp.EventType != "File" {
			continue
		}

		// match action

		isMatchingSubtype := false
		action := evt.FileFields.Action

		switch strings.ToUpper(exp.SubType) {
		case "WRITE":
			isMatchingSubtype = action == types.SimpleFileActionOpenWrite || action == types.SimpleFileActionRename || action == types.SimpleFileActionCreate
		case "CREAT":
			isMatchingSubtype = action == types.SimpleFileActionOpenWrite || action == types.SimpleFileActionCreate
		case "CREATE":
			isMatchingSubtype = action == types.SimpleFileActionOpenWrite || action == types.SimpleFileActionCreate
		case "CHMOD":
			isMatchingSubtype = action == types.SimpleFileActionChmod
		case "CHOWN":
			isMatchingSubtype = action == types.SimpleFileActionChown
		case "CHATTR":
			isMatchingSubtype = action == types.SimpleFileActionChattr
		case "RENAME":
			isMatchingSubtype = action == types.SimpleFileActionRename
		case "UNLINK":
			isMatchingSubtype = action == types.SimpleFileActionDelete
		case "DELETE":
			isMatchingSubtype = action == types.SimpleFileActionDelete
		case "READ":
			isMatchingSubtype = action == types.SimpleFileActionOpenRead
		default:
			fmt.Println("Unsupported FileMod subtype for matching:", exp.SubType)
		}

		if !isMatchingSubtype {
			continue
		}

		numMatchingChecks := 0
		for _, fc := range exp.FieldChecks {
			isMatch := false
			switch fc.FieldName {
			case "path":
				isMatch = CheckMatch(evt.FileFields.TargetPath, fc.Op, fc.Value)
				if !isMatch {
					isMatch = CheckMatch(evt.FileFields.DestPath, fc.Op, fc.Value)
				}
			default:
				fmt.Println("ERROR: unknown FieldName", fc)
			}
			if isMatch {
				if gVerbose {
					fmt.Printf("Field Match '%s' '%s'\n", fc.FieldName, fc.Value)
				}
				numMatchingChecks += 1
			}
		}
		if numMatchingChecks == len(exp.FieldChecks) {
			AddMatchingEvent(testRun, exp, evt)
			retval = true
		} else if numMatchingChecks > 0 {
			fmt.Printf("ONLY %d of %d FieldChecks satisfied.\n%s\n", numMatchingChecks, len(exp.FieldChecks), nativeJsonStr)
		}
	}
	return retval
}

func CheckNetflowEvent(testRun *SingleTestRun, evt *types.SimpleEvent, nativeJsonStr string) bool {
	retval := false
	for _, exp := range gValidateState.TestData.ExpectedEvents {

		if strings.ToUpper(exp.EventType) != "NETFLOW" {
			continue
		}

		// make regexes from subtype and all fieldchecks

		s := strings.ReplaceAll(exp.SubType, "*", ".*")
		rx, err := regexp.Compile(strings.ToLower(s))
		if err != nil {
			fmt.Println("Invalid netflow regex", exp.SubType, err)
			continue
		}

		regexes := []*regexp.Regexp{rx}

		for _, fc := range exp.FieldChecks {
			s := strings.ReplaceAll(fc.Value, "*", ".*")
			rx, err := regexp.Compile(strings.ToLower(s))
			if err != nil {
				fmt.Println("Invalid netflow regex", fc, err)
			}
			regexes = append(regexes, rx)
		}

		// now check against FlowStr, FlowStrDns

		if gVerbose {
			fmt.Println("Netflow", evt.NetflowFields.FlowStr, exp.SubType)
		}
		for _, rx := range regexes {
			matched := rx.MatchString(evt.NetflowFields.FlowStr)
			if matched {
				AddMatchingEvent(testRun, exp, evt)
				retval = true
				break
			}
			if len(evt.NetflowFields.FlowStrDns) > 0 {
				matched = rx.MatchString(evt.NetflowFields.FlowStrDns)
				if matched {
					AddMatchingEvent(testRun, exp, evt)
					retval = true
					break
				}
			}
		}
	}
	return retval
}

func ValidateSimpleTelemetry(testRun *SingleTestRun, tool *TelemTool) {
	gValidateState = ExtractState{}
	gValidateState.StartTime = uint64(testRun.StartTime)
	gValidateState.EndTime = uint64(testRun.EndTime)
	gValidateState.TestData.Technique = testRun.criteria.Technique
	gValidateState.TestData.TestIndex = testRun.criteria.TestIndex
	gValidateState.TestData.TestName = testRun.criteria.TestName
	gValidateState.TestData.ExpectedEvents = testRun.criteria.ExpectedEvents

	// load simple_telemetry.json, process each event

	path := testRun.resultsDir + "/../simple_telemetry" + tool.Suffix + ".json"
	simpleLines, err := ReadFileLines(path)
	if err != nil {
		fmt.Println("ERROR: file not found", path, err)
		return
	}

	path = testRun.resultsDir + "/../telemetry" + tool.Suffix + ".json"
	rawJsonLines, err := ReadFileLines(path)
	if err != nil {
		fmt.Println("ERROR: file not found", path, err)
		return
	}
	if len(simpleLines) != len(rawJsonLines) {
		fmt.Println("ERROR: num simple does not match num raw", len(simpleLines), len(rawJsonLines))
		return
	}

	// write native telemetry matches to a file
	outpath := testRun.resultsDir + "/matches" + tool.Suffix + ".json"
	matchFileHandle, err := os.OpenFile(outpath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("ERROR: unable to create outfile", outpath, err)
	}

	for i, line := range simpleLines {
		evt := &types.SimpleEvent{}

		err = json.Unmarshal([]byte(line), evt)
		if err != nil {
			fmt.Println("ERROR: parsing event", err, line)
			continue
		}

		rawEventStr := rawJsonLines[i]
		isMatch := false

		switch evt.EventType {
		case types.SimpleSchemaProcess:
			isMatch = CheckProcessEvent(testRun, evt, rawEventStr)
		case types.SimpleSchemaFilemod:
			isMatch = CheckFileEvent(testRun, evt, rawEventStr)
		case types.SimpleSchemaFileRead:
			isMatch = CheckFileEvent(testRun, evt, rawEventStr)
		case types.SimpleSchemaNetflow:
			isMatch = CheckNetflowEvent(testRun, evt, rawEventStr)
		default:
			fmt.Println("missing handling of type", line)
		}
		if isMatch && matchFileHandle != nil {

			// write match to file

			fmt.Fprintln(matchFileHandle, rawEventStr)

			// did we get a technique match?
			if 0 == len(gValidateState.MatchingTag) && len(evt.MitreTechniques) > 0 {
				for _, tid := range evt.MitreTechniques {
					if strings.HasPrefix(tid, testRun.criteria.Technique) {
						gValidateState.MatchingTag = tid
						testRun.HasMitreTag = true
					}
				}
			}
		}
	}

	if matchFileHandle != nil {
		matchFileHandle.Close()
	}

	// save results to file

	s := GetTelemTypes(&gValidateState.TestData)
	outPath := testRun.resultsDir + "/match_string" + tool.Suffix + ".txt"
	err = os.WriteFile(outPath, []byte(s), 0644)
	if err != nil {
		fmt.Println("ERROR: unable to write file", outPath, err)
	}

	jb, err := json.MarshalIndent(gValidateState, "", "  ")
	if err != nil {
		fmt.Println("failed to encode validation state json", err)
	} else {

		outPath = testRun.resultsDir + "/validate_summary" + tool.Suffix + ".json"
		err = os.WriteFile(outPath, jb, 0644)
		if err != nil {
			fmt.Println("ERROR: unable to write file", outPath, err)
		}
	}

	// set status based on coverage
	// NOTE: with multiple telemtools, status will depend on last tool?

	if gValidateState.Coverage == 1.0 {
		testRun.status = types.StatusValidateSuccess
	} else if gValidateState.Coverage == 0.0 {
		testRun.status = types.StatusValidateFail
	} else {
		testRun.status = types.StatusValidatePartial
	}
}

func UpdateCoverage() {
	numFound := 0
	numExpected := len(gValidateState.TestData.ExpectedEvents) +
		len(gValidateState.TestData.ExpectedCorrelations)

	for _, exp := range gValidateState.TestData.ExpectedEvents {
		if len(exp.Matches) > 0 {
			numFound += 1
		}
	}

	for _, exp := range gValidateState.TestData.ExpectedCorrelations {
		if exp.IsMet {
			numFound += 1
		}
	}

	prev := gValidateState.Coverage
	gValidateState.Coverage = float64(numFound) / float64(numExpected)

	if gVerbose && gValidateState.Coverage >= 1.0 && prev != gValidateState.Coverage {
		fmt.Println("SUCCESS: Agent Telemetry Has Full Coverage")
	}
}

func GetTelemChar(exp *types.ExpectedEvent) string {
	switch strings.ToUpper(exp.EventType) {
	case "PROCESS":
		return "P"
	case "NETFLOW":
		return "N"
	case "FILE":
		if strings.ToUpper(exp.SubType) == "READ" {
			return "f"
		}
		return "F"
	case "FILEMOD":
		return "F"
		if strings.ToUpper(exp.SubType) == "READ" {
			return "f"
		}
		return "F"
	case "AUTH":
		return "A"
	case "PTRACE":
		return "T"
	case "NETSNIFF":
		return "S"
	case "ALERT":
		return "W"
	case "MODULE":
		return "M"
	case "VOLUME":
		return "V"
	default:
		break
	}

	fmt.Println("No char code for EventType:", exp.EventType)

	return "?"
}

/**
 * IsGoArtStage will check the commandline to see if it matches
 * a goartrun execution.  Specifically for the 'test' stage.  Any
 * process events after the run of that test script and before the
 * next goartrun stage is part of the test.  While we have
 * gTimeRangeStart and gTimeRangeEnd as a rough +/- 1-second range,
 * this helps narrow down more so we don't have process events
 * from prereq, setup, cleanup stages of a test.
 *
 * Side-effects: will set testRun.TimeOfParentShell,ShellPid, TimeOfNextStage
 */
func IsGoArtStage(testRun *SingleTestRun, cmdline string, tsNs int64) bool {
	a := []string{}
	i := 1
	if utils.GetPlatformName() == "windows" {
		i += 1 // in 2,3,4 indexes on windows
		a = gRxGoArtStageWin.FindStringSubmatch(cmdline)
	} else {
		a = gRxGoArtStage.FindStringSubmatch(cmdline)
	}
	if len(a) < i+3 {
		return false
	}

	folder := a[i]
	technique := a[i+1]
	stageName := a[i+2]

	if gVerbose {
		fmt.Println("Found stage", stageName, "for", technique, "folder:", folder)
	}
	if "test" == stageName {
		// is this the target test?
		if technique == testRun.criteria.Technique {
			tsttok := fmt.Sprintf("%s_%d", technique, testRun.criteria.TestIndex)
			if gVerbose {
				fmt.Println("contains check", folder, tsttok, tsNs)
			}
			if strings.Contains(folder, tsttok) {
				testRun.TimeOfParentShell = tsNs
				testRun.TimeOfNextStage = 0
			}
		}
	} else if 0 != testRun.TimeOfParentShell {
		testRun.TimeOfNextStage = tsNs
	}
	return true
}

/**
 * IsGoArtWorkDirEvent will check the file event target path,
 * if it matches create or delete, then it's the start/end of test
 *
 * Side-effects: will set testRun.TimeWorkDirCreate, TimeWorkDirDelete
 */
func IsGoArtWorkDirEvent(testRun *SingleTestRun, evt *types.SimpleEvent) bool {
	if evt.FileFields.TargetPath == testRun.workingDir {
		if evt.FileFields.Action == types.SimpleFileActionDelete {
			testRun.TimeWorkDirDelete = evt.Timestamp
		} else if evt.FileFields.Action == types.SimpleFileActionOpenRead {
			return false
		} else {
			testRun.TimeWorkDirCreate = evt.Timestamp
		}
		return true
	}
	return false
}

/**
 * GetTelemTypes will return the collection of expected
 * event types found/not-found as a string.
 * e.g. "P<f>F<N>" would represent Process and FileMod
 *      found, but file-read and netflow not found
 */
func GetTelemTypes(criteria *types.MitreTestCriteria) string {
	s := ""
	for _, exp := range criteria.ExpectedEvents {
		c := GetTelemChar(exp)
		if len(exp.Matches) == 0 {
			s += "<" + c + ">"
		} else {
			s += c
		}
	}
	for _, exp := range criteria.ExpectedCorrelations {
		c := "C"
		if exp.IsMet == false {
			s += "<" + c + ">"
		} else {
			s += c
		}
	}
	return s
}

func BoolAsString(val bool) string {
	switch val {
	case true:
		return "true"
	default:
		break
	}
	return "false"
}

// TODO: avoid mem copy of string array
func ReadFileLines(path string) ([]string, error) {
	ret := []string{}

	file, err := os.Open(path)
	if err != nil {
		return ret, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		ret = append(ret, line)
	}

	return ret, scanner.Err()
}
