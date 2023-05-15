package main

import (
	"bufio"
	"fmt"
	"encoding/json"
	//"net"
	"os"
	"regexp"
	"strings"

)

type ExtractState struct {
	StartTime   uint64            `json:"start_time"`
	EndTime     uint64            `json:"end_time"`
	TestData    MitreTestCriteria `json:"test_data"`
	TotalEvents uint64            `json:"total_events"`
	NumMatches  uint64            `json:"num_matches"`
	Coverage    float64           `json:"coverage"`
}

var (
	gValidateState        = ExtractState{}

	// sh /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash
	gRxGoArtStage = regexp.MustCompile(`sh /tmp/(artwork-T[\w-_\.\d]+)/goart-(T[\d\._]+)-(\w+)`)
)

func CheckMatch(haystack,op,needle string) bool {
	if gDebug {
		fmt.Println("CheckMatch",op,"\"" + haystack + "\"",needle)
	}
	switch op {
	case "=":
		return haystack == needle
	case "~=":
		return strings.Contains(haystack,needle)
	case "*=":
		// TODO: only want to compile this once
		rx,err := regexp.Compile(needle)
		if err != nil {
			fmt.Println("invalid regex",needle,err)
			return false
		}
		return rx.MatchString(haystack)
	default:
		fmt.Println("ERROR: unsupported operator", op)
	}
	return false
}

func AddMatchingEvent(testRun *SingleTestRun, exp *ExpectedEvent, nativeJsonStr string) {
	exp.Matches = append(exp.Matches, nativeJsonStr)
	gValidateState.NumMatches += 1
	UpdateCoverage()
}

func CheckProcessEvent(testRun *SingleTestRun, evt *SimpleEvent, nativeJsonStr string) {

	// by default, filter out anything that is not in the actual ATR test
	// by looking for goartrun 'test' shell process event

	if flagFilterByGoartrunShell {
		if IsGoArtStage(testRun, evt.ProcessFields.Cmdline, evt.Timestamp) {
			testRun.ShellPid = evt.ProcessFields.Pid
			return
		}
		if 0 == testRun.TimeOfParentShell || 0 != testRun.TimeOfNextStage {
			if gVerbose {
				fmt.Println("Ignoring event before/after ATR test", nativeJsonStr)
			}
			return
		}
	}

	// pull out expected process event criteria and match

	for _,exp := range testRun.criteria.ExpectedEvents {
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
			AddMatchingEvent(testRun, exp, nativeJsonStr)
		} else if numMatchingChecks > 0 {
			fmt.Printf("ONLY %d of %d FieldChecks satisfied\n", numMatchingChecks, len(exp.FieldChecks), nativeJsonStr)
		}
	}
}

func CheckFileEvent(testRun *SingleTestRun, evt *SimpleEvent, nativeJsonStr string) {
	if flagFilterFileEventsTmp {
		if IsGoArtWorkDirEvent(testRun, evt) {
			return
		}
		if 0 == testRun.TimeWorkDirCreate || 0 != testRun.TimeWorkDirDelete {
			if gVerbose {
				fmt.Println("Ignoring event before/after goartrun working dir event", nativeJsonStr)
			}
			return
		}
	}


	for _,exp := range testRun.criteria.ExpectedEvents {
		if exp.EventType != "File" {
			continue
		}

		// match action

		isMatchingSubtype := false
		action := evt.FileFields.Action

		switch strings.ToUpper(exp.SubType) {
		case "WRITE":
			isMatchingSubtype = action == SimpleFileActionOpenWrite || action == SimpleFileActionRename || action == SimpleFileActionCreate
		case "CREAT":
			isMatchingSubtype = action == SimpleFileActionOpenWrite || action == SimpleFileActionCreate
		case "CREATE":
			isMatchingSubtype = action == SimpleFileActionOpenWrite || action == SimpleFileActionCreate
		case "CHMOD":
			isMatchingSubtype = action == SimpleFileActionChmod
		case "CHOWN":
			isMatchingSubtype = action == SimpleFileActionChown
		case "CHATTR":
			isMatchingSubtype = action == SimpleFileActionChattr
		case "RENAME":
			isMatchingSubtype = action == SimpleFileActionRename
		case "UNLINK":
			isMatchingSubtype = action == SimpleFileActionDelete
		case "DELETE":
			isMatchingSubtype = action == SimpleFileActionDelete
		case "READ":
			isMatchingSubtype = action == SimpleFileActionOpenRead
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
			AddMatchingEvent(testRun, exp, nativeJsonStr)
		} else if numMatchingChecks > 0 {
			fmt.Printf("ONLY %d of %d FieldChecks satisfied\n", numMatchingChecks, len(exp.FieldChecks), nativeJsonStr)
		}
	}
}

func CheckNetflowEvent(testRun *SingleTestRun, evt *SimpleEvent, nativeJsonStr string) {
	for _,exp := range gValidateState.TestData.ExpectedEvents {

		if strings.ToUpper(exp.EventType) != "NETFLOW" {
			continue
		}

		// make regexes from subtype and all fieldchecks

		s := strings.ReplaceAll(exp.SubType, "*",".*")
		rx, err := regexp.Compile(strings.ToLower(s))
		if err != nil {
			fmt.Println("Invalid netflow regex",exp.SubType,err)
			continue
		}

		regexes := []*regexp.Regexp{rx}

		for _,fc := range exp.FieldChecks {
			s := strings.ReplaceAll(fc.Value, "*",".*")
			rx, err := regexp.Compile(strings.ToLower(s))
			if err != nil {
				fmt.Println("Invalid netflow regex",fc,err)
			}
			regexes = append(regexes, rx)
		}

		// now check against FlowStr, FlowStrDns

		if gVerbose {
			fmt.Println("Netflow",evt.NetflowFields.FlowStr, exp.SubType)
		}
		for _,rx := range regexes {
			matched := rx.MatchString(evt.NetflowFields.FlowStr)
			if matched {
				AddMatchingEvent(testRun, exp, nativeJsonStr)
				break
			}
			if len(evt.NetflowFields.FlowStrDns) > 0 {
				matched = rx.MatchString(evt.NetflowFields.FlowStrDns)
				if matched {
					AddMatchingEvent(testRun, exp, nativeJsonStr)
					break
				}
			}
		}
	}
}

func ValidateSimpleTelemetry(testRun *SingleTestRun) {
	gValidateState = ExtractState{}
	gValidateState.StartTime = uint64(testRun.StartTime)
	gValidateState.EndTime = uint64(testRun.EndTime)
	gValidateState.TestData.Technique = testRun.criteria.Technique
	gValidateState.TestData.TestIndex = testRun.criteria.TestIndex
	gValidateState.TestData.TestName = testRun.criteria.TestName
	gValidateState.TestData.ExpectedEvents = testRun.criteria.ExpectedEvents

	// load simple_telemetry.json, process each event

	path := testRun.resultsDir + "/simple_telemetry.json"
	simpleLines, err := ReadFileLines(path)
	if err != nil {
		fmt.Println("ERROR: file not found", path, err)
		return
	}

	path = testRun.resultsDir + "/telemetry.json"
	rawJsonLines, err := ReadFileLines(path)
	if err != nil {
		fmt.Println("ERROR: file not found", path, err)
		return
	}
	if len(simpleLines) != len(rawJsonLines) {
		fmt.Println("ERROR: num simple does not match num raw", len(simpleLines), len(rawJsonLines))
		return
	}

	for i, line := range simpleLines {
		evt := &SimpleEvent{}

		err = json.Unmarshal([]byte(line), evt)
		if err != nil {
			fmt.Println("ERROR: parsing event",err, line)
			continue
		}
		switch evt.EventType {
		case SimpleSchemaProcess:
			CheckProcessEvent(testRun, evt, rawJsonLines[i])
		case SimpleSchemaFilemod:
			CheckFileEvent(testRun, evt, rawJsonLines[i])
		case SimpleSchemaFileRead:
			CheckFileEvent(testRun, evt, rawJsonLines[i])
		case SimpleSchemaNetflow:
			CheckNetflowEvent(testRun, evt, rawJsonLines[i])
		default:
			fmt.Println("missing handling of type", line)
		}
	}

	// save results to file

	s := GetTelemTypes(& gValidateState.TestData)
	outPath := testRun.resultsDir + "/match_string.txt"
	err = os.WriteFile(outPath, []byte(s), 0644)
	if err != nil {
		fmt.Println("ERROR: unable to write file", outPath, err)
	}

	jb, err := json.MarshalIndent(gValidateState,"","  ")
	if err != nil {
		fmt.Println("failed to encode validation state json", err)
	} else {

		outPath = testRun.resultsDir + "/validate_summary.json"
		err = os.WriteFile(outPath, jb, 0644)
		if err != nil {
			fmt.Println("ERROR: unable to write file", outPath, err)
		}
	}

	// set status based on coverage

	if gValidateState.Coverage == 1.0 {
		testRun.status = StatusValidateSuccess
	} else if gValidateState.Coverage == 0.0 {
		testRun.status = StatusValidateFail
	} else {
		testRun.status = StatusValidatePartial
	}
}

func UpdateCoverage() {
	numFound := 0
	numExpected := len(gValidateState.TestData.ExpectedEvents) +
		len(gValidateState.TestData.ExpectedCorrelations)

	for _,exp := range gValidateState.TestData.ExpectedEvents {
		if len(exp.Matches)  > 0 {
			numFound += 1
		}
	}

	for _,exp := range gValidateState.TestData.ExpectedCorrelations {
		if exp.IsMet {
			numFound += 1
		}
	}

	prev := gValidateState.Coverage
	gValidateState.Coverage = float64(numFound) / float64(numExpected)

	if gValidateState.Coverage >= 1.0 && prev != gValidateState.Coverage {
		fmt.Println("SUCCESS: Agent Telemetry Has Full Coverage")
	}
}

func GetTelemChar(exp *ExpectedEvent) string {
	switch strings.ToUpper(exp.EventType) {
	case "PROCESS": return "P"
	case "NETFLOW": return "N"
	case "FILE":
		if strings.ToUpper(exp.SubType) == "READ" {
			return "f"
		}
		return "F"
	case "FILEMOD": return "F"
		if strings.ToUpper(exp.SubType) == "READ" {
			return "f"
		}
		return "F"
	case "AUTH": return "A"
	case "PTRACE": return "T"
	case "NETSNIFF": return "S"
	case "ALERT": return "W"
	case "MODULE": return "M"
	case "VOLUME": return "V"
	default:
		break
	}

	fmt.Println("No char code for EventType:",exp.EventType)

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
	a := gRxGoArtStage.FindStringSubmatch(cmdline)
	if len(a) > 3 {
		folder := a[1]
		technique := a[2]
		stageName := a[3]
		if gVerbose {
			fmt.Println("Found stage", stageName,"for", technique,"folder:",folder)
		}
		if "test" == stageName {
			// is this the target test?
			if technique == testRun.criteria.Technique {
				tsttok := fmt.Sprintf("%s_%d", technique, testRun.criteria.TestIndex)
				fmt.Println("contains check", folder, tsttok, tsNs)
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
	return false
}

/**
 * IsGoArtWorkDirEvent will check the file event target path,
 * if it matches create or delete, then it's the start/end of test
 *
 * Side-effects: will set testRun.TimeWorkDirCreate, TimeWorkDirDelete
 */
func IsGoArtWorkDirEvent(testRun *SingleTestRun, evt *SimpleEvent) bool {
	if evt.FileFields.TargetPath == testRun.workingDir {
		if evt.FileFields.Action == SimpleFileActionDelete {
			testRun.TimeWorkDirDelete = evt.Timestamp
		} else if evt.FileFields.Action == SimpleFileActionOpenRead {
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
func GetTelemTypes(criteria *MitreTestCriteria) string {
	s := ""
	for _,exp := range criteria.ExpectedEvents {
		c := GetTelemChar(exp)
		if len(exp.Matches) == 0 {
			s += "<" + c + ">"
		} else {
			s += c
		}
	}
	for _,exp := range criteria.ExpectedCorrelations {
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
