package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io/ioutil" // TODO: shouldn't need this anymore

	//"log"

	"os"
	"path/filepath"
	"regexp"

	//"runtime"
	"strconv"
	"strings"

	//"syscall"
	//"time"

	types "github.com/secureworks/atomic-harness/pkg/types"
	utils "github.com/secureworks/atomic-harness/pkg/utils"
)

var flagCriteriaPath string
var flagAtomicsPath string
var flagPlatform string
var flagGenCriteria string
var flagGenCriteriaOutPath string
var gGenCriteriaAll = false
var gVerbose = false
var gUnsafe = false
var gPatchCriteriaRefsMode = false
var gFindTestVal string
var gFindTestCoverage = false

// sh /tmp/artwork-T1560.002_3-458617291/goart-T1560.002-test.bash
var gRxUnixRedirect = regexp.MustCompile(`\d?>>?[ ]?([#{}._/\-0-9A-Za-z ]+)`)

func init() {
	flag.StringVar(&flagCriteriaPath, "criteriapath", "", "path to folder containing CSV files used to validate telemetry")
	flag.StringVar(&flagAtomicsPath, "atomicspath", "", "path to local atomics folder")
	flag.BoolVar(&gVerbose, "verbose", false, "print more details")
	flag.BoolVar(&gPatchCriteriaRefsMode, "patch_criteria_refs", false, "will update criteria file test numbers with GUIDs")
	flag.BoolVar(&gUnsafe, "unsafe", false, "allow potentially destructive tests that may delete important file systems. Defaults to false.")
	flag.BoolVar(&gGenCriteriaAll, "genall", false, "generate criteria for ALL atomic tests")
	flag.StringVar(&gFindTestVal, "findtests", "", "Search atomic-red-team Indexes-CSV for string")
	flag.BoolVar(&gFindTestCoverage, "coverage", false, "Search atomic-red-team Indexes-CSV and find percentage of coverage using path to folder containing CSV files")
	flag.StringVar(&flagPlatform, "platform", "", "optional platform specifier (linux,macos,windows)")
	flag.StringVar(&flagGenCriteria, "gencriteria", "", "supply name of test (Ex: T1070.004) and the CSV for the criteria will be outputted")
	flag.StringVar(&flagGenCriteriaOutPath, "outfile", "", "supply name of directory to store generated criteria in csv form (requires gencriteria flag)")
}

func ToInt64(valstr string) int64 {
	i, err := strconv.ParseInt(valstr, 10, 64)
	if err != nil {
		return 0
	}
	return i
}

func ToUInt(valstr string) uint {
	i := ToInt64(valstr)
	return uint(i)
}

func UpdateCriteriaTestNumGuid(rec *types.AtomicTestCriteria, atomicMap *map[string][]*types.TestSpec) bool {
	tests, ok := (*atomicMap)[rec.Technique]
	if !ok {
		if gVerbose {
			fmt.Println("An atomic test does not exist for this technique:", rec.Technique, "It could be an old copy of atomic-red-team repo or a fork or the criteria specifies an invalid technique")
		}
		return false
	}
	for _, tst := range tests {
		if rec.TestIndex > 0 {
			if tst.TestIndex != fmt.Sprintf("%d", rec.TestIndex) {
				continue
			}
		} else if len(rec.TestGuid) > 0 {
			if !strings.HasPrefix(tst.TestGuid, rec.TestGuid) {
				continue
			}
		} else {
			fmt.Println("criteria is missing Guid or TestNum == 0", rec.Technique, rec.TestIndex, rec.TestGuid, rec.TestName)
			return false
		}

		// if criteria is missing a guid or has zero index, fill it in

		if 0 == rec.TestIndex {
			rec.TestIndex = ToUInt(tst.TestIndex)
		}
		if len(rec.TestGuid) == 0 {
			rec.TestGuid = tst.TestGuid
		}
		if rec.TestName != tst.TestName {
			fmt.Println("criteria name does not match test name:", rec.Technique, rec.TestIndex, rec.TestGuid, rec.TestName, tst.TestName)
		}
		return true
	}

	return false
}

func PatchCriteriaFileRefs(filename string, atomicMap *map[string][]*types.TestSpec) error {
	filename = filepath.FromSlash(filename)
	var cur *types.AtomicTestCriteria

	infile, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		fmt.Println("ERROR: unable to open file", filename, err)
		os.Exit(2)
	}

	outpath := strings.ReplaceAll(filename, ".csv", "_withguids.csv")
	outfile, err := os.OpenFile(outpath, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("ERROR: unable to create outfile", outpath, err)
		os.Exit(2)
	}
	defer infile.Close()
	defer outfile.Close()
	w := csv.NewWriter(outfile)

	scanner := bufio.NewScanner(infile)
	for scanner.Scan() {
		line := scanner.Text()

		r := csv.NewReader(bytes.NewReader([]byte(line)))
		r.LazyQuotes = true
		r.Comment = '#'
		r.FieldsPerRecord = -1 // no validation on num columns per row

		row, err := r.Read()

		if err == nil && len(row) >= 4 && len(row[0]) > 3 && row[0][0] == 'T' {
			cur = utils.AtomicTestCriteriaNew(row[0], row[1], row[2], row[3])
			UpdateCriteriaTestNumGuid(cur, atomicMap)

			if len(cur.TestGuid) > 0 {
				row[2] = cur.TestGuid[0:8]
			}
			w.Write(row)
			w.Flush()
		} else {
			fmt.Fprintln(outfile, line)
		}
	}
	err = scanner.Err()
	if err != nil {
		fmt.Println("ERROR: unable to read", filename, err)
	}

	return nil
}

func PatchCriteriaRefsFiles(dirPath string, atomicMap *map[string][]*types.TestSpec) bool {
	dirPath = filepath.FromSlash(dirPath)
	allfiles, err := ioutil.ReadDir(dirPath)
	if err != nil {
		fmt.Println("ERROR: unable to list files in "+dirPath, err)
		return false
	}
	for _, f := range allfiles {
		if !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}
		if strings.Contains(f.Name(), "_withguids") {
			continue
		}

		if gVerbose {
			fmt.Println("Loading " + f.Name())
		}

		err := PatchCriteriaFileRefs(filepath.FromSlash(dirPath+"/"+f.Name()), atomicMap)
		if err != nil {
			fmt.Println("ERROR:", err)
			return false
		}
	}

	return true
}

func PatchCriteriaGuids() {
	var atomicTests = map[string][]*types.TestSpec{} // tid -> tests

	err := utils.LoadAtomicsIndexCsvPlatform(filepath.FromSlash(flagAtomicsPath), &atomicTests, flagPlatform)
	if err != nil {
		fmt.Println("Unable to load Indexes-CSV file for Atomics", err)
		os.Exit(1)
	}

	PatchCriteriaRefsFiles(flagCriteriaPath, &atomicTests)
}

func FindMatchingTests(val string) {
	var atomicTests = map[string][]*types.TestSpec{} // tid -> tests

	err := utils.LoadAtomicsIndexCsvPlatform(filepath.FromSlash(flagAtomicsPath), &atomicTests, flagPlatform)
	if err != nil {
		fmt.Println("Unable to load Indexes-CSV file for Atomics", err)
		os.Exit(1)
	}
	numMatched := 0
	total := 0
	for _, entries := range atomicTests {
		for _, entry := range entries {
			total += 1
			if strings.Contains(strings.ToLower(entry.Technique), val) || strings.Contains(strings.ToLower(entry.TestName), val) {
				fmt.Println(entry.Technique, entry.TestIndex, entry.TestGuid, entry.TestName)
				numMatched += 1
			}
		}
	}
	fmt.Println("Found", numMatched, "in", total, "tests for platform", flagPlatform)
}

func FillInToolPathDefaults() {
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	if flagCriteriaPath == "" {
		flagCriteriaPath = cwd + "/../atomic-validation-criteria/" + flagPlatform
	}
	if flagAtomicsPath == "" {
		flagAtomicsPath = cwd + "/../atomic-red-team/atomics"
	}
}

func FindTestCoverage() (error, float32) {
	var atomicTests = map[string][]*types.TestSpec{} // tid -> tests

	errRead := utils.LoadAtomicsIndexCsv(filepath.FromSlash(flagAtomicsPath), &atomicTests)
	if errRead != nil {
		fmt.Println("Unable to load Indexes-CSV file for Atomics", errRead)
		return errRead, 0.0
	}

	percentage := FindTestCoverageHelper(flagCriteriaPath, &atomicTests)

	return nil, percentage
}

func FindTestCoverageHelper(dirPath string, atomicMap *map[string][]*types.TestSpec) float32 {
	dirPath = filepath.FromSlash(dirPath)
	allfiles, err := ioutil.ReadDir(dirPath)

	var percentage float32 = 0.0

	readErr := utils.LoadAtomicsIndexCsvPlatform(filepath.FromSlash(flagAtomicsPath), atomicMap, flagPlatform)
	if readErr != nil {
		fmt.Println("Unable to load Indexes-CSV file for Atomics", err)
		os.Exit(1)
	}
	total := 0

	criteria := 0
	for _, entries := range *atomicMap {
		for range entries {
			total += 1
		}
	}
	//fmt.Println("Found", total, "tests for platform", flagPlatform)

	if err != nil {
		fmt.Println("ERROR: unable to list files in "+dirPath, err)
		return 0.0
	}
	for _, f := range allfiles {
		if !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}

		if strings.Contains(f.Name(), "_withguids") {
			continue
		}

		if gVerbose {
			fmt.Println("Loading " + f.Name())
		}

		criteria += FindCoverage(filepath.FromSlash(dirPath+"/"+f.Name()), *atomicMap)
		if err != nil {
			fmt.Println("ERROR:", err)
			return 0.0
		}
	}

	percentage = float32(criteria) / float32(total)

	fmt.Printf("%s Criteria coverage : %3.1f %% of %d atomic tests\n", flagPlatform, percentage*100.0, total)

	return percentage
}

func FindCoverage(filename string, atomicMap map[string][]*types.TestSpec) int {
	platformName := utils.GetPlatformName()

	if gVerbose {
		fmt.Printf("finding coverage for %s for platform %s\n", filename, platformName)
	}

	filename = filepath.FromSlash(filename)

	infile, err := os.OpenFile(filename, os.O_RDONLY, 0644)
	if err != nil {
		fmt.Println("ERROR: unable to open file", filename, err)
		os.Exit(2)
	}

	defer infile.Close()

	scanner := bufio.NewScanner(infile)

	//define local variable to count number of occurences of criteria for particular tests
	criteria := 0

	for scanner.Scan() {
		line := scanner.Text()

		if gVerbose {
			fmt.Print(line, "\n")
		}

		r := csv.NewReader(bytes.NewReader([]byte(line)))
		r.LazyQuotes = true
		r.Comment = '#'
		r.FieldsPerRecord = -1 // no validation on num columns per row

		row, err := r.Read()

		if err == nil && strings.HasPrefix(row[0], "T") {

			cur := utils.AtomicTestCriteriaNew(row[0], row[1], row[2], row[3])

			for _, entry := range atomicMap[cur.Technique] {
				if len(cur.TestGuid) > 0 && strings.HasPrefix(entry.TestGuid, cur.TestGuid) {
					criteria += 1
					break
				}

				if gVerbose {
					fmt.Print("Current Test Index: ", cur.TestIndex, "\nEntry TestIndex: ", entry.TestIndex, "\n")
					fmt.Print("Current Test Name: ", cur.TestName, "\n")
				}

				if cur.TestIndex > 0 && cur.TestIndex == ToUInt(entry.TestIndex) {
					criteria += 1
					break
				}

			}
		}
	}

	if gVerbose {
		fmt.Printf("\n===========================================\nTotal number of criteria found in %s for %s: %d \n", filename, platformName, criteria)
		fmt.Print("===========================================\n")
	}
	// decide if scanner failed to open and display filepath given
	err = scanner.Err()
	if err != nil {
		fmt.Println("ERROR: unable to read ", filename)
	}

	return criteria
}

func stripCommandComment(cmd string, executorName string) (string, string) {
	if len(cmd) == 0 || executorName == "powershell" || executorName == "command_prompt" {
		return cmd, ""
	}

	// unix shells comments start with '#'

	// first, mask out the parameter parts like  #{param}

	tmp := strings.ReplaceAll(cmd, "#{", "^%")

	// now see if any comments exist

	parts := strings.Split(tmp, "#")
	if len(parts) <= 1 {
		return cmd, ""
	}

	// only consider the last one

	comment := parts[len(parts)-1]
	return cmd[0 : len(cmd)-len(comment)-1], comment
}

// given a string of piped unix commands, return array of the individual
// commands.
// examples:
//
//	in1:  "/bin/ls /tmp/"
//	out1: [ "/bin/ls /tmp/" ]
//	in2:  "ls /etc | grep pa | sort"
//	out2: [ "ls /etc/ " " grep pa " " sort" ]
func SplitPipedCommands(cmd string, executorName string) []string {
	if len(cmd) == 0 || executorName == "powershell" || executorName == "command_prompt" {
		return []string{cmd}
	}
	ret := strings.Split(cmd, "|")
	return ret
}

// given a unix command with file redirects, return command and array
// of file path targets
// example:
//
//	in1:  "/bin/myexe 2>/dev/null >> /tmp/abc"
//	out1: "/bin/myexe " [ "/dev/null" "/tmp/abc" ]
func extractFileRedirects(cmd string, executorName string) (string, []string) {
	paths := []string{}
	if len(cmd) == 0 || executorName == "powershell" || executorName == "command_prompt" {
		return cmd, paths
	}

	// look for ''> some_file',  '>> some_file', '2>' and '1>'
	matches := gRxUnixRedirect.FindAllStringSubmatch(cmd, -1)

	for _, matcha := range matches {
		if len(matcha) < 2 {
			continue
		}
		redirect := matcha[0]
		filepath := strings.TrimSpace(matcha[1])

		cmd = strings.ReplaceAll(cmd, redirect, "")
		paths = append(paths, filepath)
	}

	return cmd, paths
}

func GenerateCriteria(tid string) error {
	var atomicTests = map[string][]*types.TestSpec{} // tid -> tests

	var unsafeRegex = regexp.MustCompile(`(\s|^)(rm|del|remove|Remove-Item|rmdir)(\s|$)`)

	err := utils.LoadAtomicsIndexCsvPlatform(filepath.FromSlash(flagAtomicsPath), &atomicTests, flagPlatform)
	if err != nil {
		fmt.Println("Unable to load Indexes-CSV file for Atomics", err)
		return errors.New("EOF")
	}

	if gVerbose {
		fmt.Println("Searching for test", tid)
	}

	tests, ok := atomicTests[tid]

	if !ok {
		if gVerbose {
			fmt.Println("An atomic test does not exist for this technique:", tid, "It could be an old copy of atomic-red-team repo or a fork or the criteria specifies an invalid technique")
		}
		// what error code should this return? for 'not found'?
		return errors.New("EOF")
	}

	// if no tests are present, return error code 422 (standard for 'Unprocessable Entity')
	if len(tests) == 0 {
		return errors.New("EOF")
	}

	yaml, err := utils.LoadAtomicsTechniqueYaml(tid, flagAtomicsPath)

	if err != nil {
		fmt.Println("Could not load Yaml for ", tid, err)
		return errors.New("Failed to Load")
	}
	var outfile *os.File

	if len(flagGenCriteriaOutPath) > 0 {
		var writeErr error
		outfile, writeErr = os.OpenFile(flagGenCriteriaOutPath+"/"+tid+".generated.csv", os.O_CREATE|os.O_WRONLY, 0644)

		if writeErr != nil {
			fmt.Println("ERROR: unable to create outfile", flagGenCriteriaOutPath+tid+".generated.csv", writeErr)
			return errors.New("io: read/write on closed pipe")
		}
		defer outfile.Close()
	} else {
		outfile = os.Stdout
	}

	for _, cur := range yaml.AtomicTests {

		tmp := strings.Join(cur.SupportedPlatforms, "|")
		if !strings.Contains(tmp, flagPlatform) {
			continue
		}
		if "manual" == strings.ToLower(cur.Executor.Name) {
			continue
		}

		//create readable variable names for criteria string array

		guid := strings.Split(cur.GUID, "-")[0]

		testName := strings.Replace(cur.Name, "\n", "", -1)

		generatedCriteria := []string{tid, flagPlatform, guid, testName}

		s := strings.Join(generatedCriteria, ",")

		s += fmt.Sprintln()

		//if this code were to be reused for non-generated tests, remove this statement
		genDisclaimer := []string{"FYI", "Auto-generated please review"}

		s += strings.Join(genDisclaimer, ",")

		s += fmt.Sprintln()

		// put input args in criteria, so they can be easily changed

		for name, val := range cur.InputArugments {
			s += fmt.Sprintf("ARG,%s,%s\n", name, val.Default)
		}

		//DEFAULT: Treat each command as a process event and use cmdline contains (~=) to show which command is run
		for _, rawcom := range strings.Split(cur.Executor.Command, "\n") {
			if len(rawcom) == 0 {
				continue
			}

			pipedCommands := SplitPipedCommands(rawcom, cur.Executor.Name)
			if len(pipedCommands) > 1 {
				s += fmt.Sprintln("# " + rawcom)

			}

			for _, com := range pipedCommands {
				com, comment := stripCommandComment(com, cur.Executor.Name)
				if len(com) == 0 {
					continue
				}

				if !gUnsafe {
					if unsafeRegex.MatchString(com) {
						s += "!!!\n"
						s += "FYI,Potentially destructive command found: " + com
					}
				}

				com, redirectTargets := extractFileRedirects(com, cur.Executor.Name)

				out := []string{"_E_", "Process", "cmdline~=" + com}
				s += strings.Join(out, ",") // TODO: CSV comma quoting
				s += fmt.Sprintln()
				if len(comment) > 0 {
					s += fmt.Sprintln("# " + comment)
				}

				for _, targetFile := range redirectTargets {
					out := []string{"_E_", "File", "WRITE", "path~=" + targetFile}
					s += strings.Join(out, ",") // TODO: CSV comma quoting
					s += fmt.Sprintln()
				}
			}
		}

		outfile.WriteString(s)

		//ensure a new line between every generated criteria
		fmt.Fprintln(outfile)
	}

	if len(flagGenCriteriaOutPath) > 0 {
		fmt.Println("Generated Criteria for", tid, "available at ./data/generated/"+tid+".generated.csv")
	}

	//successful

	return nil
}
func GenerateAllCriteria() error {
	var atomicTests = map[string][]*types.TestSpec{} // tid -> tests

	errRead := utils.LoadAtomicsIndexCsv(filepath.FromSlash(flagAtomicsPath), &atomicTests)

	if errRead != nil {
		fmt.Println("Unable to load Indexes-CSV file for Atomics", errRead)
		os.Exit(1)
	}

	for _, entries := range atomicTests {
		for _, test := range entries {

			if gVerbose {
				fmt.Println("Searching for test", test.Technique)
			}

			err := GenerateCriteria(test.Technique)

			if err != nil {
				fmt.Println(err)
			}

		}
	}

	//successful
	return nil

}

// fmt.Println("Found", numMatched, "in", total, "tests for platform", flagPlatform)

func main() {
	flag.Parse()

	if len(flagPlatform) == 0 {
		flagPlatform = utils.GetPlatformName()
	}

	FillInToolPathDefaults()

	if gPatchCriteriaRefsMode {
		PatchCriteriaGuids()
		return
	}

	if len(gFindTestVal) > 0 {
		FindMatchingTests(strings.ToLower(gFindTestVal))
		return
	}

	if gFindTestCoverage {
		FindTestCoverage()
		return
	}

	if len(flagGenCriteria) > 0 {
		if flagGenCriteria == "all" {
			GenerateAllCriteria()
			return
		}
		GenerateCriteria(strings.ToUpper(flagGenCriteria))
		return
	}

}
