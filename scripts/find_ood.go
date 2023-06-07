package main

/*
 * CSV data format and type definitions
 */

/* Find_OutOfDate.Go:
Creates a text file that delineates every criteria which may be out of date based on the commit times to https://github.com/redcanaryco/atomic-red-team/tree/master/atomics
and https://github.com/secureworks/atomic-validation-criteria/tree/master.

Because we cannot assume that there will be the same number of tests as new tests are added, we will need to mark
'not found' tests and either prompt the user to generate the test or do it automatically.

In addition, as an unfortunate consequence of how files are stored in the criteria repo https://github.com/secureworks/atomic-validation-criteria,
we will need to map each test to the file it originated from, since the tests are sometimes stored together (ex. windows/T1027-T1047.csv), and sometimes stored alone (Ex: macos/T1000_macos.csv)
*/

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var flagCriteriaPath string
var flagAtomicsPath string
var gVerbose = false
var gMissing = false
var flagOutPath string

func init() {
	flag.StringVar(&flagCriteriaPath, "criteriapath", "", "path to folder containing CSV files used to validate telemetry")
	flag.StringVar(&flagAtomicsPath, "atomicspath", "", "path to local atomics folder")
	flag.StringVar(&flagOutPath, "outfile", "", "path to directory you want data stored to")
	flag.BoolVar(&gVerbose, "verbose", false, "print more details")
	flag.BoolVar(&gMissing, "missing", false, "also show missing criteria")
}

func FillInToolPathDefaults() {
	cwd, _ := os.Getwd()
	if cwd == "" {
		cwd = "."
	}
	if flagCriteriaPath == "" {
		flagCriteriaPath = cwd + "/../../atomic-validation-criteria"
	}
	if flagAtomicsPath == "" {
		flagAtomicsPath = cwd + "/../../atomic-red-team/atomics"
	}
}

func RetreiveCommitIDs(atomicsPath string) []string {

	//pull any changes from remote
	pull := exec.Command("git", "pull")

	//first get a log of all commits:
	log := exec.Command("git", "log", "--since=\"2022-01-01\"", "--pretty=oneline", "--decorate=short")

	//for testing, keep it short please :)

	// log := exec.Command("git", "log", "--since=\"2022-05-01\"", "--pretty=oneline", "--decorate=short")

	//TODO: replace with Atomics Path (probably by flag)
	log.Dir = filepath.FromSlash(atomicsPath)
	pull.Dir = filepath.FromSlash(atomicsPath)

	err := pull.Run()

	if err != nil {
		panic(err)
	}

	if gVerbose {
		fmt.Println("git pull success")
	}

	output, err := log.Output()

	if err != nil {
		panic(err)
	}

	//fmt.Println(string(output))

	//output looks good, now parse for all commit ids

	var commitIDs []string

	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		comID := strings.Split(line, " ")

		if gVerbose {
			fmt.Println(comID[0])
		}
		commitIDs = append(commitIDs, comID[0])
	}

	return commitIDs
}

func FindTestCommitDates(path string) map[string]string {

	commitIDs := RetreiveCommitIDs(path)

	// keep the user up to date...
	fmt.Println("Just found", len(commitIDs), "commits on the atomics repo (since 2022-01-01)... you're in for a treat!")
	wait := fmt.Sprintf("%s %d %s", "If I had to guess, this will probably take...", (len(commitIDs)/1000)+1, "minutes?")
	fmt.Println(wait)
	fmt.Println("Also, FYI, you might get some file errors later on... I swear its not my fault! (okay, it might be)")

	if len(commitIDs) <= 0 {
		panic("Seems like the path to your atomic-validation-criteria directory is not the default. Try the -criterapath flag!")
	}

	findTest := regexp.MustCompile(`atomics\/(T\d{4}(?:\.\d{3})?)`)
	findDate := regexp.MustCompile(`"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+[+-]\d{4}"`)

	uptoDateMap := make(map[string]string)

	for _, comID := range commitIDs {

		var date string

		if gVerbose {
			fmt.Println("Getting Date information for commit", comID)
		}

		comInfo := exec.Command("git", "show", "--name-only", "--format=\"%ad\"", comID)

		comInfo.Dir = filepath.FromSlash(path)

		output, err := comInfo.Output()

		if err != nil {
			fmt.Println(err)
			continue
		}

		strOutput := string(output)

		// fmt.Println(strOutput)

		//first, find the date of the commit:
		match := findDate.FindString(strOutput)

		if match != "" {
			date = match[1 : len(match)-1]
			if gVerbose {
				fmt.Println("Date:", date)
			}
		} else {
			if gVerbose {
				fmt.Println("No date found in the string.")
			}
		}

		matches := findTest.FindAllStringSubmatch(strOutput, -1)

		for _, match := range matches {

			if len(match) > 1 {
				test := match[1]
				if gVerbose {
					fmt.Println("Test:", test)
				}

				//because tests are processed by chronological order, the first time a test is referenced should be its most up to date change
				if len(uptoDateMap[test]) <= 0 {
					uptoDateMap[test] = date
				}
			}
		}
	}

	return uptoDateMap
}

// unfortunately, the criteria files are special in which they contain ranges of values. This will be treated accordingly.
func FindCriteriaCommitDates(criteriaPath string) map[string]string {

	//fill in default path
	if len(criteriaPath) == 0 {
		criteriaPath = "../atomic-validation-criteria"
	}

	commitIDs := RetreiveCommitIDs(criteriaPath)

	if len(commitIDs) <= 0 {
		panic("Seems like the path to your atomic-validation-criteria directory is not the default. Try the -criterapath flag!")
	}

	findPath := regexp.MustCompile(`\S+\.csv`)
	findDate := regexp.MustCompile(`"\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+[+-]\d{4}"`)

	criteriaDateMap := make(map[string]string)

	// from the commit IDs, we will get the date, and the path to the file
	for _, comID := range commitIDs {

		var date string
		if gVerbose {
			fmt.Println("Getting Date information for commit", comID)
		}
		comInfo := exec.Command("git", "show", "--name-only", "--format=\"%ad\"", comID)

		comInfo.Dir = filepath.FromSlash(criteriaPath)

		output, err := comInfo.Output()
		if err != nil {
			fmt.Println(err)
			continue
		}

		strOutput := string(output)

		//first, find the date of the commit:
		match := findDate.FindString(strOutput)

		if match != "" {
			date = match[1 : len(match)-1]
			if gVerbose {
				fmt.Println("Date:", date)
			}
		} else {
			if gVerbose {
				fmt.Println("No date found in the string.")
			}
		}

		// find the path to the file to be read

		matches := findPath.FindAllString(strOutput, -1)

		for _, path := range matches {

			critPath := criteriaPath + "/" + path

			if gVerbose {
				fmt.Println("criteria path:", critPath)
			}

			criteria, err := ListCriteriaInFile(filepath.FromSlash(critPath))

			if err != nil {
				fmt.Println(err)
				continue
			}

			for _, crit := range criteria {
				if gVerbose {
					fmt.Println("Criteria found:", crit)
				}
				criteriaDateMap[crit] = date
			}

		}

		// for each commit, find the date it occured and which files it affected. From those files, parse which are tests, and record the *most recent* time it was updated
	}

	return criteriaDateMap
}

type FlaggedCriteria struct {
	Name            string
	CriteriaDate    string
	TestUpdatedDate string
}

type NotFoundCriteria struct {
	Name        string
	UpdatedDate string
}

func prettifyCriteria(intef interface{}, outfile *os.File) {
	output, _ := json.MarshalIndent(intef, "", "\t")

	fmt.Fprintf(outfile, "%s \n", output)
}

func CompareCommitDates() ([]FlaggedCriteria, []NotFoundCriteria) {

	var crit []FlaggedCriteria

	var notFound []NotFoundCriteria

	redCanaryDates := FindTestCommitDates(flagAtomicsPath)

	criteriaDates := FindCriteriaCommitDates(flagCriteriaPath)

	// all dates are parsed: now time to find which tests are out of date (i.e. if redCanaryDate > criteriaDate)

	for test, date := range redCanaryDates {

		criteriaDate := criteriaDates[test]
		if gVerbose {
			fmt.Println("Canary Test: ", test)
			fmt.Println("Canary Test Date: ", date)
			fmt.Println("Corresponding Test Date: ", criteriaDate)
		}

		if len(criteriaDate) == 0 {
			if gVerbose {
				fmt.Println("No criteria found for", test)
			}
			notFound = append(notFound, NotFoundCriteria{Name: test, UpdatedDate: date})
			continue
		}

		outofDate, date := compareDates(criteriaDate, date)

		if outofDate {
			if gVerbose {
				fmt.Println("found test out of date: \n", test, "Criteria Last Updated:", criteriaDate, "Test last updated: ", date)
			}
			crit = append(crit, FlaggedCriteria{Name: test, CriteriaDate: criteriaDate, TestUpdatedDate: date})
		}

	}
	return crit, notFound

}

// this function will return the most recent date from the comparison in both dates
func compareDates(date1Str string, date2Str string) (bool, string) {
	layout := "Mon Jan 2 15:04:05 2006 -0700"

	date1, _ := time.Parse(layout, date1Str)
	date2, _ := time.Parse(layout, date2Str)

	if len(date1Str) <= 0 {
		return false, date2Str
	}
	if len(date2Str) <= 0 {
		return false, date1Str
	}

	if date1.Before(date2) {
		return true, date2Str

	} else if date1.After(date2) {
		return false, date1Str

	} else {
		return false, date2Str
	}
}

func ListCriteriaInFile(filename string) ([]string, error) {
	retval := []string{}
	mapTech := map[string]bool{}

	filename = filepath.FromSlash(filename)
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return retval, err
	}

	r := csv.NewReader(bytes.NewReader(data))
	r.LazyQuotes = true
	r.Comment = '#'
	r.FieldsPerRecord = -1 // no validation on num columns per row

	records, err := r.ReadAll()
	if err != nil {
		fmt.Println("ERROR parsing CSV", filename, err)
		return retval, err
	}

	for _, row := range records {

		if 3 != len(row[0]) {

			if len(row[0]) < 3 {
				continue
			}
			if row[0][0] == '#' {
				continue
			}
			if row[0][0] == 'T' {
				techniqueId := row[0]
				mapTech[techniqueId] = true
			} else {
				// ignore
			}
		} else {
			// ignore
		}
	}

	// extract keys from map into array

	for key, _ := range mapTech {
		retval = append(retval, key)
	}

	return retval, nil
}

func main() {
	flag.Parse()

	FillInToolPathDefaults()

	var outfile *os.File
	if len(flagOutPath) > 0 {
		var writeErr error
		outfile, writeErr = os.OpenFile(flagOutPath+"/outofdate.csv", os.O_CREATE|os.O_WRONLY, 0644)

		if writeErr != nil {
			fmt.Println("ERROR: unable to create outfile", flagOutPath+"/outofdate.csv", writeErr)
			return
		}
		defer outfile.Close()
	} else {
		outfile = os.Stdout
	}

	fmt.Println("Hang on, this will take a while...")

	caption := "Criteria Flagged: May be out of Date: \n"
	flagged, notFound := CompareCommitDates()
	outfile.WriteString(caption)
	for _, criteria := range flagged {
		prettifyCriteria(criteria, outfile)
	}

	if gMissing {
		caption = "\nCritera Not Found: \n"
		outfile.WriteString(caption)
		for _, criteria := range notFound {
			prettifyCriteria(criteria, outfile)
		}
	}

	if len(flagOutPath) > 0 {
		fmt.Println("Output stored to", flagOutPath+"/outofdate.csv")
		return
	}
	fmt.Println("Done!")

}
