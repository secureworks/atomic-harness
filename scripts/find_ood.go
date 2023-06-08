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
	"strings"
	"time"
)

var flagCriteriaPath string
var flagAtomicsPath string
var gVerbose = false
var flagOutPath string

func init() {
	flag.StringVar(&flagCriteriaPath, "criteriapath", "", "path to folder containing CSV files used to validate telemetry")
	flag.StringVar(&flagAtomicsPath, "atomicspath", "", "path to local atomics folder")
	flag.StringVar(&flagOutPath, "outfile", "", "path to directory you want data stored to")
	flag.BoolVar(&gVerbose, "verbose", false, "print more details")
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

// unfortunately, the criteria files are special in which they contain ranges of values. This will be treated accordingly.
func FindCriteriaCommitDates(criteriaPath string) map[string]string {

	dirPath := filepath.FromSlash(criteriaPath)

	winDir := dirPath + "/windows"
	linuxDir := dirPath + "/linux"
	macosDir := dirPath + "/macos"

	criteriaDateMap := make(map[string]string)

	pull := exec.Command("git", "pull")

	pull.Dir = dirPath

	pullErr := pull.Run()

	if pullErr != nil {
		panic(pullErr)
	}
	if gVerbose {
		fmt.Println("Pull on Criteria Repo Successful")
	}

	readWindowsErr := ListCriteria(winDir, criteriaDateMap)
	if readWindowsErr != nil {
		fmt.Println("Could not read Windows Directory")
	}

	readMacosErr := ListCriteria(macosDir, criteriaDateMap)
	if readMacosErr != nil {
		fmt.Println("Could not read Macos Directory")
	}

	readLinuxErr := ListCriteria(linuxDir, criteriaDateMap)
	if readLinuxErr != nil {
		fmt.Println("Could not read Linux Directory")
	}

	return criteriaDateMap
}

type FlaggedCriteria struct {
	Name            string
	CriteriaDate    string
	TestUpdatedDate string
}

func prettifyCriteria(intef interface{}, outfile *os.File) {
	output, _ := json.MarshalIndent(intef, "", "\t")

	fmt.Fprintf(outfile, "%s \n", output)
}

func CompareCommitDates() []FlaggedCriteria {

	var crit []FlaggedCriteria

	criteriaDates := FindCriteriaCommitDates(flagCriteriaPath)

	for test, date := range criteriaDates {

		if gVerbose {
			fmt.Println("Edits to test since criteria were made: ", test)
		}

		log := exec.Command("git", "log", "--since="+date, flagAtomicsPath+"/"+test)

		log.Dir = filepath.FromSlash(flagAtomicsPath)

		output, logErr := log.Output()

		if logErr != nil {
			fmt.Println("ERROR: unable to parse the file "+flagAtomicsPath+"/"+test, logErr, ": the test may not exist")
			continue
		}

		strOutput := string(output)

		if len(strOutput) > 0 {
			if gVerbose {
				fmt.Println("Possibly out of date criteria for test:", test)
			}
			// parse the criteria for the date it was updated
			lines := strings.Split(strOutput, "\n")

			testDate := strings.Trim(lines[2], "Date: ")

			crit = append(crit, FlaggedCriteria{Name: test, CriteriaDate: translateDate(date), TestUpdatedDate: testDate})
		} else {
			if gVerbose {
				fmt.Println("Criteria up to date for test", test)
			}
		}

	}

	// all dates are parsed: now time to find which tests are out of date (i.e. if redCanaryDate > criteriaDate)
	return crit

}

func translateDate(dateStr string) string {
	inputLayout := "2006-01-02 15:04:05 -0700"
	outputLayout := "Mon Jan 02 15:04:05 2006 -0700"

	t, err := time.Parse(inputLayout, dateStr)
	if err != nil {
		fmt.Println("Error while parsing date:", err)
		return ""
	}

	output := t.Format(outputLayout)

	return output
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

func ListCriteria(dirPath string, dateMap map[string]string) error {

	dirPath = filepath.FromSlash(dirPath)
	allfiles, err := ioutil.ReadDir(dirPath)
	if err != nil {
		fmt.Println("ERROR: unable to list files in "+dirPath, err)
		return err
	}
	for _, f := range allfiles {

		var date string

		if !strings.HasSuffix(f.Name(), ".csv") {
			continue
		}
		if strings.Contains(f.Name(), "_withguids") {
			continue
		}

		if gVerbose {
			fmt.Println("Loading " + f.Name())
		}
		//find the date
		log := exec.Command("git", "log", "-n", "1", "--date", "iso", "./"+f.Name())

		log.Dir = filepath.FromSlash(dirPath)

		output, logErr := log.Output()

		if logErr != nil {
			fmt.Println("ERROR: unable to list files in "+dirPath, err)
			return err
		}

		strOutput := string(output)

		// parse output for the date
		lines := strings.Split(strOutput, "\n")

		date = strings.Trim(lines[2], "Date: ")

		//assign date to each technique
		techniqueIds, err := ListCriteriaInFile(filepath.FromSlash(dirPath + "/" + f.Name()))

		if err != nil {
			fmt.Println("ERROR:", err)
			return nil
		} else {
			for _, technique := range techniqueIds {
				if gVerbose {
					fmt.Println("Assigning technique", technique, "to date", date)
				}
				dateMap[technique] = date
			}
		}
	}

	return nil
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

	caption := "Criteria Flagged -> May be out of Date: \n"
	flagged := CompareCommitDates()
	outfile.WriteString(caption)
	for _, criteria := range flagged {
		prettifyCriteria(criteria, outfile)
	}

	if len(flagOutPath) > 0 {
		fmt.Println("Output stored to", flagOutPath+"/outofdate.csv")
		return
	}
	fmt.Println("Done!")

}
