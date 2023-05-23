package utils

/*
 * Validation criteria CSV data format and type definitions
 */

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

func AtomicTestCriteriaNew(tid string, plat string, numstr string, name string) *types.AtomicTestCriteria {
	obj := &types.AtomicTestCriteria{}
	obj.Technique = tid
	obj.Platform = plat
	obj.TestName = name
	obj.Args = make(map[string]string)

	if len(numstr) >= 8 {
		obj.TestGuid = numstr
	} else {
		// parse the 1-based test number
		val, err := strconv.ParseUint(numstr,10,32)
		obj.TestIndex = uint(val)
		if err != nil {
			fmt.Println("ERROR: TestIndex is not an integer",numstr)
		}
	}
	return obj
}

func ParseFieldCriteria(str string, eventType string) (*types.FieldCriteria, error) {
	a := strings.SplitN(str,"=",2)
	if len(a) != 2 {
		if eventType == "FILE" {
			// assume it's a path
			a = []string{"path",str}
		} else {
			return nil, fmt.Errorf("no operator")
		}
	}
	fc := &types.FieldCriteria{}
	fc.FieldName = a[0]
	fc.Value = a[1]
	namelen := len(fc.FieldName)

	switch(fc.FieldName[namelen-1]) {
	case '*':
		fc.Op = "*="
		namelen -= 1
	case '~':
		fc.Op = "~="
		namelen -= 1
	default:
		fc.Op = "="
	}

	// TODO: trim whitespace on name, value
	fc.FieldName = fc.FieldName[:namelen]

	return fc,nil
}

func EventFromRow(id int, row []string) types.ExpectedEvent {
	obj := types.ExpectedEvent{}
	obj.Id = string(id)
	obj.EventType = row[1] //strings.ToTitle(strings.ToLower(row[1]))
	idx := 2
	ET := strings.ToUpper(obj.EventType)
	if ET == "FILE" || ET == "MODULE" || ET == "ALERT" { // TODO: better match and validate values
		obj.SubType = row[2] // TODO: can have multiple CREATE|WRITE
		idx += 1
	}
	if ET == "NETFLOW" {
		obj.SubType = row[2] // TCP:*->victim-host:22
		idx += 1
	}
	if ET == "NETSNIFF" {
		obj.SubType = row[2] // 
		idx += 1
	}
	for i := idx; i < len(row); i++ {
		entry, err := ParseFieldCriteria(row[i], ET)
		if err != nil {
			fmt.Println("ERROR: invalid FieldCriteria:" + row[i], err)
			continue
		}
		obj.FieldChecks = append(obj.FieldChecks, *entry)
	}
	return obj
}

func CorrelationFromRow(row []string) types.CorrelationRow {
	obj := types.CorrelationRow{}
	obj.Type = row[1]
	obj.SubType = row[2]
	for i := 3; i < len(row); i++ {
		obj.EventIndexes = append(obj.EventIndexes, row[i])
	}
	return obj
}

/*
 * loads CSV containing rows of TechniqueId,TacticId,Name
 * Populates dest with TechniqueId-Name
 */
func LoadMitreTechniqueCsv(path string, dest *map[string]string) error {
	data, err := ioutil.ReadFile(filepath.FromSlash(path))
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

	for i,row := range records {
		if i == 0 {
			continue; // skip header row
		}
		if len(row) < 3 || len(row[0])==0 || row[0][0] == '#' {
			continue
		}
		(*dest)[row[0]] = row[2]
	}
	return nil
}



func LoadAtomicDefaultArgs(criteria *types.AtomicTestCriteria, flagAtomicsPath string, isVerbose bool) {
	var body []byte

	// Check to see if test is defined locally first. If not, body will be nil
	// and the test will be loaded below.
	atomicsPath,_ := filepath.Abs(flagAtomicsPath)
	path := atomicsPath + "/" + criteria.Technique + "/" + criteria.Technique + ".yaml"
	if isVerbose {
		fmt.Println("loading",path)
	}
	body, _ = os.ReadFile(path)
	if len(body) == 0 {
		path = strings.ReplaceAll(path,".yaml",".yml")
		fmt.Println("loading",path)
		body, _ = os.ReadFile(path)
	}

	if len(body) == 0 {
		fmt.Println("Failed to load atomic for ", criteria.Technique)
		return
	}

	var atoms types.Atomic

	if err := yaml.Unmarshal(body, &atoms); err != nil {
		fmt.Println("processing Atomic Test YAML file", err)
		return
	}

	for i, testInfo := range atoms.AtomicTests {
		if criteria.TestIndex > 0 {
			if ((criteria.TestIndex-1) != uint(i)) {
				continue
			}
		} else if len(criteria.TestGuid) > 0 {
			if !strings.HasPrefix(testInfo.GUID, criteria.TestGuid) {
				continue
			}
		} else {
			fmt.Println("Criteria missing TestNum or TestGuid", criteria.Technique, criteria.TestIndex, criteria.TestGuid)
			return
		}
		for name,obj := range testInfo.InputArugments {
			_,ok := criteria.Args[name]
			if ok {
				continue // we have override value
			}
			if isVerbose {
				fmt.Printf("  Loading default arg %s:'%s'\n",name,obj.Default)
			}

			val := strings.ReplaceAll(obj.Default,"$PathToAtomicsFolder",atomicsPath)
			val = strings.ReplaceAll(val,"PathToAtomicsFolder",atomicsPath)

			criteria.Args[name] = val
		}
	}
}

