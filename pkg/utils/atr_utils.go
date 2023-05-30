package utils

/*
 * CSV data format and type definitions
 */

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

func LoadAtomicsTechniqueYaml(tid string, atomicsDir string) (*types.Atomic, error) {
	if !strings.HasPrefix(tid, "T") {
		tid = "T" + tid
	}

	var body []byte

	if atomicsDir == "" {
		return nil, fmt.Errorf("missing atomic dir")
	}

	// Check to see if test is defined locally first. If not, body will be nil
	// and the test will be loaded below.
	body, _ = os.ReadFile(atomicsDir + "/" + tid + "/" + tid + ".yaml")
	if len(body) == 0 {
		body, _ = os.ReadFile(atomicsDir + "/" + tid + "/" + tid + ".yml")
	}

	if len(body) != 0 {
		var technique types.Atomic

		if err := yaml.Unmarshal(body, &technique); err != nil {
			return nil, fmt.Errorf("processing Atomic Test YAML file: %w", err)
		}

		technique.BaseDir = atomicsDir
		return &technique, nil
	}

	return nil, fmt.Errorf("missing atomic", tid)
}

func GetPlatformName() string {
	var platform = runtime.GOOS
	if runtime.GOOS == "darwin" {
		platform = "macos"
	}
	return platform
}

func LoadAtomicsIndexCsv(atomicsPath string, dest *map[string][]*types.TestSpec) error {
	return LoadAtomicsIndexCsvPlatform(atomicsPath, dest, "")
}

func LoadAtomicsIndexCsvPlatform(atomicsPath string, dest *map[string][]*types.TestSpec, platform string) error {

	var path string
	if len(platform) == 0 {
		platform = GetPlatformName()
	}
	path = atomicsPath + "/Indexes/Indexes-CSV/" + platform + "-index.csv"

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	r := csv.NewReader(bytes.NewReader(data))
	r.LazyQuotes = true

	records, err := r.ReadAll()
	if err != nil {
		log.Fatal(err)
	}

	// Tactic,Technique #,Technique Name,Test #,Test Name,Test GUID,Executor Name

	for i, row := range records {
		if i == 0 {
			continue // skip header row
		}
		if len(row) < 6 || len(row[0]) == 0 || row[0][0] == '#' {
			continue
		}
		spec := &types.TestSpec{}

		spec.Technique = row[1]
		spec.TestIndex = row[3]
		spec.TestName = row[4]
		spec.TestGuid = row[5]

		_, ok := (*dest)[spec.Technique]
		if !ok {
			(*dest)[spec.Technique] = []*types.TestSpec{}
		}

		// The indexes are listed by Tactic, and some techniques appear in more than one.
		// So filter out duplicates. 65 duplicates found in linux index

		notPresent := true
		for _, entry := range (*dest)[spec.Technique] {
			if spec.Technique == entry.Technique && spec.TestGuid == entry.TestGuid {
				notPresent = false
				break
			}
		}
		if notPresent {
			(*dest)[spec.Technique] = append((*dest)[spec.Technique], spec)
		}

	}
	return nil
}
