package utils

/*
 * CSV data format and type definitions
 */

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

// id,type,hostname,addr,port,username,password,pubkey
// # the detection rules for $SERVER[rsync_server].addr will match next line
// rsync_server,rsync,,10.0.0.16,873,rsyncuser,rsyncpass531,

type ServerConfig struct {
	Id       string
	Type     string
	Hostname string
	Addr     string
	Port     string
	Username string
	Password string
	Pubkey   string
}

func LoadServerConfigsCsv(path string, dest *map[string]string) error {
	data, err := ioutil.ReadFile(path)
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

	for i, row := range records {
		if i == 0 {
			continue // skip header row
		}
		if len(row) == 0 || len(row[0]) == 0 || row[0][0] == '#' {
			continue
		}
		if len(row) != 8 {
			fmt.Println("server config row should have 8 columns:", row)
			continue
		}

		obj := &ServerConfig{row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]}

		if obj.Hostname != "" {
			(*dest)["$SERVER["+obj.Id+"].addr"] = obj.Hostname
			(*dest)["$SERVER["+obj.Type+"].addr"] = obj.Hostname
		}
		if obj.Addr != "" {
			(*dest)["$SERVER["+obj.Id+"].addr"] = obj.Addr
			(*dest)["$SERVER["+obj.Type+"].addr"] = obj.Addr
		}
		if obj.Port != "" {
			(*dest)["$SERVER["+obj.Id+"].port"] = obj.Port
			(*dest)["$SERVER["+obj.Type+"].port"] = obj.Port
		}
		if obj.Username != "" {
			(*dest)["$SERVER["+obj.Id+"].username"] = obj.Username
			(*dest)["$SERVER["+obj.Type+"].username"] = obj.Username
		}
		if obj.Password != "" {
			(*dest)["$SERVER["+obj.Id+"].password"] = obj.Password
			(*dest)["$SERVER["+obj.Type+"].password"] = obj.Password
		}
		if obj.Pubkey != "" {
			(*dest)["$SERVER["+obj.Id+"].pubkey"] = obj.Pubkey
			(*dest)["$SERVER["+obj.Type+"].pubkey"] = obj.Pubkey
		}
	}

	return nil
}

func LoadFailedTechniquesList(prevResultsDir string, dest *[]*types.TestSpec) error {
	results := []types.TestProgress{}

	path := prevResultsDir
	if !strings.HasSuffix(path, ".json") {
		path += "/status.json"
	}
	body, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Failed to load", path, err)
		return err
	}
	if len(body) == 0 {
		fmt.Println("status.json is empty")
		return nil
	}
	if err = json.Unmarshal(body, &results); err != nil {
		fmt.Println("failed to parse", path, err)
		return err
	}

	for _, entry := range results {
		if entry.Status == types.StatusValidateSuccess || entry.Status == types.StatusSkipped {
			continue
		}
		spec := &types.TestSpec{}

		spec.Technique = entry.Technique
		spec.TestIndex = entry.TestIndex
		spec.TestName = entry.TestName

		(*dest) = append((*dest), spec)
	}
	return nil
}
