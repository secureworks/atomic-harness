package main

import (
	"fmt"
)

// from CSV

type FieldCriteria struct {
	FieldName string              `json:"field"`
	Op        string              `json:"op"`
	Value     string              `json:"value"`
}


// _E_,Process,cmdline=echo "# THIS IS A COMMENT"
// _E_,File,WRITE,path=/etc/ufw/ufw.conf
type ExpectedEvent struct {
	Id          string            `json:"id"`
	EventType   string            `json:"event_type"`
	SubType     string            `json:"sub_type,omitempty"`
	FieldChecks []FieldCriteria   `json:"field_checks"`
	IsMaybe     bool              `json:"is_maybe,omitempty"`


	Matches     []string   `json:"matches,omitempty"`
}
/*type ExpectedEvent struct {
	Id int
	Type string
	SubType string
	Matches []string
}*/

// _C_,Process,Pipe,0,1
type CorrelationRow struct {
	Id string                     `json:"id"`
	Type string                   `json:"type"`
	SubType string                `json:"sub_type"`
	EventIndexes []string         `json:"indexes"`
	IsMet bool                    `json:"is_met"`
}

// _A_,Process,exit elevated
// _A_,Process,high_cpu
type AlertRow struct {
	Type string
	Matches []string
}

// ARG,remote_host,victim-host
type ArgRow struct {
	Name string
	Value string
}

type MitreTestCriteria struct {
	Technique        string              `json:"technique"`
	TestIndex        uint                `json:"test_index"`
	TestName         string              `json:"test_name"`
	ExpectedEvents   []*ExpectedEvent     `json:"expected_events"`
	ExpectedCorrelations []*CorrelationRow  `json:"exp_correlations,omitempty"`
}

// T1562.004,linux,7,Stop/Start UFW firewall
type AtomicTestCriteria struct {
	MitreTestCriteria
	Platform string                        `json:"platform,omitempty"`
	Args map[string]string                 `json:"args,omitempty"`
	Infos []string                         `json:"infos,omitempty"` // FYI
	Warnings []string                      `json:"warnings,omitempty"` // !!!

	ExpectedCorrelations []CorrelationRow  `json:"exp_correlations,omitempty"`
}

func (s *AtomicTestCriteria) Id() string {
	return s.Technique + "#" + fmt.Sprintf("%d",s.TestIndex)
}

// system info for variable substitution

type SysInfoVars struct {
	Hostname   string
	Netif      string // default network interface
	Ipaddr4    string
	Ipaddr6    string
	LlIpaddr6  string
	Macaddr    string
	Ipaddr     string // first avail: ipv4 or ipv6
	Gateway    string // e.g. 10.0.0.1
	SubnetMask string // e.g. 0xffffff00
	Subnet     string // e.g. 10.0.0
	Username   string
}

