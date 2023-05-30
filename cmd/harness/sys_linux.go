//go:build linux
// +build linux

package main

// routines to get system details for ARG variable substitution

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

func GetSysInfo(dest *types.SysInfoVars) error {
	err := GetIpAddrs(dest)
	if err != nil {
		return err
	}
	GetHostname(dest)
	GetEnvInfo(dest)
	return nil
}

func GetHostname(dest *types.SysInfoVars) {
	cmd := exec.Command("hostname")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("failed to run hostname", err)
		return
	}
	dest.Hostname = strings.TrimSpace(string(output))
}

func GetIpAddrs(dest *types.SysInfoVars) error {
	cmd := exec.Command("ip", "addr")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	ParseIpAddrOutput(dest, string(output))

	// get first addr, v4 or v6

	dest.Ipaddr = dest.Ipaddr4
	if dest.Ipaddr == "" {
		dest.Ipaddr = dest.Ipaddr6
	} else {
		LazyGatewaySubnet(dest)
	}

	return nil
}

func GetEnvInfo(dest *types.SysInfoVars) {
	// these are set on ubuntu linux bash
	dest.Username = os.Getenv("SUDO_USER") // harness is supposed to be run using sudo
	if len(dest.Hostname) == 0 {
		dest.Hostname = os.Getenv("HOSTNAME")
	}
}

// rather than getting actual values, this uses Ipaddr4 and assumes
func LazyGatewaySubnet(dest *types.SysInfoVars) {
	if dest.Ipaddr4 == "" {
		return
	}
	a := strings.SplitN(dest.Ipaddr4, ".", 4)
	dest.Subnet = fmt.Sprintf("%s.%s.%s", a[0], a[1], a[2])
	dest.Gateway = dest.Subnet + ".1"
}

func ParseIpAddrOutput(dest *types.SysInfoVars, s string) {
	a := strings.SplitN(s, "\n", 100)
	currentIf := ""
	for _, line := range a {
		trimmed := strings.TrimLeft(line, " \t")
		if len(trimmed) == 0 {
			continue
		}
		if line[0] == trimmed[0] {
			// interface line
			// 2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
			tmp := strings.SplitN(line, ":", 3)
			ifname := strings.TrimSpace(tmp[1])

			// ignore loopback

			if ifname == "lo" {
				currentIf = ""
				continue
			}

			// ignore links down

			if strings.Contains(tmp[2], "state DOWN") {
				currentIf = ""
				continue
			}

			currentIf = ifname
			dest.Netif = ifname

		} else if currentIf != "" {
			// detail line
			if strings.HasPrefix(trimmed, "inet6") {
				// inet6 fe80::2705:2628:3cd2:1124/64 scope link noprefixroute
				tmp := strings.SplitN(trimmed, " ", 3)
				tmp = strings.SplitN(tmp[1], "/", 2)
				dest.Ipaddr6 = tmp[0]
			} else if strings.HasPrefix(trimmed, "inet") {
				// inet 10.0.0.6/24 brd 10.0.0.255 scope global dynamic noprefixroute ens33
				tmp := strings.SplitN(trimmed, " ", 3)
				tmp = strings.SplitN(tmp[1], "/", 2)
				dest.Ipaddr4 = tmp[0]
			}
		}
	}
}
