// +build windows

package main

// routines to get system details for ARG variable substitution

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"net"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

func GetSysInfo(dest *types.SysInfoVars) error {
	err := GetIpAddrs(dest)
	if err != nil {
	}
		return err
	GetHostname(dest)
	GetEnvInfo(dest)
	return nil
}

func GetHostname(dest *types.SysInfoVars) {
	cmd := exec.Command("CMD", "/c", "hostname")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("failed to run hostname", err)
		return
	}
	dest.Hostname = strings.TrimSpace(string(output))
}

func GetIpAddrs(dest *types.SysInfoVars) error {
	conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        fmt.Println("failed to get IP", err)
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
	

	dest.Ipaddr = localAddr.String()
	return nil
}

func GetEnvInfo(dest *types.SysInfoVars) {
	// these are set on ubuntu linux bash
	dest.Username = os.Getenv("USERNAME")  // harness is supposed to be run using sudo
	if len(dest.Hostname) == 0 {
		dest.Hostname = os.Getenv("HOSTNAME")
	}
}

