//go:build darwin
// +build darwin

package main

// routines to get system details for ARG variable substitution

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

var gSubnetMaskMappings = map[string]string{
	"0x00000000": "0.0.0.0",
	"0x80000000": "128.0.0.0",
	"0xc0000000": "192.0.0.0",
	"0xe0000000": "224.0.0.0",
	"0xf0000000": "240.0.0.0",
	"0xf8000000": "248.0.0.0",
	"0xfc000000": "252.0.0.0",
	"0xfe000000": "254.0.0.0",
	"0xff000000": "255.0.0.0",
	"0xff800000": "255.128.0.0",
	"0xffc00000": "255.192.0.0",
	"0xffe00000": "255.224.0.0",
	"0xfff00000": "255.240.0.0",
	"0xfff80000": "255.248.0.0",
	"0xfffc0000": "255.252.0.0",
	"0xfffe0000": "255.254.0.0",
	"0xffff0000": "255.255.0.0",
	"0xffff8000": "255.255.128.0",
	"0xffffc000": "255.255.192.0",
	"0xffffe000": "255.255.224.0",
	"0xfffff000": "255.255.240.0",
	"0xfffff800": "255.255.248.0",
	"0xfffffc00": "255.255.252.0",
	"0xfffffe00": "255.255.254.0",
	"0xffffff00": "255.255.255.0",
	"0xffffff80": "255.255.255.128",
	"0xffffffc0": "255.255.255.192",
	"0xffffffe0": "255.255.255.224",
	"0xfffffff0": "255.255.255.240",
	"0xfffffff8": "255.255.255.248",
	"0xfffffffc": "255.255.255.252",
	"0xfffffffe": "255.255.255.254",
	"0xffffffff": "255.255.255.255",
}

func GetSysInfo(dest *types.SysInfoVars) error {
	err := GetIpInfo(dest)
	if err != nil {
		return err
	}
	GetHostName(dest)
	GetUserName(dest)
	return nil
}

func GetHostName(dest *types.SysInfoVars) {
	cmd := exec.Command("hostname")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("failed to run hostname", err)
		return
	}
	dest.Hostname = strings.TrimSpace(string(output))
}

func GetUserName(dest *types.SysInfoVars) {
	cmd := exec.Command("whoami")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Println("failed to run hostname", err)
		return
	}
	dest.Username = strings.TrimSpace(string(output))
}

func GetIpInfo(dest *types.SysInfoVars) error {

	// get active interface
	var activeInterface string
	err := GetActiveInetInterface(&activeInterface)
	if err != nil {
		return err
	}

	// get details of active interface
	cmd := exec.Command("ifconfig", activeInterface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}

	ParseInterfaceDetails(dest, string(output))

	// get first addr, v4 or v6
	dest.Ipaddr = dest.Ipaddr4
	if dest.Ipaddr == "" {
		dest.Ipaddr = dest.Ipaddr6
	}

	// get default gateway
	var defaultGateway string
	err = GetActiveGateway(&defaultGateway)
	if err != nil {
		return err
	}
	dest.Gateway = defaultGateway

	// get subnet address
	dest.Subnet = CalculateSubnetIPv4(dest.Ipaddr4, dest.SubnetMask)
	return nil
}

func CalculateSubnetIPv4(ipAddress string, subnetMask string) string {

	ipv4IP := net.ParseIP(ipAddress).To4()
	subnetMaskIPAddr := net.ParseIP(subnetMask).To4()
	subnetMaskIP := net.IPv4Mask(subnetMaskIPAddr[0],
		subnetMaskIPAddr[1],
		subnetMaskIPAddr[2],
		subnetMaskIPAddr[3])

	return ipv4IP.Mask(subnetMaskIP).String()
}

func GetActiveGateway(outDefaultGatewayStr *string) error {

	// get active network interface
	cmdActiveInterface := "route get google.com | grep gateway"
	cmd := exec.Command("bash", "-c", cmdActiveInterface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	outputStr := string(output)
	outputStr = strings.TrimLeft(outputStr, " \t")
	outputStr = strings.TrimRight(outputStr, " \t\n")

	// parse default gateway interface
	if false == strings.Contains(outputStr, "gateway") { // check if its mac address
		return errors.New("could not figure out default gateway")
	}

	//"gateway: 192.168.1.1"
	tmp := strings.SplitN(outputStr, " ", 2)
	*outDefaultGatewayStr = tmp[1]

	return nil
}

func GetActiveInetInterface(outActiveInterfaceStr *string) error {

	// get active network interface
	cmdActiveInterface := "route get google.com | grep interface"
	cmd := exec.Command("bash", "-c", cmdActiveInterface)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	outputStr := string(output)
	outputStr = strings.TrimLeft(outputStr, " \t")
	outputStr = strings.TrimRight(outputStr, " \t\n")

	// parse active interface
	if false == strings.Contains(outputStr, "interface") { // check if its mac address
		return errors.New("could not figure out active interface")
	}

	//"interface: en0"
	tmp := strings.SplitN(outputStr, " ", 2)
	*outActiveInterfaceStr = tmp[1]

	return nil
}

func ParseInterfaceDetails(dest *types.SysInfoVars, s string) {
	a := strings.SplitN(s, "\n", 25)
	currentIf := ""
	for _, line := range a {
		trimmed := strings.TrimLeft(line, " \t")
		if len(trimmed) == 0 {
			continue
		}
		if line[0] == trimmed[0] {
			// interface line
			// lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
			// en0: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
			tmp := strings.SplitN(line, ":", 3)
			ifname := strings.TrimSpace(tmp[0])

			// ignore loopback
			if ifname == "lo0" {
				currentIf = ""
				continue
			}

			// ignore links down
			if false == strings.Contains(tmp[1], "UP") {
				currentIf = ""
				continue
			}

			currentIf = ifname
			dest.Netif = ifname

		} else if currentIf != "" {
			// detail line
			/*
				en0: flags=8963<UP,BROADCAST,SMART,RUNNING,PROMISC,SIMPLEX,MULTICAST> mtu 1500
						options=6463<RXCSUM,TXCSUM,TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
						ether 14:7d:da:8b:88:1c
						inet6 fe80::8be:1559:8e4b:db40%en0 prefixlen 64 secured scopeid 0xa
						inet 192.168.1.54 netmask 0xffffff00 broadcast 192.168.1.255
						nd6 options=201<PERFORMNUD,DAD>
						media: autoselect
						status: active
			*/
			if strings.Contains(trimmed, "ether") { // check if its mac address

				//ether ac:de:48:00:11:22
				tmp := strings.SplitN(trimmed, " ", 3)
				dest.Macaddr = tmp[1]
			} else if strings.Contains(trimmed, "fe80::") { // check if its link local Ipv6 address

				// inet6 fe80::aede:48ff:fe00:1122%en6 prefixlen 64 scopeid 0x8
				tmp := strings.SplitN(trimmed, " ", 3)
				dest.LlIpaddr6 = tmp[1]
			} else if strings.HasPrefix(trimmed, "inet6") {

				// inet6 fe80::2705:2628:3cd2:1124/64 scope link noprefixroute
				tmp := strings.SplitN(trimmed, " ", 3)
				tmp = strings.SplitN(tmp[1], "/", 2)
				dest.Ipaddr6 = tmp[0]
			} else if strings.HasPrefix(trimmed, "inet") {

				// inet 192.168.1.54 netmask 0xffffff00 broadcast 192.168.1.255
				tmp := strings.SplitN(trimmed, " ", 10)
				dest.Ipaddr4 = tmp[1]
				if val, ok := gSubnetMaskMappings[tmp[3]]; ok {
					dest.SubnetMask = val
				}
			}
		}
	}
}
