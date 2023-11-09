// +build linux darwin

package main

import (
//	"fmt"
//	"os"
//	"os/user"
//	"strconv"
//	"syscall"

	types "github.com/secureworks/atomic-harness/pkg/types"
)

func ManagePrivilege(atomicTest *types.AtomicTest, runSpec *types.RunSpec) {
/*
	usr,err := user.Current()
	if err != nil {
		fmt.Println("ERROR: unable to determine current user", err)
		return
	}
	if usr.Uid == "0" {
		// we are running as root
		if atomicTest.Executor.ElevationRequired {
			fmt.Println("test requires Elevated privilege, remaining as root")
			return
		}

		// drop to user

		username := runSpec.Username
		if len(username) == 0 {
			username = os.Getenv("SUDO_USER")
		}
		if len(username) == 0 {
			fmt.Println("Unable to determine user. Using nobody")
			username = "nobody"
		}
		if username == "root" {
			username = "nobody"
		}
		usr, err = user.Lookup(username)
		if err != nil {
			fmt.Println("unable to get uid for user",username)
			return
		}
		uid,err := strconv.Atoi(usr.Uid)
		if err != nil {
			fmt.Println("uid parse failed",usr.Uid, err)
			return
		}
		err = syscall.Setuid(uid)
		if err != nil {
			fmt.Println("ERROR: Setuid Failed",uid,username, err)
		}
		fmt.Println("Dropped privilege to user",username)

		// move to user's home
		if username == "nobody" {
			os.Setenv("HOME","/tmp/")
			os.Chdir("/tmp/")
		} else {
			os.Setenv("HOME","/home/" + username)
			os.Chdir("/home/" + username)
		}

		return
	}

	// we are normal user
	if atomicTest.Executor.ElevationRequired {
		fmt.Println("WARN: test requires Elevated privilege, but running as user",usr)
		return
	}
*/
}
