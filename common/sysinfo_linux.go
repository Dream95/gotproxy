//go:build linux

package common

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// SystemInfo returns kernel uname fields and OS release name when available.
func SystemInfo() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return fmt.Sprintf("uname failed: %v", err)
	}

	sysname := unix.ByteSliceToString(u.Sysname[:])
	release := unix.ByteSliceToString(u.Release[:])
	version := unix.ByteSliceToString(u.Version[:])
	machine := unix.ByteSliceToString(u.Machine[:])

	info := fmt.Sprintf("%s %s %s %s", sysname, release, version, machine)
	if pretty := osReleasePrettyName(); pretty != "" {
		return pretty + "; " + info
	}
	return info
}

func osReleasePrettyName() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if bytes.HasPrefix(line, []byte("PRETTY_NAME=")) {
			val := string(line[len("PRETTY_NAME="):])
			return strings.Trim(val, "\"")
		}
	}
	return ""
}
