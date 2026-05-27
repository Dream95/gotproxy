package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

const taskCommLen = 16

func commMatchesCommand(comm, command string) bool {
	var commArr, cmdArr [taskCommLen]byte
	copy(cmdArr[:], []byte(command))
	copy(commArr[:], []byte(comm))
	if commArr == cmdArr {
		return true
	}
	// Match git-remote-https / git-remote-http when --cmd git.
	if command == "git" && len(comm) >= 3 && comm[:3] == "git" &&
		(len(comm) == 3 || comm[3] == '-') {
		return true
	}
	return false
}

// seedTrackedPIDs adds PIDs whose comm matches command into filter_tracked_map.
func seedTrackedPIDs(trackedMap *ebpf.Map, command string, excludePid uint64) (int, error) {
	if trackedMap == nil || command == "" {
		return 0, nil
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, fmt.Errorf("read /proc: %w", err)
	}

	var seeded int
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid64, err := strconv.ParseUint(ent.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := uint32(pid64)
		if uint64(pid) == excludePid {
			continue
		}

		commBytes, err := os.ReadFile(filepath.Join("/proc", ent.Name(), "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(commBytes))
		if !commMatchesCommand(comm, command) {
			continue
		}

		if err := trackedMap.Update(pid, int8(1), ebpf.UpdateAny); err != nil {
			return seeded, fmt.Errorf("update filter_tracked_map pid=%d: %w", pid, err)
		}
		seeded++
	}
	return seeded, nil
}

func seedTrackedPIDsOrLog(trackedMap *ebpf.Map, command string, excludePid uint64) {
	n, err := seedTrackedPIDs(trackedMap, command, excludePid)
	if err != nil {
		log.Printf("seed tracked PIDs for --cmd %q: %v (seeded %d)", command, err, n)
		return
	}
	if n > 0 {
		log.Printf("seeded %d tracked PID(s) for --cmd %q", n, command)
	}
}
