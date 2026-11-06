package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ChronyStatus holds the parsed output of `chronyc tracking`.
type ChronyStatus struct {
	Running         bool   `json:"running"`
	Synced          bool   `json:"synced"`
	ReferenceID     string `json:"reference_id"`
	RefName         string `json:"ref_name"`
	Stratum         int    `json:"stratum"`
	SystemTimeError string `json:"system_time_error"`
	LastOffset      string `json:"last_offset"`
	RMSOffset       string `json:"rms_offset"`
	UpdateInterval  string `json:"update_interval"`
	LeapStatus      string `json:"leap_status"`
}

// IsChronyRunning returns true if the chronyd service is active.
func IsChronyRunning() bool {
	out, err := exec.Command("systemctl", "is-active", "chronyd").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "active"
}

// GetChronyStatus runs `chronyc tracking` and parses the result.
func GetChronyStatus() (ChronyStatus, error) {
	s := ChronyStatus{Running: IsChronyRunning()}
	if !s.Running {
		return s, nil
	}
	out, err := exec.Command("chronyc", "tracking").Output()
	if err != nil {
		return s, fmt.Errorf("chronyc tracking: %w", err)
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		kv := strings.SplitN(scanner.Text(), ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		val := strings.TrimSpace(kv[1])
		switch key {
		case "Reference ID":
			// "A29FC801 (time.apple.com)"
			if i := strings.Index(val, "("); i != -1 {
				s.ReferenceID = strings.TrimSpace(val[:i])
				s.RefName = strings.Trim(val[i:], "()")
			} else {
				s.ReferenceID = val
			}
		case "Stratum":
			fmt.Sscanf(val, "%d", &s.Stratum)
		case "System time":
			s.SystemTimeError = val
		case "Last offset":
			s.LastOffset = val
		case "RMS offset":
			s.RMSOffset = val
		case "Update interval":
			s.UpdateInterval = val
		case "Leap status":
			s.LeapStatus = val
			s.Synced = val == "Normal"
		}
	}
	return s, nil
}

const chronyConf = "/etc/chrony/chrony.conf"

// GetNTPServers returns the server/pool lines from chrony.conf.
func GetNTPServers() ([]string, error) {
	data, err := os.ReadFile(chronyConf)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", chronyConf, err)
	}
	var servers []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "server ") || strings.HasPrefix(line, "pool ") {
			servers = append(servers, line)
		}
	}
	return servers, nil
}

// SetNTPServers replaces the server/pool lines in chrony.conf and restarts chronyd.
func SetNTPServers(servers []string) error {
	data, err := os.ReadFile(chronyConf)
	if err != nil {
		return fmt.Errorf("read %s: %w", chronyConf, err)
	}
	// Rebuild config without old server/pool lines.
	var kept []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "server ") || strings.HasPrefix(t, "pool ") {
			continue
		}
		kept = append(kept, line)
	}
	newCfg := strings.Join(servers, "\n") + "\n" + strings.Join(kept, "\n") + "\n"

	teeCmd := exec.Command("sudo", "tee", chronyConf)
	teeCmd.Stdin = strings.NewReader(newCfg)
	if out, err := teeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write %s: %s: %w", chronyConf, strings.TrimSpace(string(out)), err)
	}
	if out, err := exec.Command("sudo", "systemctl", "restart", "chronyd").CombinedOutput(); err != nil {
		return fmt.Errorf("restart chronyd: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}
