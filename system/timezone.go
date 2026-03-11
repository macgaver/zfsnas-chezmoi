package system

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// GetTimezone returns the currently configured system timezone (e.g. "America/New_York").
func GetTimezone() string {
	// Prefer /etc/timezone (Debian/Ubuntu standard).
	if data, err := os.ReadFile("/etc/timezone"); err == nil {
		tz := strings.TrimSpace(string(data))
		if tz != "" {
			return tz
		}
	}
	// Fall back to timedatectl.
	out, err := exec.Command("timedatectl", "show", "--property=Timezone", "--value").Output()
	if err == nil {
		tz := strings.TrimSpace(string(out))
		if tz != "" {
			return tz
		}
	}
	return "UTC"
}

// SetTimezone sets the system timezone using timedatectl.
func SetTimezone(tz string) error {
	out, err := exec.Command("sudo", "timedatectl", "set-timezone", tz).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ListTimezones returns all timezone names known to timedatectl.
func ListTimezones() ([]string, error) {
	out, err := exec.Command("timedatectl", "list-timezones").Output()
	if err != nil {
		return nil, err
	}
	var tzs []string
	for _, line := range strings.Split(string(out), "\n") {
		if t := strings.TrimSpace(line); t != "" {
			tzs = append(tzs, t)
		}
	}
	return tzs, nil
}
