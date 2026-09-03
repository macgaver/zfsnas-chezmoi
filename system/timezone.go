package system

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
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

var (
	zoneinfoDir   = "/usr/share/zoneinfo"
	localtimePath = "/etc/localtime"
	timezonePath  = "/etc/timezone"
)

// setTimezoneApplianceMode writes THROUGH the bind-mounted /etc/localtime
// (timedatectl's symlink swap gets EBUSY on a bind mount) so the change
// lands in the persist store, and records the zone name in /etc/timezone.
func setTimezoneApplianceMode(tz string) error {
	if tz == "" || strings.Contains(tz, "..") || strings.ContainsAny(tz, " \t\n\\") {
		return fmt.Errorf("invalid timezone %q", tz)
	}
	b, err := os.ReadFile(filepath.Join(zoneinfoDir, tz))
	if err != nil {
		return fmt.Errorf("unknown timezone %q: %w", tz, err)
	}
	f, err := os.OpenFile(localtimePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.WriteFile(timezonePath, []byte(tz+"\n"), 0644)
}

// SetTimezone sets the system timezone using timedatectl.
func SetTimezone(tz string) error {
	if ApplianceMode() {
		return setTimezoneApplianceMode(tz)
	}
	out, err := exec.Command("sudo", "timedatectl", "set-timezone", tz).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ListTimezones returns all timezone names available on the system.
// It tries timedatectl first, then falls back to walking /usr/share/zoneinfo/.
func ListTimezones() ([]string, error) {
	if out, err := exec.Command("timedatectl", "list-timezones").Output(); err == nil {
		var tzs []string
		for _, line := range strings.Split(string(out), "\n") {
			if t := strings.TrimSpace(line); t != "" {
				tzs = append(tzs, t)
			}
		}
		if len(tzs) > 0 {
			return tzs, nil
		}
	}
	return listTimezonesFromZoneinfo("/usr/share/zoneinfo")
}

// listTimezonesFromZoneinfo walks the zoneinfo directory and returns timezone names.
func listTimezonesFromZoneinfo(root string) ([]string, error) {
	var tzs []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		// Skip non-timezone files (posix/, right/ sub-dirs, leap-seconds.list, etc.)
		rel := strings.TrimPrefix(path, root+"/")
		if strings.HasPrefix(rel, "posix/") || strings.HasPrefix(rel, "right/") ||
			strings.HasPrefix(rel, "+VERSION") || strings.HasSuffix(rel, ".list") ||
			strings.HasSuffix(rel, ".tab") || strings.HasSuffix(rel, ".zi") ||
			!strings.Contains(rel, "/") {
			return nil
		}
		tzs = append(tzs, rel)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("zoneinfo not found: %w", err)
	}
	sort.Strings(tzs)
	return tzs, nil
}
