package system

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Package describes a required system package and its install status.
type Package struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
	Version     string `json:"version,omitempty"`
}

// RequiredPackages lists every package the application needs.
var RequiredPackages = []Package{
	{Name: "zfsutils-linux", Description: "ZFS pool and dataset management"},
	{Name: "samba", Description: "Windows file sharing (SMB/CIFS)"},
	{Name: "nfs-kernel-server", Description: "Linux NFS server (NFS exports)"},
	{Name: "smartmontools", Description: "SSD/HDD health monitoring (smartctl)"},
	{Name: "nvme-cli", Description: "NVMe drive health monitoring"},
	{Name: "util-linux", Description: "Disk utilities (lsblk)"},
}

// CheckPackages returns RequiredPackages with Installed and Version populated.
func CheckPackages() []Package {
	result := make([]Package, len(RequiredPackages))
	copy(result, RequiredPackages)
	for i := range result {
		result[i].Installed, result[i].Version = packageInfo(result[i].Name)
	}
	return result
}

// MissingPackages returns the names of packages that are not installed.
func MissingPackages(pkgs []Package) []string {
	var missing []string
	for _, p := range pkgs {
		if !p.Installed {
			missing = append(missing, p.Name)
		}
	}
	return missing
}

// packageInfo checks whether a Debian/Ubuntu package is fully installed and returns its version.
func packageInfo(pkg string) (installed bool, version string) {
	out, err := exec.Command("dpkg", "-s", pkg).Output()
	if err != nil {
		return false, ""
	}
	s := string(out)
	if !strings.Contains(s, "Status: install ok installed") {
		return false, ""
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "Version:") {
			version = strings.TrimSpace(strings.TrimPrefix(line, "Version:"))
			break
		}
	}
	return true, version
}

// ZfsutilsBelowMinVersion returns true if the version string is below major.minor threshold.
// version looks like "2.1.5-1ubuntu6~22.04.1" — only the leading major.minor is compared.
func ZfsutilsBelowMinVersion(version string, minMajor, minMinor int) bool {
	plain := strings.SplitN(version, "-", 2)[0]
	parts := strings.Split(plain, ".")
	if len(parts) < 2 {
		return false
	}
	major, err1 := strconv.Atoi(parts[0])
	minor, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	if major != minMajor {
		return major < minMajor
	}
	return minor < minMinor
}

// SudoStatus describes the sudo access mode the process has.
type SudoStatus struct {
	// Type is one of: "root" | "all" | "hardened" | "none"
	//   root     — process UID is 0 (full access, but not recommended)
	//   all      — user has NOPASSWD: ALL in sudoers (green, ideal)
	//   hardened — specific commands only; MissingCommands lists gaps
	//   none     — no sudo access detected
	Type            string   `json:"type"`
	MissingCommands []string `json:"missing_commands"`
}

// requiredSudoCmds lists every command covered by the hardened sudoers template
// in SECURITY.md. The check flags any command from this list that is absent
// from the running user's sudo -l output.
var requiredSudoCmds = []string{
	// ZFS
	"zpool", "zfs",
	// Hardware monitoring
	"smartctl", "nvme",
	// Kernel / packages / service management
	"modprobe", "apt-get", "systemctl", "tee",
	// User / Samba
	"useradd", "usermod", "smbpasswd", "chmod",
	// NFS
	"exportfs",
	// System
	"timedatectl", "shutdown",
}

// CheckSudoAccess probes the effective sudo permissions of the running process.
func CheckSudoAccess() SudoStatus {
	// Running as root — all operations succeed without sudo.
	if os.Getuid() == 0 {
		return SudoStatus{Type: "root", MissingCommands: []string{}}
	}

	out, err := exec.Command("sudo", "-l", "-n").Output()
	if err != nil {
		return SudoStatus{Type: "none", MissingCommands: []string{}}
	}
	sudoList := string(out)

	// Blanket NOPASSWD: ALL — every command allowed.
	if strings.Contains(sudoList, "NOPASSWD: ALL") || strings.Contains(sudoList, "NOPASSWD:ALL") {
		return SudoStatus{Type: "all", MissingCommands: []string{}}
	}

	// Hardened configuration — check each required command.
	var missing []string
	for _, cmd := range requiredSudoCmds {
		path, err := exec.LookPath(cmd)
		if err != nil {
			continue // not installed on this system, not a sudo gap
		}
		if !strings.Contains(sudoList, path) && !strings.Contains(sudoList, "/"+cmd) {
			missing = append(missing, cmd)
		}
	}
	if missing == nil {
		missing = []string{}
	}
	return SudoStatus{Type: "hardened", MissingCommands: missing}
}

// ZfsModuleLoaded returns true if the zfs kernel module is currently loaded.
// It checks /proc/modules which is available on all Linux kernels.
func ZfsModuleLoaded() bool {
	out, err := exec.Command("grep", "-qw", "zfs", "/proc/modules").Output()
	_ = out
	return err == nil
}

// LoadZfsModule attempts to load the zfs kernel module via modprobe.
// Returns the combined output and any error.
func LoadZfsModule() (string, error) {
	out, err := exec.Command("sudo", "modprobe", "zfs").CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// IsServiceInstalled returns true if the zfsnas systemd unit exists and is enabled.
func IsServiceInstalled() bool {
	out, err := exec.Command("systemctl", "is-enabled", "zfsnas").Output()
	if err != nil {
		return false
	}
	status := strings.TrimSpace(string(out))
	return status == "enabled" || status == "static"
}
