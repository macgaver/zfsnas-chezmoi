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
	{Name: "gdisk", Description: "GPT disk partitioning utilities (sgdisk)"},
	{Name: "rsync", Description: "File Browser copy/move progress, and external storage sync"},
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

// sudoCheck describes one entry that must be present in the hardened sudoers.
// Binary is resolved via LookPath to get the full path; Match is the substring
// that must appear in "sudo -l" output.  When a command is a specific subcommand
// (e.g. "zpool get") set Binary to the executable and Match to the subcommand
// suffix — the checker will look for "<fullpath> <match>" in the output.
// IfBinary, when set, skips the check if that binary is not installed — used to
// gate optional-feature entries (e.g. NUT, MinIO, iSCSI) that are irrelevant on
// systems that have not enabled the feature.
type sudoCheck struct {
	Binary         string // executable name passed to exec.LookPath
	Match          string // extra suffix after the binary path (empty = binary path alone)
	Name           string // display name reported in MissingCommands
	IfBinary       string // skip this check if the named binary is absent from PATH
	IfExperimental bool   // skip this check when ZNAS is not started with --experimental
	// — required for entries whose Cmnd_Alias is in experimentalSudoersAliases
	// (sudoers_hardening.go). Without this gate, installing the underlying
	// binary (e.g. `sanoid` pulls in syncoid as a transitive dep) would
	// produce a "missing sudo entry" warning that the user can't fix from
	// the sudo editor — the alias isn't part of the template stripped for
	// non-experimental hosts. (v6.5.30 fix.)
}

// requiredSudoChecks lists every entry covered by the hardened sudoers template
// in SECURITY.md. The check flags any entry whose expected string is absent from
// the running user's "sudo -l -n" output.
var requiredSudoChecks = []sudoCheck{
	// ── ZFS pool & dataset management ────────────────────────────────────────
	{Binary: "zpool", Match: "*", Name: "zpool *"},
	{Binary: "zfs", Match: "*", Name: "zfs *"},
	// ── Hardware monitoring ──────────────────────────────────────────────────
	{Binary: "smartctl", Match: "*", Name: "smartctl *"},
	{Binary: "nvme", Name: "nvme"},
	// ── Kernel / packages / service management ───────────────────────────────
	{Binary: "modprobe", Name: "modprobe"},
	{Binary: "apt-get", Match: "*", Name: "apt-get *"},
	{Binary: "systemctl", Name: "systemctl"},
	// ── Config file write paths (tee) ────────────────────────────────────────
	{Binary: "cat", Match: "/etc/sudoers.d/zfsnas", Name: "cat /etc/sudoers.d/zfsnas"},
	{Binary: "tee", Match: "/etc/samba/smb.conf", Name: "tee /etc/samba/smb.conf"},
	{Binary: "tee", Match: "/etc/exports", Name: "tee /etc/exports"},
	{Binary: "tee", Match: "/etc/systemd/system/zfsnas.service", Name: "tee /etc/systemd/system/zfsnas.service"},
	{Binary: "tee", Match: "/etc/modprobe.d/zfs.conf", Name: "tee /etc/modprobe.d/zfs.conf"},
	{Binary: "tee", Match: "/sys/module/zfs/parameters/zfs_arc_max", Name: "tee /sys/module/zfs/parameters/zfs_arc_max"},
	{Binary: "tee", Match: "/sys/module/zfs/parameters/zfs_arc_min", Name: "tee /sys/module/zfs/parameters/zfs_arc_min"},
	// ── NUT (UPS) — only checked when nut packages are installed ─────────────
	{Binary: "nut-scanner", Name: "nut-scanner", IfBinary: "upsc"},
	{Binary: "tee", Match: "/etc/nut/nut.conf", Name: "tee /etc/nut/nut.conf", IfBinary: "upsc"},
	{Binary: "tee", Match: "/etc/nut/ups.conf", Name: "tee /etc/nut/ups.conf", IfBinary: "upsc"},
	{Binary: "tee", Match: "/etc/nut/upsd.conf", Name: "tee /etc/nut/upsd.conf", IfBinary: "upsc"},
	{Binary: "tee", Match: "/etc/nut/upsd.users", Name: "tee /etc/nut/upsd.users", IfBinary: "upsc"},
	{Binary: "tee", Match: "/etc/nut/upsmon.conf", Name: "tee /etc/nut/upsmon.conf", IfBinary: "upsc"},
	// ── MinIO (S3) — only checked when minio is installed ────────────────────
	{Binary: "tee", Match: "/etc/systemd/system/minio.service", Name: "tee /etc/systemd/system/minio.service", IfBinary: "minio"},
	{Binary: "tee", Match: "/etc/default/minio", Name: "tee /etc/default/minio", IfBinary: "minio"},
	// ── iSCSI — only checked when targetcli-fb is installed ──────────────────
	{Binary: "targetcli", Name: "targetcli"},
	// ── User / Samba ─────────────────────────────────────────────────────────
	{Binary: "useradd", Name: "useradd"},
	{Binary: "usermod", Name: "usermod"},
	{Binary: "userdel", Match: "-f", Name: "userdel -f"},
	{Binary: "groupadd", Name: "groupadd"},
	{Binary: "groupdel", Name: "groupdel"},
	{Binary: "gpasswd", Name: "gpasswd"},
	{Binary: "smbpasswd", Match: "*", Name: "smbpasswd *"},
	{Binary: "smbstatus", Match: "-S", Name: "smbstatus -S"},
	{Binary: "chgrp", Match: "sambashare", Name: "chgrp sambashare"},
	{Binary: "chmod", Match: "0770", Name: "chmod 0770"},
	// ── NFS ──────────────────────────────────────────────────────────────────
	{Binary: "exportfs", Match: "-ra", Name: "exportfs -ra"},
	// ── System ───────────────────────────────────────────────────────────────
	{Binary: "timedatectl", Name: "timedatectl"},
	{Binary: "shutdown", Match: "*", Name: "shutdown *"},
	// ── Folder usage scanning & recycle bin cleanup ──────────────────────────
	{Binary: "du", Name: "du"},
	{Binary: "find", Name: "find"},
	// ── Disk preparation & wipe ──────────────────────────────────────────────
	{Binary: "wipefs", Match: "-a", Name: "wipefs -a"},
	{Binary: "sgdisk", Match: "--zap-all", Name: "sgdisk --zap-all"},
	{Binary: "dd", Name: "dd"},
	{Binary: "partprobe", Name: "partprobe"},
	{Binary: "udevadm", Match: "settle", Name: "udevadm settle"},
	{Binary: "blkid", Match: "-o export", Name: "blkid -o export"},
	// ── UPS udev rules reload — only checked when NUT is installed ───────────
	{Binary: "udevadm", Match: "control", Name: "udevadm control", IfBinary: "upsc"},
	// ── Disk Power Management (hdparm) — only checked when hdparm is installed
	{Binary: "hdparm", Match: "*", Name: "hdparm *", IfBinary: "hdparm"},
	{Binary: "tee", Match: "/etc/hdparm.conf", Name: "tee /etc/hdparm.conf", IfBinary: "hdparm"},
	// ── ZFS Replication (syncoid) — only checked when syncoid is installed
	// AND ZNAS is running with --experimental. syncoid is part of the
	// `sanoid` package, which can be a transitive dep on Ubuntu 26.04
	// (and gets pulled in by completely unrelated workloads). Without
	// IfExperimental the user would see a "syncoid * missing" warning
	// they can't dismiss — the sudo editor's template strips
	// ZFSNAS_SYNCOID on non-experimental hosts so the line never appears
	// in the editor for them to "Apply".
	{Binary: "syncoid", Match: "*", Name: "syncoid *", IfBinary: "syncoid", IfExperimental: true},
	// ── System/Platform Power Management ─────────────────────────────────────
	{Binary: "tee", Match: "/etc/rc.local", Name: "tee /etc/rc.local"},
	{Binary: "chmod", Match: "+x /etc/rc.local", Name: "chmod +x /etc/rc.local"},
	{Binary: "systemctl", Match: "enable rc-local", Name: "systemctl enable rc-local"},
	{Binary: "systemctl", Match: "start rc-local", Name: "systemctl start rc-local"},
	// System Power Management uses runtime-determined paths (per-CPU scaling
	// governor, /sys/module/pcie_aspm/..., per-USB-device autosuspend, /etc/rc.local).
	// sudo-rs does not allow wildcards in non-trailing argument positions, so the
	// sudoers template grants `/usr/bin/tee *` in ZFSNAS_SYSPOWER. The wildcard
	// fallback in the loop below treats `tee *` as covering this check.
	{Binary: "tee", Match: "*", Name: "tee * (System Power Management)"},
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

	// "sudo -l" output is unreliable for substring matching across sudo versions:
	//   - Classic sudo on some configurations leaves Cmnd_Alias names unexpanded
	//     (the output literally contains "ZFSNAS_ZFS" instead of the command paths).
	//   - sudo-rs (default on Ubuntu 26.04+) collapses "cmd *" entries to bare
	//     "cmd" in its output, so substring checks for "/usr/sbin/zpool *" miss.
	// In both cases the authoritative source is the sudoers file itself; prefer it
	// whenever it is readable.
	if content, _ := GetCurrentSudoersContent(); content != "" {
		sudoList = content
	}

	// Hardened configuration — check each required entry.
	var missing []string
	for _, chk := range requiredSudoChecks {
		// Skip virtualization-only entries unless Incus is actually installed.
		// The sudoers template removes their alias block until the feature is
		// enabled, so warning about a missing line the user can't add from the
		// editor is pure noise. As of v6.6.26 the feature is no longer gated
		// behind --experimental, so installation of Incus is the only signal
		// that matters (v6.5.30/v6.6.9 also keyed on the now-removed flag).
		if chk.IfExperimental && !IncusInstalled() {
			continue
		}
		// Skip optional-feature entries when the feature is not installed.
		if chk.IfBinary != "" {
			if _, err := exec.LookPath(chk.IfBinary); err != nil {
				continue
			}
		}
		path, err := exec.LookPath(chk.Binary)
		if err != nil {
			continue // binary not installed on this system — not a sudo gap
		}
		// Primary needle uses the resolved path; fallback uses "/binary" so that
		// a path mismatch between LookPath and the sudoers file (e.g. /usr/sbin
		// vs /usr/bin) does not produce a false positive.
		needle := path
		altNeedle := "/" + chk.Binary
		if chk.Match != "" {
			needle = path + " " + chk.Match
			altNeedle = "/" + chk.Binary + " " + chk.Match
		}
		// A wildcard sudoers entry (binary *) covers any specific subcommand match.
		wildcardNeedle := path + " *"
		wildcardAlt := "/" + chk.Binary + " *"
		if !strings.Contains(sudoList, needle) && !strings.Contains(sudoList, altNeedle) &&
			!strings.Contains(sudoList, wildcardNeedle) && !strings.Contains(sudoList, wildcardAlt) {
			missing = append(missing, chk.Name)
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
