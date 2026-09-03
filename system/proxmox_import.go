package system

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ProxmoxSSHConn holds credentials for a remote Proxmox server.
type ProxmoxSSHConn struct {
	Host     string
	User     string
	Password string
}

// ProxmoxVMNIC describes one NIC on a Proxmox VM.
type ProxmoxVMNIC struct {
	Device string `json:"device"` // "net0", "net1"
	Driver string `json:"driver"` // "virtio", "e1000"
	MAC    string `json:"mac"`    // "AA:BB:CC:DD:EE:FF"
}

// ProxmoxVMTPM describes a tpmstate0 entry on a Proxmox VM.
//
// Proxmox provisions a 4 MiB volume per TPM-equipped VM and runs swtpm
// with `--tpmstate backend-uri=file://<path>` against it, so the volume's
// raw bytes ARE the swtpm state (single-file backend, not a filesystem).
// Incus uses swtpm's directory backend with a `tpm2-00.permall` file; the
// inner blob format is shared, which is why a drop-in import is worth a
// best-effort attempt.
type ProxmoxVMTPM struct {
	StorageVol string `json:"storage_vol"` // "<storage>:<volume>"
	Version    string `json:"version"`     // "v2.0" | "v1.2"
	SizeBytes  int64  `json:"size_bytes"`
}

// ProxmoxVMDisk describes one disk on a Proxmox VM.
type ProxmoxVMDisk struct {
	Device     string `json:"device"`      // "scsi0", "ide0"
	StorageVol string `json:"storage_vol"` // "local-lvm:vm-100-disk-0"
	SizeBytes  int64  `json:"size_bytes"`
	SizeStr    string `json:"size_str"` // "32G"
}

// ProxmoxVM describes a VM found on a live Proxmox host.
type ProxmoxVM struct {
	VMID       int             `json:"vmid"`
	Name       string          `json:"name"`
	Status     string          `json:"status"` // "running", "stopped", "paused"
	CPU        int             `json:"cpu"`
	MemoryMB   int             `json:"memory_mb"`
	NICs       []ProxmoxVMNIC  `json:"nics"`
	Disks      []ProxmoxVMDisk `json:"disks"`
	IsUEFI     bool            `json:"is_uefi"`            // true when bios: ovmf
	BootDevice string          `json:"boot_device"`        // first device in boot: order=
	EFIDisk    *ProxmoxVMDisk  `json:"efi_disk,omitempty"` // efidisk0 entry (OVMF vars)
	SMBIOS1    *LXDSMBIOSType1 `json:"smbios1,omitempty"`  // parsed from "smbios1:" qm config line
	TPM        *ProxmoxVMTPM   `json:"tpm,omitempty"`      // parsed from "tpmstate0:" qm config line
	Error      string          `json:"error,omitempty"`
}

// ProxmoxImportRequest is the full import request body from the frontend.
type ProxmoxImportRequest struct {
	Host        string      `json:"host"`
	User        string      `json:"user"`
	Password    string      `json:"password"`
	VMs         []ProxmoxVM `json:"vms"`
	LocalBridge string      `json:"local_bridge"`
	StoragePool string      `json:"storage_pool"`
	StartAfter  bool        `json:"start_after"`
}

// SshpassAvailable returns true if sshpass is installed.
func SshpassAvailable() bool {
	_, err := exec.LookPath("sshpass")
	return err == nil
}

// QemuImgAvailable returns true if qemu-img is installed.
func QemuImgAvailable() bool {
	_, err := exec.LookPath("qemu-img")
	return err == nil
}

// NtfsfixAvailable returns true if ntfsfix is installed (ntfs-3g package).
// Used by fixUEFIWindows() to clear the NTFS dirty bit on imported Windows disks.
func NtfsfixAvailable() bool {
	_, err := exec.LookPath("ntfsfix")
	return err == nil
}

// HivexAvailable returns true if python3-hivex bindings are loadable. Used by
// fixUEFIWindows() to patch BCD on imported Windows ESPs (remove BootMgr's
// resumeobject + set bootstatuspolicy=IgnoreAllFailures).
func HivexAvailable() bool {
	if _, err := exec.LookPath("python3"); err != nil {
		return false
	}
	return exec.Command("python3", "-c", "import hivex").Run() == nil
}

// sudoMkdirTemp creates a uniquely-named temporary directory under base using
// sudo (for pool roots owned by root), then chowns it to the current user so
// the portal process can write to it without further privilege.
func sudoMkdirTemp(base string) (string, error) {
	path := fmt.Sprintf("%s/.znas-proxmox-%d", base, time.Now().UnixNano())

	whoamiOut, _ := exec.Command("whoami").Output()
	currentUser := strings.TrimSpace(string(whoamiOut))
	if currentUser == "" {
		currentUser = "zfsnas"
	}

	if out, err := exec.Command("sudo", "mkdir", "-p", path).CombinedOutput(); err != nil {
		return "", fmt.Errorf("sudo mkdir: %s: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "chown", currentUser, path).CombinedOutput(); err != nil {
		exec.Command("sudo", "rm", "-rf", path).Run() //nolint:errcheck
		return "", fmt.Errorf("sudo chown: %s: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "chmod", "700", path).CombinedOutput(); err != nil {
		exec.Command("sudo", "rm", "-rf", path).Run() //nolint:errcheck
		return "", fmt.Errorf("sudo chmod: %s: %s", err, strings.TrimSpace(string(out)))
	}
	return path, nil
}

// diskFreeBytes returns the number of available bytes on the filesystem
// containing the given path.
func diskFreeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil
}

// importTempDir returns the best directory to hold large import temp files for
// the given LXD storage pool. It tries in order:
//  1. Mounted ZFS ancestor of the dataset backing the LXD pool (walks up the
//     hierarchy so a "legacy"-mounted dataset finds its mounted parent pool).
//  2. Well-known LXD snap/apt storage-pools directories.
//  3. /var/tmp as a last resort.
func importTempDir(lxdPoolName string) string {
	// tryZFS returns the mountpoint of a ZFS dataset if it is directly mounted
	// (i.e. mountpoint is a real path, not "none"/"legacy"/"-").
	tryZFS := func(dataset string) string {
		out, err := exec.Command("zfs", "get", "-H", "-o", "value", "mountpoint", dataset).Output()
		if err != nil {
			return ""
		}
		mp := strings.TrimSpace(string(out))
		if mp == "" || mp == "none" || mp == "-" || mp == "legacy" || mp == "inherit" {
			return ""
		}
		if _, statErr := os.Stat(mp); statErr != nil {
			return ""
		}
		return mp
	}

	// tryZFSWithParents walks up the dataset path (e.g. "tank/lxd-base" →
	// "tank") until it finds an ancestor with a real mountpoint.
	tryZFSWithParents := func(dataset string) string {
		parts := strings.Split(dataset, "/")
		for i := len(parts); i >= 1; i-- {
			if mp := tryZFS(strings.Join(parts[:i], "/")); mp != "" {
				return mp
			}
		}
		return ""
	}

	// 1. Try by LXD pool name directly (covers cases where name == dataset).
	if mp := tryZFSWithParents(lxdPoolName); mp != "" {
		return mp
	}

	// 2. Parse `lxc storage show` config block → get backing ZFS dataset → walk up.
	// (lxc storage show has a stable YAML format with "source:" under "config:".)
	for _, subcmd := range []string{"show", "info"} {
		out, err := exec.Command("incus", "storage", subcmd, lxdPoolName).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			kv := strings.SplitN(strings.TrimSpace(line), ":", 2)
			if len(kv) == 2 && strings.TrimSpace(kv[0]) == "source" {
				if mp := tryZFSWithParents(strings.TrimSpace(kv[1])); mp != "" {
					return mp
				}
			}
		}
	}

	// 3. Well-known Incus storage-pools directory (deb install only).
	{
		p := fmt.Sprintf("/var/lib/incus/storage-pools/%s", lxdPoolName)
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}

	// 4. Last resort.
	return "/var/tmp"
}

// runRemoteSSH executes a single command string on the remote host via sshpass+ssh.
// The password is passed only via the SSHPASS environment variable.
func runRemoteSSH(conn ProxmoxSSHConn, cmdStr string) (string, error) {
	cmd := exec.Command("sshpass", "-e", "ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=no",
		"-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=30",
		fmt.Sprintf("%s@%s", conn.User, conn.Host),
		cmdStr,
	)
	cmd.Env = append(os.Environ(), "SSHPASS="+conn.Password)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// ListProxmoxVMs SSHes to the remote Proxmox host, lists all VMs via qm list,
// then fetches each VM's config via qm config.
func ListProxmoxVMs(conn ProxmoxSSHConn) ([]ProxmoxVM, error) {
	if !SshpassAvailable() {
		return nil, fmt.Errorf("sshpass is not installed; install it from Prerequisites")
	}

	out, err := runRemoteSSH(conn, "qm list")
	if err != nil {
		return nil, fmt.Errorf("SSH connection failed: %w", err)
	}

	var vms []ProxmoxVM
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		vmid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue // skip header and non-numeric lines
		}
		vm := ProxmoxVM{
			VMID:   vmid,
			Name:   fields[1],
			Status: fields[2],
		}
		if len(fields) >= 4 {
			if mem, err := strconv.ParseFloat(fields[3], 64); err == nil {
				vm.MemoryMB = int(mem)
			}
		}

		// Fetch full config.
		cfgOut, cfgErr := runRemoteSSH(conn, fmt.Sprintf("qm config %d", vmid))
		if cfgErr != nil {
			vm.Error = cfgErr.Error()
		} else {
			parseQmConfig(cfgOut, &vm)
		}
		vms = append(vms, vm)
	}
	return vms, nil
}

// parseQmConfig parses the output of "qm config <vmid>" into a ProxmoxVM.
func parseQmConfig(raw string, vm *ProxmoxVM) {
	// efidisk entries are OVMF variable stores, not bootable disks — handle separately.
	diskDevRe := regexp.MustCompile(`^(?:scsi|ide|virtio|sata)\d+$`)
	efidiskRe := regexp.MustCompile(`^efidisk\d+$`)
	nicDevRe := regexp.MustCompile(`^net\d+$`)
	skipDevRe := regexp.MustCompile(`^(?:usb|hostpci|serial|audio|parallel|unused)\d*$`)
	tpmstateRe := regexp.MustCompile(`^tpmstate\d+$`)

	var cores, sockets int
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		if skipDevRe.MatchString(key) {
			continue
		}

		switch key {
		case "name":
			vm.Name = val
		case "memory":
			if n, err := strconv.Atoi(val); err == nil {
				vm.MemoryMB = n
			}
		case "cores":
			if n, err := strconv.Atoi(val); err == nil {
				cores = n
			}
		case "sockets":
			if n, err := strconv.Atoi(val); err == nil {
				sockets = n
			}
		case "bios":
			vm.IsUEFI = (val == "ovmf")
		case "smbios1":
			if s := parseProxmoxSMBIOS1(val); s != nil {
				vm.SMBIOS1 = s
			}
		case "boot":
			// New format: "order=scsi0;ide2"   Old format: "c" / "dc"
			for _, part := range strings.Split(val, ";") {
				part = strings.TrimSpace(part)
				if strings.HasPrefix(part, "order=") {
					devs := strings.Split(strings.TrimPrefix(part, "order="), ";")
					if len(devs) > 0 && devs[0] != "" {
						vm.BootDevice = strings.TrimSpace(devs[0])
					}
					break
				}
			}
		default:
			if efidiskRe.MatchString(key) {
				if !strings.Contains(val, "media=cdrom") && !strings.HasPrefix(val, "none") {
					storageVol := strings.SplitN(val, ",", 2)[0]
					sizeStr := proxmoxDiskSizeStr(val)
					vm.EFIDisk = &ProxmoxVMDisk{
						Device:     key,
						StorageVol: storageVol,
						SizeBytes:  proxmoxParseDiskSize(sizeStr),
						SizeStr:    sizeStr,
					}
					vm.IsUEFI = true // efidisk implies UEFI even without explicit bios: ovmf
				}
			} else if diskDevRe.MatchString(key) {
				// Skip cdrom/none entries.
				if strings.Contains(val, "media=cdrom") || strings.HasPrefix(val, "none") {
					continue
				}
				storageVol := strings.SplitN(val, ",", 2)[0]
				sizeStr := proxmoxDiskSizeStr(val)
				vm.Disks = append(vm.Disks, ProxmoxVMDisk{
					Device:     key,
					StorageVol: storageVol,
					SizeBytes:  proxmoxParseDiskSize(sizeStr),
					SizeStr:    sizeStr,
				})
			} else if tpmstateRe.MatchString(key) {
				if !strings.HasPrefix(val, "none") {
					storageVol := strings.SplitN(val, ",", 2)[0]
					sizeStr := proxmoxDiskSizeStr(val)
					vm.TPM = &ProxmoxVMTPM{
						StorageVol: storageVol,
						Version:    proxmoxParseTPMVersion(val),
						SizeBytes:  proxmoxParseDiskSize(sizeStr),
					}
				}
			} else if nicDevRe.MatchString(key) {
				driver, mac := proxmoxParseNIC(val)
				vm.NICs = append(vm.NICs, ProxmoxVMNIC{
					Device: key,
					Driver: driver,
					MAC:    mac,
				})
			}
		}
	}

	if cores < 1 {
		cores = 1
	}
	if sockets < 1 {
		sockets = 1
	}
	vm.CPU = cores * sockets

	if vm.Name == "" {
		vm.Name = fmt.Sprintf("vm-%d", vm.VMID)
	}
	if vm.MemoryMB == 0 {
		vm.MemoryMB = 512
	}

	// Ensure the Proxmox boot device is disk index 0 (root disk in LXD).
	// Without this, alphabetical parsing order (efidisk0 < scsi0) or any other
	// order could put the wrong volume as the LXD root disk.
	if vm.BootDevice != "" {
		for i, d := range vm.Disks {
			if d.Device == vm.BootDevice && i != 0 {
				vm.Disks = append([]ProxmoxVMDisk{d}, append(vm.Disks[:i], vm.Disks[i+1:]...)...)
				break
			}
		}
	}
}

// proxmoxParseTPMVersion extracts the version field from a tpmstate0 value.
// Format example: "<storage>:vm-100-disk-1,size=4M,version=v2.0".
func proxmoxParseTPMVersion(val string) string {
	for _, p := range strings.Split(val, ",") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "version=") {
			return strings.TrimPrefix(p, "version=")
		}
	}
	return ""
}

// runRemoteSSHBytes is the binary-safe sibling of runRemoteSSH: stdout is
// returned untouched and stderr is captured separately so an SSH banner or
// progress line never lands inside the bytes the caller is about to write
// to disk. Used to stream the Proxmox TPM volume.
func runRemoteSSHBytes(conn ProxmoxSSHConn, cmdStr string) ([]byte, error) {
	cmd := exec.Command("sshpass", "-e", "ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=no",
		"-o", "ConnectTimeout=15",
		"-o", "ServerAliveInterval=30",
		fmt.Sprintf("%s@%s", conn.User, conn.Host),
		cmdStr,
	)
	cmd.Env = append(os.Environ(), "SSHPASS="+conn.Password)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %s", err.Error(), strings.TrimSpace(stderr.String()))
	}
	return out, nil
}

// shellSingleQuote wraps a string for safe inclusion inside a single-quoted
// remote shell argument. Embedded single quotes are closed, escaped, and
// reopened — the standard POSIX-portable trick.
func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// importProxmoxTPM is the best-effort TPM state migration from Proxmox to
// the just-created Incus VM. Compatibility gates:
//
//   - TPM v2.0 only (Incus' swtpm has no TPM 1.2 support).
//   - swtpm available on the local host.
//   - File size in [64 B, 4 MiB].
//
// On success, the TPM device is added to the Incus VM and the state file
// is placed at the standard Incus path. On any failure the function
// returns an error and adds nothing — the caller logs and continues, so
// a TPM-state import problem never blocks the rest of the import.
//
// Caveat: Proxmox uses swtpm's `file=` backend (single binary), Incus uses
// the `dir=` backend (`tpm2-00.permall`). The blob magic header is shared,
// so the drop-in works for many guests; if it doesn't, the user can
// disable the device via the Edit UI.
func importProxmoxTPM(conn ProxmoxSSHConn, vm ProxmoxVM, vmName, poolName string, log func(string)) error {
	if vm.TPM.Version != "v2.0" {
		return fmt.Errorf("Proxmox TPM is %q — only v2.0 is supported by Incus' swtpm", vm.TPM.Version)
	}
	if _, err := exec.LookPath("swtpm"); err != nil {
		return fmt.Errorf("swtpm is not installed on this host (apt install swtpm)")
	}

	// Resolve the local path on the Proxmox side. `pvesm path` works for
	// every storage type (ZFS zvol, dir, LVM, …) and prints exactly one path.
	pathOut, err := runRemoteSSH(conn, "pvesm path "+shellSingleQuote(vm.TPM.StorageVol))
	if err != nil {
		return fmt.Errorf("pvesm path %s: %v", vm.TPM.StorageVol, err)
	}
	remotePath := strings.TrimSpace(pathOut)
	if remotePath == "" {
		return fmt.Errorf("pvesm returned an empty path for %s", vm.TPM.StorageVol)
	}

	// Cap the read at 4 MiB — Proxmox always provisions exactly that and
	// reading further off a /dev/zvol would just be zeros.
	body, err := runRemoteSSHBytes(conn, fmt.Sprintf("head -c %d %s",
		4*1024*1024, shellSingleQuote(remotePath)))
	if err != nil {
		return fmt.Errorf("read TPM state: %v", err)
	}
	if len(body) < 64 {
		return fmt.Errorf("TPM state implausibly short (%d bytes)", len(body))
	}

	// Place into Incus' standard TPM dir. This is the package-install path;
	// the snap install would use /var/snap/incus/common/incus/... — out of
	// scope, since the rest of the importer also targets the package layout.
	const deviceName = "tpm"
	tpmDir := fmt.Sprintf("/var/lib/incus/storage-pools/%s/virtual-machines/%s/tpm.%s",
		poolName, vmName, deviceName)
	if out, err := exec.Command("sudo", "mkdir", "-p", tpmDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir %s: %s", tpmDir, strings.TrimSpace(string(out)))
	}
	statePath := tpmDir + "/tpm2-00.permall"
	teeCmd := exec.Command("sudo", "tee", statePath)
	teeCmd.Stdin = bytes.NewReader(body)
	if out, err := teeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write %s: %s", statePath, strings.TrimSpace(string(out)))
	}

	// Add the TPM device LAST so a failure earlier doesn't leave the VM
	// pointing at an empty / half-written state directory.
	if out, err := exec.Command("incus", "config", "device", "add",
		vmName, deviceName, "tpm").CombinedOutput(); err != nil {
		return fmt.Errorf("incus config device add tpm: %s", strings.TrimSpace(string(out)))
	}
	log(fmt.Sprintf("  ✓ TPM v2.0 state imported (%d KiB) and TPM device enabled.",
		len(body)/1024))
	return nil
}

// parseProxmoxSMBIOS1 decodes a Proxmox "smbios1:" config value into an
// LXDSMBIOSType1 so the imported VM can inherit the same DMI identity. The
// Proxmox format is comma-separated key=value pairs; when the special key
// "base64=1" is present, every other field's value is base64-encoded so it
// can safely contain commas, equals or spaces. Returns nil when no usable
// fields are found.
func parseProxmoxSMBIOS1(val string) *LXDSMBIOSType1 {
	parts := strings.Split(val, ",")
	raw := map[string]string{}
	encoded := false
	for _, p := range parts {
		p = strings.TrimSpace(p)
		eq := strings.IndexByte(p, '=')
		if eq <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(p[:eq]))
		v := strings.TrimSpace(p[eq+1:])
		if k == "base64" {
			encoded = (v == "1" || strings.EqualFold(v, "true"))
			continue
		}
		raw[k] = v
	}
	decode := func(k string) string {
		v := raw[k]
		if v == "" {
			return ""
		}
		// Per Proxmox: uuid is always plain text; other fields obey base64=1.
		if encoded && k != "uuid" {
			if b, err := base64.StdEncoding.DecodeString(v); err == nil {
				return string(b)
			}
		}
		return v
	}
	out := &LXDSMBIOSType1{
		UUID:         decode("uuid"),
		Manufacturer: decode("manufacturer"),
		Product:      decode("product"),
		Version:      decode("version"),
		Serial:       decode("serial"),
		SKU:          decode("sku"),
		Family:       decode("family"),
	}
	if *out == (LXDSMBIOSType1{}) {
		return nil
	}
	return out
}

// proxmoxParseNIC parses a Proxmox NIC value like "virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0".
func proxmoxParseNIC(val string) (driver, mac string) {
	knownDrivers := map[string]bool{
		"virtio": true, "e1000": true, "e1000e": true,
		"vmxnet3": true, "rtl8139": true, "vmxnet": true,
	}
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		eqIdx := strings.Index(part, "=")
		if eqIdx < 0 {
			continue
		}
		k := part[:eqIdx]
		v := part[eqIdx+1:]
		if knownDrivers[k] {
			driver = k
			mac = strings.ToUpper(v)
		}
	}
	return
}

// proxmoxDiskSizeStr extracts the size value from a Proxmox disk config string.
func proxmoxDiskSizeStr(val string) string {
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "size=") {
			return strings.TrimPrefix(part, "size=")
		}
	}
	return ""
}

// proxmoxParseDiskSize converts "50G", "512M", "1T" to bytes.
func proxmoxParseDiskSize(s string) int64 {
	if s == "" {
		return 0
	}
	s = strings.ToUpper(strings.TrimSpace(s))
	multipliers := map[byte]int64{
		'K': 1024,
		'M': 1024 * 1024,
		'G': 1024 * 1024 * 1024,
		'T': 1024 * 1024 * 1024 * 1024,
	}
	last := s[len(s)-1]
	if mul, ok := multipliers[last]; ok {
		n, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil {
			return 0
		}
		return int64(n * float64(mul))
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// sanitiseLXDName converts a Proxmox VM name to a valid LXD instance name.
func sanitiseLXDName(name string) string {
	name = strings.ToLower(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.' || r == ' ':
			b.WriteRune('-')
		}
	}
	result := strings.Trim(b.String(), "-")
	if result == "" {
		result = "imported-vm"
	}
	if result[0] >= '0' && result[0] <= '9' {
		result = "px-" + result
	}
	if len(result) > 63 {
		result = result[:63]
	}
	return strings.TrimRight(result, "-")
}

// lxcNameFree returns true if no LXD instance with the given name exists.
func lxcNameFree(name string) bool {
	return exec.Command("incus", "info", name).Run() != nil
}

// ImportProxmoxVM imports a single live Proxmox VM as a new LXD VM.
//
// Pipeline per disk (no temp space on the remote):
//
//	remote: pvesm path → qemu-img convert -O raw → stdout
//	SSH pipe → local raw file on ZFS pool → lxc storage volume import
//
// Progress lines are written to logCh.
// pxiCountingReader wraps an io.Reader and calls fn with the number of bytes read on each Read.
type pxiCountingReader struct {
	r  io.Reader
	fn func(int64)
}

func (c *pxiCountingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.fn != nil {
		c.fn(int64(n))
	}
	return n, err
}

func ImportProxmoxVM(ctx context.Context, conn ProxmoxSSHConn, vm ProxmoxVM, req ProxmoxImportRequest, logCh chan<- string, progressFn func(int64)) error {
	log := func(msg string) {
		if logCh != nil {
			logCh <- msg
		}
	}

	if !SshpassAvailable() {
		return fmt.Errorf("sshpass is not installed")
	}

	// Resolve unique LXD VM name.
	baseName := sanitiseLXDName(vm.Name)
	vmName := baseName
	for attempt := 1; attempt <= 5; attempt++ {
		if lxcNameFree(vmName) {
			break
		}
		vmName = fmt.Sprintf("%s-%d", baseName, attempt)
	}
	log(fmt.Sprintf("Importing VM %d ('%s') as LXD VM '%s'", vm.VMID, vm.Name, vmName))
	if vm.Status == "running" {
		log("  ⚠ VM is running — disk snapshot is live and may be inconsistent.")
	}

	// Step 1: Create empty LXD VM, with its root disk on the chosen datastore.
	//
	// The pool MUST be set here, at init: Incus refuses to move an existing
	// root disk to another pool afterwards ("Cannot update root disk device
	// pool name to X"), and a plain `init --empty` inherits the default
	// profile's root disk — which points at whatever pool that profile names.
	// Importing into any other datastore then failed on the very next step.
	// `--storage` attaches the root disk to the INSTANCE (not the shared
	// profile), so it also survives the `profile remove` below.
	log(fmt.Sprintf("Creating LXD VM '%s' (vCPU=%d, RAM=%d MB)...", vmName, vm.CPU, vm.MemoryMB))
	rootSize := ""
	if len(vm.Disks) > 0 {
		rootSize = proxmoxSizeToLXD(vm.Disks[0].SizeStr)
	}
	initArgs := proxmoxInitArgs(vmName, req.StoragePool, rootSize)
	if out, err := exec.Command("incus", initArgs...).CombinedOutput(); err != nil {
		return fmt.Errorf("lxc init: %s: %s", err.Error(), strings.TrimSpace(string(out)))
	}

	var createdVolumes []string
	rollback := func() {
		exec.Command("incus", "delete", "--force", vmName).Run() //nolint:errcheck
		for _, vol := range createdVolumes {
			exec.Command("incus", "storage", "volume", "delete", req.StoragePool, vol).Run() //nolint:errcheck
		}
	}

	if out, err := exec.Command("incus", "config", "set", vmName,
		fmt.Sprintf("limits.cpu=%d", vm.CPU)).CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("set cpu: %s: %s", err.Error(), strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("incus", "config", "set", vmName,
		fmt.Sprintf("limits.memory=%dMiB", vm.MemoryMB)).CombinedOutput(); err != nil {
		rollback()
		return fmt.Errorf("set memory: %s: %s", err.Error(), strings.TrimSpace(string(out)))
	}

	if vm.IsUEFI {
		log("  UEFI VM detected — disabling Secure Boot for compatibility.")
		exec.Command("incus", "config", "set", vmName, "security.secureboot=false").Run() //nolint:errcheck
	} else {
		// SeaBIOS (legacy BIOS) VM.
		// Prefer LXD-native CSM support (5.4+/6.x). On LXD 5.0.x the key is
		// unknown, so fall back to injecting -bios via raw.qemu which tells
		// QEMU to load SeaBIOS directly instead of OVMF.
		log("  SeaBIOS (legacy BIOS) VM detected — configuring CSM/SeaBIOS mode.")

		// LXD 5.4+ requires secureboot=false before csm=true.
		exec.Command("incus", "config", "set", vmName, "security.secureboot=false").Run() //nolint:errcheck
		csmOut, csmErr := exec.Command("incus", "config", "set", vmName, "security.csm=true").CombinedOutput()
		if csmErr == nil {
			log("  ✓ CSM (SeaBIOS) mode enabled via security.csm.")
		} else {
			// LXD 5.0.x: security.csm is unknown. Undo secureboot=false (UEFI
			// concept) and force SeaBIOS via raw.qemu -bios flag instead.
			log(fmt.Sprintf("  security.csm not supported (%s) — using raw.qemu -bios fallback.",
				strings.TrimSpace(string(csmOut))))
			exec.Command("incus", "config", "unset", vmName, "security.secureboot").Run() //nolint:errcheck

			biosPath := seabiosBinPath()
			if biosPath == "" {
				log("  ⚠ SeaBIOS binary not found — VM may not boot; install the 'seabios' package.")
			} else {
				if out, err := exec.Command("incus", "config", "set", vmName, "raw.qemu=-bios "+biosPath).CombinedOutput(); err != nil {
					log(fmt.Sprintf("  ⚠ Could not set raw.qemu=-bios: %s — VM may not boot.", strings.TrimSpace(string(out))))
				} else {
					log(fmt.Sprintf("  ✓ SeaBIOS configured via raw.qemu -bios %s.", biosPath))
				}
			}
		}
	}
	if vm.BootDevice != "" {
		log(fmt.Sprintf("  Boot device: %s (disk 0 = root).", vm.BootDevice))
	}

	// Replicate the Proxmox SMBIOS type 1 (System Information) identity so
	// guest-side bindings (Windows OEM activation, license servers, hypervisor
	// fingerprinting) keep working after the move. Merge into any existing
	// raw.qemu (e.g. the SeaBIOS -bios clause set just above) rather than
	// overwriting it.
	if vm.SMBIOS1 != nil {
		existing, _ := exec.Command("incus", "config", "get", vmName, "raw.qemu").Output()
		newRaw := updateRawQEMUSMBIOSType1(strings.TrimSpace(string(existing)), vm.SMBIOS1)
		if newRaw == "" {
			exec.Command("incus", "config", "unset", vmName, "raw.qemu").Run() //nolint:errcheck
		} else if out, err := exec.Command("incus", "config", "set", vmName, "raw.qemu="+newRaw).CombinedOutput(); err != nil {
			log(fmt.Sprintf("  ⚠ Could not apply SMBIOS type 1 from Proxmox: %s", strings.TrimSpace(string(out))))
		} else {
			log("  ✓ SMBIOS type 1 (System Information) replicated from Proxmox.")
		}
	}

	// Step 2: For each disk, create the backing zvol first (with no space
	// reservation), then stream the disk image from Proxmox directly into
	// the zvol via a local pipe — no temp file, so the pool only ever holds
	// one copy of the data at a time.

	// Resolve the ZFS dataset that backs the LXD pool.
	poolSource := getLXDPoolSource(req.StoragePool)
	if poolSource == "" {
		rollback()
		return fmt.Errorf("cannot determine ZFS source dataset for LXD pool '%s'", req.StoragePool)
	}
	log(fmt.Sprintf("  LXD pool '%s' backed by ZFS dataset '%s'", req.StoragePool, poolSource))

	for i, disk := range vm.Disks {
		lxdSize := proxmoxSizeToLXD(disk.SizeStr)
		volName := fmt.Sprintf("%s-disk-%d", vmName, i)

		var zvolDataset string

		if i == 0 {
			// Root disk: already attached at init (pool + size + boot.priority),
			// because Incus will not let it change pools after the fact. LXD
			// created the backing zvol with it.
			//
			// The default profile gives the VM an eth0 NIC on the LXD managed
			// bridge. Remove the profile now that the root disk is set at instance
			// level; otherwise adding the imported NICs to the same bridge causes
			// a DNS-name conflict error.
			exec.Command("incus", "profile", "remove", vmName, "default").Run() //nolint:errcheck
			zvolDataset = fmt.Sprintf("%s/virtual-machines/%s.block", poolSource, vmName)
		} else {
			// Additional disk: create a custom block volume.
			createArgs := []string{"storage", "volume", "create",
				req.StoragePool, volName, "--type", "block",
			}
			if lxdSize != "" {
				createArgs = append(createArgs, "size="+lxdSize)
			}
			if out, err := exec.Command("incus", createArgs...).CombinedOutput(); err != nil {
				rollback()
				return fmt.Errorf("create disk volume %d: %s: %s", i, err.Error(), strings.TrimSpace(string(out)))
			}
			createdVolumes = append(createdVolumes, volName)
			zvolDataset = fmt.Sprintf("%s/custom/default_%s", poolSource, volName)
		}

		// Remove the ZFS space reservation so writing the zvol doesn't compete
		// with other data on the pool. The data we stream in IS the reservation.
		exec.Command("sudo", "zfs", "set", "refreservation=none", zvolDataset).Run() //nolint:errcheck

		// Disable ZFS sync during import so writes are batched rather than
		// flushed to disk after every block. This is safe: if the import
		// crashes, the zvol is discarded anyway. Restore sync=standard after.
		exec.Command("sudo", "zfs", "set", "sync=disabled", zvolDataset).Run() //nolint:errcheck

		// Set the exact volsize from the Proxmox config. ZFS volsize must be a
		// multiple of volblocksize (LXD default is 16 KiB).
		if disk.SizeBytes > 0 {
			volblockOut, _ := exec.Command("sudo", "zfs", "get", "-H", "-o", "value",
				"volblocksize", zvolDataset).Output()
			vbs := int64(16384)
			if vbsStr := strings.TrimSpace(string(volblockOut)); vbsStr != "" {
				vbs = proxmoxParseDiskSize(vbsStr)
				if vbs <= 0 {
					vbs = 16384
				}
			}
			volsizeBytes := ((disk.SizeBytes + vbs - 1) / vbs) * vbs
			if out, err := exec.Command("sudo", "zfs", "set",
				fmt.Sprintf("volsize=%d", volsizeBytes),
				zvolDataset).CombinedOutput(); err != nil {
				rollback()
				return fmt.Errorf("set zvol size for disk %d: %s: %s", i, err.Error(), strings.TrimSpace(string(out)))
			}
			log(fmt.Sprintf("  Zvol sized to %d bytes (%s)", volsizeBytes, disk.SizeStr))
		}

		// LXD snap creates zvols with volmode=none (no block device in /dev/).
		// We set volmode=dev so ZFS creates the /dev/zdX kernel block device.
		// We bypass /dev/zvol/ symlinks entirely (udev may be blocked by a
		// stale regular file left by a prior failed import). Instead we snapshot
		// the existing zd* devices, set volmode=dev, then poll for the new one.

		// Snapshot existing /dev/zd<N> block device nodes (no partitions).
		zdRe := regexp.MustCompile(`^zd\d+$`)
		beforeZDs := map[string]bool{}
		if devEntries, _ := os.ReadDir("/dev"); devEntries != nil {
			for _, e := range devEntries {
				if zdRe.MatchString(e.Name()) {
					beforeZDs[e.Name()] = true
				}
			}
		}

		if out, err := exec.Command("sudo", "zfs", "set", "volmode=dev", zvolDataset).CombinedOutput(); err != nil {
			rollback()
			return fmt.Errorf("set volmode=dev for disk %d: %s: %s", i, err.Error(), strings.TrimSpace(string(out)))
		}

		// Poll up to 10 s for the new /dev/zdX device to appear.
		blockDev := ""
		for attempt := 0; attempt < 100 && blockDev == ""; attempt++ {
			time.Sleep(100 * time.Millisecond)
			devEntries, _ := os.ReadDir("/dev")
			for _, e := range devEntries {
				if zdRe.MatchString(e.Name()) && !beforeZDs[e.Name()] {
					blockDev = "/dev/" + e.Name()
					break
				}
			}
		}
		if blockDev == "" {
			rollback()
			return fmt.Errorf("disk %d: no /dev/zdX appeared after setting volmode=dev on %s", i, zvolDataset)
		}
		log(fmt.Sprintf("  Disk %d block device: %s", i, blockDev))

		// Stream the disk image from Proxmox directly into the zvol using a
		// local pipe (SSH stdout → pipe → sudo dd → /dev/zdX). No temp file is
		// written so the pool only ever allocates the zvol blocks, not a
		// duplicate copy.
		log(fmt.Sprintf("Streaming disk %d (%s, %s) → %s...", i, disk.Device, disk.SizeStr, blockDev))

		streamScript := fmt.Sprintf(`
_p=$(pvesm path %q) || exit 1
if echo "$_p" | grep -q '^rbd:'; then
    _rbd=$(echo "$_p" | sed 's/^rbd://;s/:.*//')
    rbd export "$_rbd" - 2>/dev/null
elif [ -b "$_p" ]; then
    dd if="$_p" bs=4M status=none
else
    qemu-img convert -O raw "$_p" /dev/stdout
fi`, disk.StorageVol)

		// Check for cancellation before starting the streaming pipeline.
		if ctx.Err() != nil {
			rollback()
			return fmt.Errorf("import canceled")
		}

		sshCmd := exec.CommandContext(ctx, "sshpass", "-e", "ssh",
			"-o", "StrictHostKeyChecking=no",
			"-o", "BatchMode=no",
			"-o", "ConnectTimeout=15",
			"-o", "ServerAliveInterval=30",
			"-o", "Compression=no",
			fmt.Sprintf("%s@%s", conn.User, conn.Host),
			streamScript,
		)
		sshCmd.Env = append(os.Environ(), "SSHPASS="+conn.Password)

		ddCmd := exec.CommandContext(ctx, "sudo", "dd", "of="+blockDev, "bs=4M", "conv=notrunc", "oflag=direct")

		pr, pw := io.Pipe()
		sshCmd.Stdout = pw
		ddCmd.Stdin = &pxiCountingReader{r: pr, fn: progressFn}

		var sshStderr, ddStderr bytes.Buffer
		sshCmd.Stderr = &sshStderr
		ddCmd.Stderr = &ddStderr

		if startErr := sshCmd.Start(); startErr != nil {
			pr.Close()
			pw.Close()
			rollback()
			return fmt.Errorf("start ssh for disk %d: %w", i, startErr)
		}
		if startErr := ddCmd.Start(); startErr != nil {
			sshCmd.Process.Kill() //nolint:errcheck
			pr.Close()
			pw.Close()
			rollback()
			return fmt.Errorf("start dd for disk %d: %w", i, startErr)
		}

		sshRunErr := sshCmd.Wait()
		pw.Close() // signal EOF to dd
		ddRunErr := ddCmd.Wait()
		pr.Close()

		sshErrMsg := strings.TrimSpace(sshStderr.String())
		ddErrMsg := strings.TrimSpace(ddStderr.String())

		// Restore sync regardless of success or failure — must happen before rollback.
		exec.Command("sudo", "zfs", "set", "sync=standard", zvolDataset).Run() //nolint:errcheck

		// qemu-img writes all data then fails only on the final ftruncate of a
		// pipe; tolerate that specific error since all bytes are already written.
		if sshRunErr != nil && !strings.Contains(sshErrMsg, "Could not resize file") {
			rollback()
			if ctx.Err() != nil {
				return fmt.Errorf("import canceled")
			}
			if sshErrMsg == "" {
				sshErrMsg = sshRunErr.Error()
			}
			return fmt.Errorf("stream disk %d (%s): %s", i, disk.Device, sshErrMsg)
		}
		if ddRunErr != nil {
			// Restore volmode regardless, best effort.
			exec.Command("sudo", "zfs", "set", "volmode=none", zvolDataset).Run() //nolint:errcheck
			rollback()
			if ddErrMsg == "" {
				ddErrMsg = ddRunErr.Error()
			}
			return fmt.Errorf("write disk %d (%s): %s", i, disk.Device, ddErrMsg)
		}

		// Disk-truth UEFI detection: if the root disk carries an EFI System
		// Partition but the Proxmox config never flagged UEFI (no `bios: ovmf`,
		// no efidisk), we configured SeaBIOS/CSM above — which CANNOT boot an OS
		// that lives behind UEFI: the firmware never finds the EFI loader and the
		// guest reports it can't find its boot disk (seen importing an OPNsense
		// VM). Now that the written disk is readable, correct the firmware to UEFI.
		if i == 0 && !vm.IsUEFI && diskHasEFISystemPartition(blockDev) {
			log("  Root disk has an EFI System Partition → switching this VM to UEFI boot (the Proxmox config didn't indicate UEFI, so SeaBIOS/CSM was configured, which can't boot it).")
			vm.IsUEFI = true
			exec.Command("incus", "config", "unset", vmName, "security.csm").Run()            //nolint:errcheck
			exec.Command("incus", "config", "set", vmName, "security.secureboot=false").Run() //nolint:errcheck
		}

		// For UEFI root disk: fix the fallback GRUB boot path on the ESP while
		// the block device is still accessible (before volmode=none removes it).
		if vm.IsUEFI && i == 0 {
			log("  Repairing UEFI fallback boot path...")
			fixUEFIGrub(blockDev, log)
			// Windows-specific repairs run alongside fixUEFIGrub (no-ops on
			// non-Windows ESPs). They neutralise the "every-other-boot →
			// recovery loop" we used to see on imported Windows VMs: the
			// disk arrives with the NTFS volume marked dirty by Windows'
			// fast-startup shutdown, and BCD's resumeobject points at a
			// hiberfile location that no longer matches Incus's hardware
			// topology. After applying ntfsfix to clear the dirty bit and
			// stripping the resume / ignoreallfailures policy from BCD,
			// Windows does a cold boot every time and stops cycling through
			// recovery on each second start.
			fixUEFIWindows(blockDev, log)
		}

		// Restore volmode=none so LXD finds the zvol in its expected state.
		// LXD sets volmode=dev itself when the VM starts.
		exec.Command("sudo", "zfs", "set", "volmode=none", zvolDataset).Run() //nolint:errcheck

		if i > 0 {
			devArgs := []string{"config", "device", "add", vmName,
				fmt.Sprintf("disk%d", i), "disk",
				"pool=" + req.StoragePool,
				"source=" + volName,
			}
			if out, err := exec.Command("incus", devArgs...).CombinedOutput(); err != nil {
				rollback()
				return fmt.Errorf("attach disk %d: %s: %s", i, err.Error(), strings.TrimSpace(string(out)))
			}
		}

		log(fmt.Sprintf("  ✓ Disk %d imported.", i))
	}

	// Step 3: Add NICs with preserved MAC addresses.
	// nictype=bridged avoids LXD DNS tracking for unmanaged bridges, but LXD 6.x
	// still enforces uniqueness when the parent happens to be a managed bridge
	// name — a second NIC on the same managed bridge triggers a DNS-conflict error.
	// When that happens (or any other add failure), store the NIC in the
	// user.disconnected_nics.<device> config key so ZNAS shows it as a
	// disconnected NIC that the user can re-attach to the correct bridge later.
	for _, nic := range vm.NICs {
		log(fmt.Sprintf("Adding NIC %s (MAC=%s) on bridge '%s'...", nic.Device, nic.MAC, req.LocalBridge))
		nicArgs := []string{"config", "device", "add", vmName,
			nic.Device, "nic",
			"nictype=bridged",
			fmt.Sprintf("parent=%s", req.LocalBridge),
		}
		if nic.MAC != "" {
			nicArgs = append(nicArgs, fmt.Sprintf("hwaddr=%s", strings.ToLower(nic.MAC)))
		}
		if out, err := exec.Command("incus", nicArgs...).CombinedOutput(); err != nil {
			errMsg := strings.TrimSpace(string(out))
			log(fmt.Sprintf("  ⚠ NIC %s could not be directly attached (%s) — saved as disconnected NIC.", nic.Device, errMsg))
			// Preserve config so the user can reconnect via ZNAS VM edit UI.
			mac := strings.ToLower(nic.MAC)
			disconnConf := fmt.Sprintf(`{"bridge":%q,"mac":%q,"vlan":""}`, req.LocalBridge, mac)
			disconnKey := "user.disconnected_nics." + nic.Device
			if setOut, setErr := exec.Command("incus", "config", "set", vmName, disconnKey, disconnConf).CombinedOutput(); setErr != nil {
				log(fmt.Sprintf("  ✗ Could not save disconnected NIC config: %s", strings.TrimSpace(string(setOut))))
			}
		} else {
			log(fmt.Sprintf("  ✓ NIC %s connected (MAC=%s).", nic.Device, nic.MAC))
		}
	}

	// TPM import (best-effort). Skipped silently when no Proxmox tpmstate0
	// is configured; the VM was created without a TPM device above, so the
	// "skip + disable" branch is the no-op default.
	if vm.TPM != nil {
		log(fmt.Sprintf("Detected Proxmox TPM (%s, %s).",
			vm.TPM.Version, formatBytes(uint64(vm.TPM.SizeBytes))))
		if err := importProxmoxTPM(conn, vm, vmName, req.StoragePool, log); err != nil {
			log("  ⚠ TPM import skipped: " + err.Error())
			log("  ⚠ TPM device NOT added to imported VM. Enable manually via VM Edit if desired.")
		}
	}

	// Step 4: Optionally start.
	if req.StartAfter {
		log(fmt.Sprintf("Starting VM '%s'...", vmName))
		if out, err := exec.Command("incus", "start", vmName).CombinedOutput(); err != nil {
			log(fmt.Sprintf("  ⚠ Could not start VM: %s: %s", err.Error(), strings.TrimSpace(string(out))))
		} else {
			log("  ✓ VM started.")
		}
	}

	log(fmt.Sprintf("✓ VM %d ('%s') imported successfully as LXD VM '%s'.", vm.VMID, vm.Name, vmName))
	return nil
}

// getLXDPoolSource parses `lxc storage show <pool>` and returns the ZFS dataset
// name backing the pool (e.g. "NVMEPool/lxd-base"). Returns "" on any failure.
func getLXDPoolSource(poolName string) string {
	out, err := exec.Command("incus", "storage", "show", poolName).Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(kv) == 2 && strings.TrimSpace(kv[0]) == "source" {
			src := strings.TrimSpace(kv[1])
			src = strings.TrimPrefix(src, "/")
			src = strings.TrimRight(src, "/")
			return src
		}
	}
	return ""
}

// proxmoxSizeToLXD converts a Proxmox disk size string (e.g. "32G", "512M")
// into the IEC form expected by LXD (e.g. "32GiB", "512MiB").
// proxmoxInitArgs builds the `incus init` command for an imported VM. Split
// out so the one thing that broke imports into a non-default datastore — the
// root pool not being set at creation time — is covered by a test.
func proxmoxInitArgs(vmName, pool, rootSize string) []string {
	args := []string{"init", "--empty", vmName, "--vm"}
	if pool != "" {
		args = append(args, "--storage", pool)
	}
	if rootSize != "" {
		args = append(args, "-d", "root,size="+rootSize)
	}
	return append(args, "-d", "root,boot.priority=1")
}

func proxmoxSizeToLXD(s string) string {
	if s == "" {
		return ""
	}
	s = strings.TrimSpace(s)
	upper := strings.ToUpper(s)
	for _, unit := range []string{"T", "G", "M", "K"} {
		if strings.HasSuffix(upper, unit) {
			return s[:len(s)-1] + unit + "iB"
		}
	}
	return s
}

// fixUEFIGrub mounts the EFI System Partition on blockDev and copies the
// distro's grub.cfg to EFI/BOOT/grub.cfg.
//
// When LXD starts a VM with a fresh OVMF NVRAM (no imported efidisk), OVMF
// falls back to \EFI\BOOT\BOOTX64.EFI. That binary has its prefix set to
// \EFI\BOOT\ — not \EFI\<distro>\ — so GRUB loads but can't find grub.cfg
// and drops to the grub> prompt. Placing grub.cfg in \EFI\BOOT\ fixes this.
// diskHasEFISystemPartition reports whether the GPT on blockDev contains an EFI
// System Partition (GPT type code EF00 / type GUID C12A7328-F81F-11D2-BA4B-
// 00A0C93EC93B). It reads the on-disk GPT directly via sgdisk so it works even
// before the kernel has scanned the freshly-written zvol's partitions. Used to
// detect a UEFI install whose Proxmox config didn't flag UEFI. Best-effort:
// returns false when no partition tool is available.
func diskHasEFISystemPartition(blockDev string) bool {
	if _, err := exec.LookPath("sgdisk"); err == nil {
		if out, err := exec.Command("sudo", "sgdisk", "-p", blockDev).CombinedOutput(); err == nil {
			for _, ln := range strings.Split(string(out), "\n") {
				// sgdisk prints the 4-hex GPT type code; EF00 == EFI System.
				if strings.Contains(ln, "EF00") {
					return true
				}
			}
			return false
		}
	}
	// Fallback: expose partitions and check their type GUIDs via lsblk.
	exec.Command("sudo", "partx", "-a", "-u", blockDev).Run() //nolint:errcheck
	defer exec.Command("sudo", "partx", "-d", blockDev).Run() //nolint:errcheck
	time.Sleep(300 * time.Millisecond)
	out, err := exec.Command("lsblk", "-rno", "PARTTYPE", blockDev).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(strings.ToLower(string(out)), "c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
}

func fixUEFIGrub(blockDev string, log func(string)) {
	// Get current user's UID so FAT32 is mounted with uid= and we can
	// read/write the ESP directly without sudo for file operations.
	uidOut, _ := exec.Command("id", "-u").Output()
	uid := strings.TrimSpace(string(uidOut))

	// Expose partition block devices: /dev/zd32 → /dev/zd32p1, /dev/zd32p2 …
	exec.Command("sudo", "partx", "-a", "-u", blockDev).Run() //nolint:errcheck
	time.Sleep(300 * time.Millisecond)                        // let kernel create dev nodes
	defer exec.Command("sudo", "partx", "-d", blockDev).Run() //nolint:errcheck

	tmpDir := fmt.Sprintf("/tmp/.znas-esp-%d", time.Now().UnixNano())
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		log("  ⚠ Could not create ESP mount point — UEFI boot path not repaired.")
		return
	}
	defer os.RemoveAll(tmpDir)

	mountOpts := "umask=022"
	if uid != "" {
		mountOpts = "uid=" + uid + ",umask=022"
	}

	// Try partitions p1..p4 — find the FAT32 one with an EFI/ directory.
	espMounted := false
	for p := 1; p <= 4; p++ {
		part := fmt.Sprintf("%sp%d", blockDev, p)
		if _, err := os.Stat(part); err != nil {
			continue
		}
		if exec.Command("sudo", "mount", "-t", "vfat", "-o", mountOpts, part, tmpDir).Run() != nil {
			continue
		}
		if info, err := os.Stat(filepath.Join(tmpDir, "EFI")); err == nil && info.IsDir() {
			espMounted = true
			break
		}
		exec.Command("sudo", "umount", "-l", tmpDir).Run() //nolint:errcheck
	}
	if !espMounted {
		log("  ⚠ No EFI System Partition found on disk — UEFI boot path not repaired.")
		return
	}
	defer exec.Command("sudo", "umount", "-l", tmpDir).Run() //nolint:errcheck

	// Find the distro's grub.cfg — one level under EFI/, not in EFI/BOOT/.
	efiDir := filepath.Join(tmpDir, "EFI")
	entries, err := os.ReadDir(efiDir)
	if err != nil {
		log("  ⚠ Could not list EFI/ directory — UEFI boot path not repaired.")
		return
	}
	srcCfg := ""
	for _, e := range entries {
		if !e.IsDir() || strings.EqualFold(e.Name(), "BOOT") {
			continue
		}
		candidate := filepath.Join(efiDir, e.Name(), "grub.cfg")
		if _, err := os.Stat(candidate); err == nil {
			srcCfg = candidate
			break
		}
	}
	if srcCfg == "" {
		log("  ⚠ No distro grub.cfg on ESP (no EFI/<distro>/grub.cfg) — UEFI boot path not repaired.")
		return
	}

	// Install it as EFI/BOOT/grub.cfg — the path fallback GRUB will look for.
	bootDir := filepath.Join(efiDir, "BOOT")
	if err := os.MkdirAll(bootDir, 0755); err != nil {
		log(fmt.Sprintf("  ⚠ Could not create EFI/BOOT/: %v", err))
		return
	}
	data, err := os.ReadFile(srcCfg)
	if err != nil {
		log(fmt.Sprintf("  ⚠ Could not read %s: %v", srcCfg, err))
		return
	}
	if err := os.WriteFile(filepath.Join(bootDir, "grub.cfg"), data, 0644); err != nil {
		log(fmt.Sprintf("  ⚠ Could not write EFI/BOOT/grub.cfg: %v", err))
		return
	}
	distro := filepath.Base(filepath.Dir(srcCfg))
	distroDir := filepath.Dir(srcCfg)
	log(fmt.Sprintf("  ✓ UEFI fallback boot repaired — EFI/BOOT/grub.cfg installed from EFI/%s/grub.cfg.", distro))

	// Ensure EFI/BOOT/BOOTX64.EFI exists — OVMF needs this for the UEFI
	// fallback boot path.  Proxmox-imported disks often only have the distro-
	// specific path; without this binary OVMF reports "no boot target" before
	// GRUB is ever reached.
	bootBin := filepath.Join(bootDir, "BOOTX64.EFI")
	if _, statErr := os.Stat(bootBin); os.IsNotExist(statErr) {
		findEFI := func(name string) string {
			efis, _ := os.ReadDir(distroDir)
			for _, f := range efis {
				if !f.IsDir() && strings.EqualFold(f.Name(), name) {
					return filepath.Join(distroDir, f.Name())
				}
			}
			return ""
		}
		copyEFI := func(src, dst string) bool {
			d, readErr := os.ReadFile(src)
			if readErr != nil {
				return false
			}
			return os.WriteFile(dst, d, 0644) == nil
		}
		// Prefer grubx64.efi: GRUB uses its compiled-in prefix to locate
		// EFI/<distro>/grub.cfg, which is still on disk.  Fall back to
		// shimx64.efi, then any .efi in the distro directory.
		if grub := findEFI("grubx64.efi"); grub != "" {
			if copyEFI(grub, bootBin) {
				log(fmt.Sprintf("  ✓ EFI/BOOT/BOOTX64.EFI installed from EFI/%s/grubx64.efi.", distro))
			} else {
				log("  ⚠ Could not write EFI/BOOT/BOOTX64.EFI.")
			}
		} else if shim := findEFI("shimx64.efi"); shim != "" {
			if copyEFI(shim, bootBin) {
				log(fmt.Sprintf("  ✓ EFI/BOOT/BOOTX64.EFI installed from EFI/%s/shimx64.efi.", distro))
			} else {
				log("  ⚠ Could not write EFI/BOOT/BOOTX64.EFI.")
			}
		} else {
			efis, _ := os.ReadDir(distroDir)
			for _, f := range efis {
				if !f.IsDir() && strings.HasSuffix(strings.ToLower(f.Name()), ".efi") {
					if copyEFI(filepath.Join(distroDir, f.Name()), bootBin) {
						log(fmt.Sprintf("  ✓ EFI/BOOT/BOOTX64.EFI installed from EFI/%s/%s.", distro, f.Name()))
						break
					}
				}
			}
		}
	}
}

// seabiosBinPath returns the first SeaBIOS binary found on this system, or "".
func seabiosBinPath() string {
	for _, p := range []string{
		"/usr/share/seabios/bios.bin",
		"/usr/lib/qemu/bios.bin",
		"/usr/share/qemu/bios.bin",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// fixUEFIWindows applies repairs that an imported Windows guest needs to boot
// reliably on Incus. Detection: an ESP that contains
// \EFI\Microsoft\Boot\bootmgfw.efi. No-op for non-Windows VMs.
//
// Why this is needed: Windows' default shutdown is fast-startup (a partial
// kernel hibernation). The captured Proxmox disk therefore arrives with
//  1. NTFS volume dirty bit + "kept in cache" flag set, blocking r/w mount
//     and forcing Windows to run a slow check on every boot.
//  2. BCD pointing the BootMgr at a `resumeobject` (Windows Resume App)
//     that references hibernation memory captured against the Proxmox
//     QEMU machine (different ACPI / PCI topology than Incus). On Incus
//     the resume aborts; without `bootstatuspolicy=ignoreallfailures`,
//     BootMgr alternates between the resume attempt and Windows RE on
//     every second boot — the "recovery loop every 2 boots" we saw.
//
// The fix runs offline against the imported zvol, before LXD ever sets
// volmode=none on it, so the user's first start finds a clean disk.
func fixUEFIWindows(blockDev string, log func(string)) {
	parts, err := listPartitions(blockDev)
	if err != nil {
		log("  ⚠ Windows fix: " + err.Error())
		return
	}
	if len(parts) == 0 {
		return
	}

	// Find the ESP (FAT32 partition with \EFI\Microsoft\Boot\bootmgfw.efi).
	// Each partition is reached via an offset+sizelimit loop device because
	// `partx -a` is unreliable on zvols whose 16 KiB volblocksize doesn't
	// match a 512-byte logical sector size — the kernel rejects the add
	// with EINVAL and `${blockDev}p1` never appears.
	tmpESP := fmt.Sprintf("/tmp/.znas-esp-win-%d", time.Now().UnixNano())
	if err := os.MkdirAll(tmpESP, 0o755); err != nil {
		log("  ⚠ Windows fix: mkdir ESP: " + err.Error())
		return
	}
	defer os.RemoveAll(tmpESP)

	espLoop := ""
	for _, p := range parts {
		loop, lerr := pxiLoopAttach(blockDev, p)
		if lerr != nil {
			continue
		}
		if exec.Command("sudo", "mount", "-t", "vfat", "-o", "umask=022", loop, tmpESP).Run() != nil {
			exec.Command("sudo", "losetup", "-d", loop).Run() //nolint:errcheck
			continue
		}
		if _, err := os.Stat(filepath.Join(tmpESP, "EFI", "Microsoft", "Boot", "bootmgfw.efi")); err == nil {
			espLoop = loop
			break
		}
		exec.Command("sudo", "umount", "-l", tmpESP).Run() //nolint:errcheck
		exec.Command("sudo", "losetup", "-d", loop).Run()  //nolint:errcheck
	}
	if espLoop == "" {
		// Not a Windows install — nothing to do.
		return
	}
	log("  Detected Windows ESP — applying boot-state repairs.")

	// Patch BCD before unmounting the ESP. Done first because if it fails
	// we'd rather know now than after we've already touched NTFS partitions.
	bcdPath := filepath.Join(tmpESP, "EFI", "Microsoft", "Boot", "BCD")
	if err := patchWindowsBCD(bcdPath); err != nil {
		log("  ⚠ BCD patch: " + err.Error())
	} else {
		log("  ✓ BCD patched: removed BootMgr resumeobject + bootstatuspolicy=IgnoreAllFailures")
	}
	exec.Command("sudo", "umount", "-l", tmpESP).Run()   //nolint:errcheck
	exec.Command("sudo", "losetup", "-d", espLoop).Run() //nolint:errcheck

	// Clear the NTFS dirty / fast-startup-cache bit on every NTFS partition
	// that lives on this disk. Without this, Windows refuses to mount the
	// volume read/write on first boot and keeps falling through to recovery.
	for _, p := range parts {
		loop, lerr := pxiLoopAttach(blockDev, p)
		if lerr != nil {
			continue
		}
		// Skip the ESP itself (FAT32) and anything that isn't NTFS.
		out, err := exec.Command("sudo", "blkid", "-o", "value", "-s", "TYPE", loop).Output()
		if err != nil || strings.TrimSpace(string(out)) != "ntfs" {
			exec.Command("sudo", "losetup", "-d", loop).Run() //nolint:errcheck
			continue
		}
		if out, err := exec.Command("sudo", "ntfsfix", "--clear-dirty", loop).CombinedOutput(); err != nil {
			log(fmt.Sprintf("  ⚠ ntfsfix on partition %d: %s", p.Index, strings.TrimSpace(string(out))))
		} else {
			log(fmt.Sprintf("  ✓ ntfsfix on partition %d — cleared NTFS dirty bit", p.Index))
		}
		// Best-effort: drop \hiberfil.sys if Windows left one behind.
		tmpNT := fmt.Sprintf("/tmp/.znas-nt-%d", time.Now().UnixNano())
		if err := os.MkdirAll(tmpNT, 0o755); err == nil {
			if exec.Command("sudo", "mount", "-o", "remove_hiberfile", "-t", "ntfs-3g", loop, tmpNT).Run() == nil {
				exec.Command("sudo", "umount", tmpNT).Run() //nolint:errcheck
			}
			os.RemoveAll(tmpNT)
		}
		exec.Command("sudo", "losetup", "-d", loop).Run() //nolint:errcheck
	}
}

// pxiPart describes one partition entry parsed from `sgdisk -p`.
type pxiPart struct {
	Index      int   // 1-based partition index
	StartBytes int64 // first byte of the partition (sector * 512)
	SizeBytes  int64 // partition size in bytes
}

// pxiSGDiskRow matches a partition row in sgdisk's print output:
//
//	Number  Start (sector)    End (sector)  Size       Code  Name
//	   1            2048          206847   100.0 MiB   EF00  EFI system partition
//
// Captures: 1=Number, 2=Start sector, 3=End sector.
var pxiSGDiskRow = regexp.MustCompile(`^\s*(\d+)\s+(\d+)\s+(\d+)\s+`)

// listPartitions parses `sgdisk -p <blockDev>` to enumerate partitions on the
// imported zvol. We use sgdisk because `partx -a` fails on zvols whose 16 KiB
// volblocksize doesn't match the partition table's 512-byte sector
// arithmetic (kernel returns EINVAL for every partition), and because
// resolving partition geometry through GPT lets us mount each partition via
// an offset loop device — a path that always works.
func listPartitions(blockDev string) ([]pxiPart, error) {
	out, err := exec.Command("sudo", "sgdisk", "-p", blockDev).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sgdisk -p %s: %s", blockDev, strings.TrimSpace(string(out)))
	}
	const sectorSize = 512
	var parts []pxiPart
	for _, line := range strings.Split(string(out), "\n") {
		m := pxiSGDiskRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		idx, _ := strconv.Atoi(m[1])
		start, _ := strconv.ParseInt(m[2], 10, 64)
		end, _ := strconv.ParseInt(m[3], 10, 64)
		if idx <= 0 || end < start {
			continue
		}
		parts = append(parts, pxiPart{
			Index:      idx,
			StartBytes: start * sectorSize,
			SizeBytes:  (end - start + 1) * sectorSize,
		})
	}
	return parts, nil
}

// pxiLoopAttach attaches a read/write loop device to one partition of blockDev
// using offset+sizelimit. Caller MUST detach with `losetup -d`.
func pxiLoopAttach(blockDev string, p pxiPart) (string, error) {
	out, err := exec.Command("sudo", "losetup", "-f", "--show",
		"-o", strconv.FormatInt(p.StartBytes, 10),
		"--sizelimit", strconv.FormatInt(p.SizeBytes, 10),
		blockDev,
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("losetup p%d: %s", p.Index, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// patchWindowsBCD opens the Windows BCD registry hive at bcdPath and:
//  1. Deletes the BootMgr's `resumeobject` element (`23000006`) so BootMgr
//     never tries to resume from a stale hibernate file.
//  2. Sets the BootMgr's `bootstatuspolicy` (`25000005`) to 1 = IgnoreAll-
//     Failures so a single boot hiccup doesn't kick Windows into RE on
//     the next start.
//
// Implemented via libhivex's Python bindings (python3-hivex), piped through
// stdin so sudoers only has to whitelist the very narrow `python3 -` form
// rather than allowing `python3 -c '<arbitrary code>'`.
func patchWindowsBCD(bcdPath string) error {
	const script = `import hivex, struct, sys
h = hivex.Hivex(sys.argv[1], write=True)
def child(node, name):
    for c in h.node_children(node):
        if h.node_name(c) == name: return c
    return None
root = h.root()
objs = child(root, "Objects")
if not objs: sys.exit("no Objects")
bm = child(objs, "{9dea862c-5cdd-4e70-acc1-f32b344d4795}")
if not bm: sys.exit("no BootMgr GUID")
elements = child(bm, "Elements")
if not elements: sys.exit("no Elements")
res = child(elements, "23000006")
if res:
    h.node_delete_child(res)
bsp = child(elements, "25000005")
if not bsp:
    bsp = h.node_add_child(elements, "25000005")
h.node_set_value(bsp, {"key": "Element", "t": 3, "value": struct.pack("<Q", 1)})
h.commit(None)
`
	cmd := exec.Command("sudo", "python3", "-", bcdPath)
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("hivex: %s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
