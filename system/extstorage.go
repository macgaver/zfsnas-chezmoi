package system

// extstorage.go — v6.7.7 External Storage mount engine for the Protect →
// Filesystem rsync tab.
//
// All four protocols (SMB / NFS / FTP / SSH) funnel into one primitive: the
// remote filesystem is mounted under /mnt/zfsnas-ext/<id>, and both the file
// browser and rsync operate against that local path. Every mount runs via
// sudo (root-owned) — this matches the file browser, whose operations already
// shell through `sudo find/stat/cat`, and lets `sudo rsync` read/write both
// sides without fuse allow_other complications.
//
// Mount modes:
//   - "ondemand" (default): mounted when an rsync run starts or the file
//     browser opens the storage; a janitor unmounts it after ~15 min idle.
//     Non-lazy umount — busy mounts are skipped and retried next tick.
//   - "persistent": mounted on save and re-mounted at service startup.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/config"
)

// ExtMountBase is the parent directory for all external-storage mountpoints.
const ExtMountBase = "/mnt/zfsnas-ext"

// extIdleTimeout is how long an on-demand mount may sit unused before the
// janitor unmounts it. The file browser sends a keepalive touch while open.
const extIdleTimeout = 15 * time.Minute

var extIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// ValidExtID reports whether an external-storage id is safe to embed in
// mountpoint paths (they appear inside sudoers-matched command lines).
func ValidExtID(id string) bool { return extIDRe.MatchString(id) }

// ExtMountpoint returns the mountpoint path for a storage id.
func ExtMountpoint(id string) string { return filepath.Join(ExtMountBase, id) }

// extLastUsed tracks per-storage last-use timestamps for the idle janitor.
var (
	extMu       sync.Mutex
	extLastUsed = map[string]time.Time{}
)

// ExtTouch bumps the idle timer for a storage (called on mount, on rsync
// start/finish, and by the file-browser keepalive).
func ExtTouch(id string) {
	extMu.Lock()
	extLastUsed[id] = time.Now()
	extMu.Unlock()
}

// ExtIsMounted reports whether the storage's mountpoint is currently a live
// mount, by scanning /proc/self/mounts (no fork, no sudo).
func ExtIsMounted(id string) bool {
	return pathIsMountpoint(ExtMountpoint(id))
}

func pathIsMountpoint(mp string) bool {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		// Field 1 is the mountpoint; octal-escape decoding (\040 for space)
		// is irrelevant here because our ids can't contain spaces.
		if len(f) >= 2 && f[1] == mp {
			return true
		}
	}
	return false
}

// extstorageSecretsDir returns config/extstorage, creating it 0700.
func extstorageSecretsDir(configDir string) (string, error) {
	dir := filepath.Join(configDir, "extstorage")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

// ExtCredFile returns the path of the CIFS credentials file for a storage.
func ExtCredFile(configDir, id string) string {
	return filepath.Join(configDir, "extstorage", id+".cred")
}

// ExtSSHKeyFile returns the path of the SSH private key file for a storage.
func ExtSSHKeyFile(configDir, id string) string {
	return filepath.Join(configDir, "extstorage", id+".key")
}

// WriteExtCredFile writes the mount.cifs credentials file (0600, never on
// argv) for an SMB storage.
func WriteExtCredFile(configDir string, es *config.ExternalStorage) error {
	dir, err := extstorageSecretsDir(configDir)
	if err != nil {
		return err
	}
	content := "username=" + es.Username + "\npassword=" + es.Password + "\n"
	if es.Domain != "" {
		content += "domain=" + es.Domain + "\n"
	}
	return os.WriteFile(filepath.Join(dir, es.ID+".cred"), []byte(content), 0600)
}

// WriteExtSSHKey stores a pasted private key (0600).
func WriteExtSSHKey(configDir, id, key string) error {
	dir, err := extstorageSecretsDir(configDir)
	if err != nil {
		return err
	}
	if !strings.HasSuffix(key, "\n") {
		key += "\n" // OpenSSH refuses keys without a trailing newline
	}
	return os.WriteFile(filepath.Join(dir, id+".key"), []byte(key), 0600)
}

// RemoveExtSecrets deletes any credential material for a storage id.
func RemoveExtSecrets(configDir, id string) {
	os.Remove(ExtCredFile(configDir, id))  //nolint:errcheck
	os.Remove(ExtSSHKeyFile(configDir, id)) //nolint:errcheck
}

// extMountCmd builds the sudo mount command (argv list) + optional stdin
// payload for one storage. mountpoint is passed in so the connection tester
// can target a probe directory.
func extMountCmd(configDir string, es *config.ExternalStorage, mountpoint string) (argv []string, stdin string, err error) {
	extra := strings.TrimSpace(es.ExtraOpts)
	switch es.Type {
	case "smb":
		opts := "credentials=" + ExtCredFile(configDir, es.ID) + ",iocharset=utf8"
		if extra != "" {
			opts += "," + extra
		}
		share := strings.Trim(es.Share, "/\\")
		return []string{"sudo", "mount", "-t", "cifs", "//" + es.Host + "/" + share, mountpoint, "-o", opts}, "", nil
	case "nfs":
		// soft + timeo so a dead server degrades with I/O errors instead of
		// hanging rsync / the file browser forever (hard is the NFS default).
		opts := "soft,timeo=150,retrans=3"
		if extra != "" {
			opts += "," + extra
		}
		export := "/" + strings.TrimLeft(es.Share, "/")
		return []string{"sudo", "mount", "-t", "nfs", es.Host + ":" + export, mountpoint, "-o", opts}, "", nil
	case "ssh":
		port := es.Port
		if port == 0 {
			port = 22
		}
		base := es.Share
		if base == "" {
			base = "/"
		}
		opts := "StrictHostKeyChecking=accept-new,reconnect,ServerAliveInterval=15,ServerAliveCountMax=3"
		if es.SSHKey {
			opts += ",IdentityFile=" + ExtSSHKeyFile(configDir, es.ID)
		} else {
			opts += ",password_stdin"
			stdin = es.Password + "\n"
		}
		if extra != "" {
			opts += "," + extra
		}
		argv = []string{"sudo", "sshfs", "-p", fmt.Sprint(port),
			es.Username + "@" + es.Host + ":" + base, mountpoint, "-o", opts}
		return argv, stdin, nil
	case "ftp":
		hostPort := es.Host
		if es.Port != 0 && es.Port != 21 {
			hostPort += fmt.Sprintf(":%d", es.Port)
		}
		base := strings.TrimLeft(es.Share, "/")
		url := "ftp://" + hostPort + "/" + base
		// curlftpfs has no credentials-file mechanism; user:pass ride the
		// option string (visible in local `ps` — surfaced as an info-tip in
		// the UI; acceptable on a single-admin appliance).
		opts := "user=" + es.Username + ":" + es.Password + ",utf8"
		if extra != "" {
			opts += "," + extra
		}
		return []string{"sudo", "curlftpfs", url, mountpoint, "-o", opts}, "", nil
	}
	return nil, "", fmt.Errorf("unknown storage type %q", es.Type)
}

// ExtMount ensures the storage is mounted at its canonical mountpoint.
// Idempotent — returns nil when already mounted.
func ExtMount(configDir string, es *config.ExternalStorage) error {
	if !ValidExtID(es.ID) {
		return fmt.Errorf("invalid storage id")
	}
	mp := ExtMountpoint(es.ID)
	if pathIsMountpoint(mp) {
		ExtTouch(es.ID)
		return nil
	}
	if err := extMountAt(configDir, es, mp); err != nil {
		return err
	}
	ExtTouch(es.ID)
	return nil
}

func extMountAt(configDir string, es *config.ExternalStorage, mp string) error {
	if out, err := exec.Command("sudo", "mkdir", "-p", mp).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir mountpoint: %s", firstLine(string(out), err))
	}
	// Refresh secrets on every mount so credential edits take effect without
	// a separate "apply" step.
	if es.Type == "smb" {
		if err := WriteExtCredFile(configDir, es); err != nil {
			return fmt.Errorf("write credentials: %v", err)
		}
	}
	argv, stdin, err := extMountCmd(configDir, es, mp)
	if err != nil {
		return err
	}
	// A dead host must not hang the HTTP handler: 30 s hard cap.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("mount timed out after 30s — host unreachable?")
	}
	if err != nil {
		return fmt.Errorf("mount failed: %s", firstLine(string(out), err))
	}
	return nil
}

// ExtUnmount unmounts a storage. When force is true a lazy unmount (-l) is
// used so a hung remote can always be detached.
func ExtUnmount(id string, force bool) error {
	if !ValidExtID(id) {
		return fmt.Errorf("invalid storage id")
	}
	mp := ExtMountpoint(id)
	if !pathIsMountpoint(mp) {
		return nil
	}
	args := []string{"umount"}
	if force {
		args = append(args, "-l")
	}
	args = append(args, mp)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount: %s", firstLine(string(out), err))
	}
	return nil
}

// ExtTestConnection mounts the storage at a temporary probe mountpoint,
// lists the top level, and unmounts. Returns a small sample of entry names
// so the UI can show "connected — found N entries".
func ExtTestConnection(configDir string, es *config.ExternalStorage) ([]string, error) {
	if es.ID == "" {
		es.ID = "probe" // credentials file name for unsaved storages
	}
	if !ValidExtID(es.ID) {
		return nil, fmt.Errorf("invalid storage id")
	}
	mp := filepath.Join(ExtMountBase, ".probe-"+es.ID)
	_ = ExtUnmountPath(mp) // stale probe from a previous crash
	if err := extMountAt(configDir, es, mp); err != nil {
		return nil, err
	}
	defer func() {
		_ = ExtUnmountPath(mp)
		exec.Command("sudo", "rmdir", mp).Run() //nolint:errcheck
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sudo", "find", mp, "-mindepth", "1", "-maxdepth", "1", "-printf", "%f\\n").Output()
	if err != nil {
		return nil, fmt.Errorf("connected but listing failed: %v", err)
	}
	names := []string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			names = append(names, l)
		}
		if len(names) >= 8 {
			break
		}
	}
	return names, nil
}

// ExtListDirs ensures the storage is mounted, then lists directories under
// its mountpoint up to `depth` levels deep (relative paths, sorted, capped at
// `limit`). Backs the sync modal's remote-folder picker.
func ExtListDirs(configDir string, es *config.ExternalStorage, depth, limit int) ([]string, error) {
	if err := ExtMount(configDir, es); err != nil {
		return nil, err
	}
	mp := ExtMountpoint(es.ID)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "sudo", "find", mp,
		"-mindepth", "1", "-maxdepth", strconv.Itoa(depth),
		"-type", "d", "-printf", "%P\n").Output()
	// find exits non-zero when any subdirectory is unreadable but still
	// prints the rest — only fail when we got nothing at all.
	if err != nil && len(out) == 0 {
		return nil, fmt.Errorf("could not list the remote share: %v", err)
	}
	dirs := []string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l != "" {
			dirs = append(dirs, l)
		}
	}
	sort.Strings(dirs)
	if len(dirs) > limit {
		dirs = dirs[:limit]
	}
	return dirs, nil
}

// ExtUnmountPath unmounts an arbitrary path under ExtMountBase (probe dirs).
func ExtUnmountPath(mp string) error {
	if !strings.HasPrefix(mp, ExtMountBase+"/") || !pathIsMountpoint(mp) {
		return nil
	}
	out, err := exec.Command("sudo", "umount", "-l", mp).CombinedOutput()
	if err != nil {
		return fmt.Errorf("umount: %s", firstLine(string(out), err))
	}
	return nil
}

// MountAllPersistent mounts every persistent-mode storage. Called from
// main.go at startup (and after config edits). Errors are logged by the
// caller per storage; a dead remote must not block the others.
func MountAllPersistent(configDir string, storages []config.ExternalStorage) map[string]error {
	errs := map[string]error{}
	for i := range storages {
		es := &storages[i]
		if es.MountMode != "persistent" {
			continue
		}
		if err := ExtMount(configDir, es); err != nil {
			errs[es.ID] = err
		}
	}
	return errs
}

// StartExtMountJanitor unmounts idle on-demand mounts once a minute.
// getStorages returns the current storage list (reads live config);
// rsyncActive reports whether a storage currently has a running rsync job.
func StartExtMountJanitor(getStorages func() []config.ExternalStorage, rsyncActive func(id string) bool) {
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for range tick.C {
			for _, es := range getStorages() {
				if es.MountMode == "persistent" || !ExtIsMounted(es.ID) {
					continue
				}
				if rsyncActive(es.ID) {
					ExtTouch(es.ID)
					continue
				}
				extMu.Lock()
				last, ok := extLastUsed[es.ID]
				extMu.Unlock()
				if ok && time.Since(last) < extIdleTimeout {
					continue
				}
				// Plain (non-lazy) umount: if something is holding files
				// open the kernel refuses and we simply retry next tick.
				exec.Command("sudo", "umount", ExtMountpoint(es.ID)).Run() //nolint:errcheck
			}
		}
	}()
}

// ── File-browser integration ─────────────────────────────────────────────────

// extSource returns the current external-storage list. Registered from
// handlers at startup (SetExtStorageSource) so ResolveKnownRoots can expose
// mounted storages as file-browser roots without an import cycle.
var extSource func() []config.ExternalStorage

// SetExtStorageSource registers the live storage-list getter.
func SetExtStorageSource(f func() []config.ExternalStorage) { extSource = f }

// extKnownRoots returns mountpoint→label for every currently mounted
// external storage.
func extKnownRoots() map[string]string {
	out := map[string]string{}
	if extSource == nil {
		return out
	}
	for _, es := range extSource() {
		if ExtIsMounted(es.ID) {
			out[ExtMountpoint(es.ID)] = "Ext: " + es.Name
		}
	}
	return out
}

// ── Prerequisite binaries ─────────────────────────────────────────────────────

// extTypeBinaries maps storage type → helper binary + Debian package.
var extTypeBinaries = map[string][2]string{
	"smb":   {"mount.cifs", "cifs-utils"},
	"nfs":   {"mount.nfs", "nfs-common"},
	"ssh":   {"sshfs", "sshfs"},
	"ftp":   {"curlftpfs", "curlftpfs"},
	"rsync": {"rsync", "rsync"},
}

// ExtStoragePrereqs reports which helper binaries are present.
// Keys: smb, nfs, ssh, ftp, rsync. Uses the sticky binaryPresent check
// (LookPath + common bin-dir scan) so fork-starvation under load can never
// flip a feature to "missing".
func ExtStoragePrereqs() map[string]bool {
	out := map[string]bool{}
	for typ, bp := range extTypeBinaries {
		out[typ] = binaryPresent(bp[0])
	}
	return out
}

// ExtPackageForType returns the Debian package that provides a type's helper.
func ExtPackageForType(typ string) string {
	if bp, ok := extTypeBinaries[typ]; ok {
		return bp[1]
	}
	return ""
}

// ExtInstallPackage installs the helper package for one storage type via apt
// (covered by the existing ZFSNAS_APT sudoers alias).
func ExtInstallPackage(typ string) (string, error) {
	pkg := ExtPackageForType(typ)
	if pkg == "" {
		return "", fmt.Errorf("unknown type %q", typ)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sudo", "env", "DEBIAN_FRONTEND=noninteractive",
		"apt-get", "install", "-y", pkg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("apt-get install %s: %v", pkg, err)
	}
	return string(out), nil
}

// firstLine condenses command output for error messages, falling back to the
// raw exec error when the command printed nothing.
func firstLine(out string, err error) string {
	out = strings.TrimSpace(out)
	if out == "" {
		return err.Error()
	}
	if i := strings.IndexByte(out, '\n'); i > 0 {
		out = out[:i]
	}
	return out
}
