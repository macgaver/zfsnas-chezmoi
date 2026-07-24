package system

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	smbConfPath          = "/etc/samba/smb.conf"
	smbBeginMarker       = "# ===== ZFS NAS MANAGED SHARES BEGIN ====="
	smbEndMarker         = "# ===== ZFS NAS MANAGED SHARES END ====="
	smbGlobalBeginMarker = "# ===== ZFS NAS MANAGED GLOBAL BEGIN ====="
	smbGlobalEndMarker   = "# ===== ZFS NAS MANAGED GLOBAL END ====="
)

// SMBUserAccess represents a user's access level for an SMB share.
type SMBUserAccess struct {
	Username string `json:"username"`
	ReadOnly bool   `json:"read_only"` // false = read-write (default)
}

// SMBShare represents a Samba file share.
type SMBShare struct {
	Name       string          `json:"name"`
	Path       string          `json:"path"`
	Comment    string          `json:"comment"`
	Browseable bool            `json:"browseable"`
	ReadOnly   bool            `json:"read_only"`
	ValidUsers []SMBUserAccess `json:"valid_users"`
	GuestOK    bool            `json:"guest_ok"`

	// Time Machine
	TimeMachine bool `json:"time_machine"`
	TMQuotaGB   int  `json:"tm_quota_gb"` // 0 = unlimited

	// Recycle Bin
	RecycleBin        bool `json:"recycle_bin"`
	RecycleRetainDays int  `json:"recycle_retain_days"` // 0 = keep forever

	// SMB2/3 Durable Handles (posix locking = no)
	DurableHandles bool `json:"durable_handles"`

	// Apple-style character encoding (vfs catia)
	AppleEncoding bool `json:"apple_encoding"`

	// Windows ACL compatibility (native ZFS NFSv4 ACLs surfaced to Windows via
	// the zfsacl VFS module + nfs4:* mapping params; dataset set to acltype=nfsv4)
	WindowsACL bool `json:"windows_acl"`

	// Shadow Copy (VSS Previous Versions via vfs_shadow_copy2)
	ShadowCopy       bool   `json:"shadow_copy"`
	ShadowCopyFormat string `json:"shadow_copy_format,omitempty"` // strftime format for shadow:format; default auto-%Y%m%d-%H%M%S

	// Host access control
	AllowedHosts string `json:"allowed_hosts"` // space-separated IPs/hostnames/subnets
	HostsDeny    string `json:"hosts_deny"`

	// Availability — when true, the share is written with "available = no" in smb.conf
	// so Samba refuses connections but the service keeps running for other shares.
	Disabled bool `json:"disabled,omitempty"`
}

// UnmarshalJSON for SMBShare handles migration from the old []string valid_users
// format (where each entry was a plain username) to the new []SMBUserAccess format.
func (s *SMBShare) UnmarshalJSON(data []byte) error {
	type SMBShareAlias SMBShare
	type rawShare struct {
		SMBShareAlias
		ValidUsers json.RawMessage `json:"valid_users"`
	}
	var raw rawShare
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = SMBShare(raw.SMBShareAlias)
	if len(raw.ValidUsers) == 0 || string(raw.ValidUsers) == "null" {
		return nil
	}
	// Try new format first.
	var newFmt []SMBUserAccess
	if err := json.Unmarshal(raw.ValidUsers, &newFmt); err == nil {
		s.ValidUsers = newFmt
		return nil
	}
	// Fall back to old []string format.
	var oldFmt []string
	if err := json.Unmarshal(raw.ValidUsers, &oldFmt); err == nil {
		for _, name := range oldFmt {
			s.ValidUsers = append(s.ValidUsers, SMBUserAccess{Username: name, ReadOnly: false})
		}
	}
	return nil
}

func smbSharesPath(configDir string) string {
	return filepath.Join(configDir, "shares.json")
}

// ListSMBShares returns all configured SMB shares from the JSON store.
func ListSMBShares(configDir string) ([]SMBShare, error) {
	data, err := os.ReadFile(smbSharesPath(configDir))
	if os.IsNotExist(err) {
		return []SMBShare{}, nil
	}
	if err != nil {
		return nil, err
	}
	var shares []SMBShare
	if err := json.Unmarshal(data, &shares); err != nil {
		return nil, err
	}
	if shares == nil {
		return []SMBShare{}, nil
	}
	return shares, nil
}

// SaveSMBShares persists shares to JSON and applies them to smb.conf.
func SaveSMBShares(configDir string, shares []SMBShare) error {
	data, err := json.MarshalIndent(shares, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(smbSharesPath(configDir), data, 0640); err != nil {
		return err
	}
	return applySMBConf(shares)
}

// stripManagedSection removes every occurrence of a begin…end marked block from
// conf, including any trailing newline that immediately follows the end marker.
// If a begin marker exists without a matching end marker the content from the
// begin marker to the end of the string is also removed.
func stripManagedSection(conf, beginMarker, endMarker string) string {
	for {
		begin := strings.Index(conf, beginMarker)
		if begin < 0 {
			break
		}
		end := strings.Index(conf[begin:], endMarker)
		if end < 0 {
			// Orphaned begin with no end — trim to begin.
			conf = conf[:begin]
			break
		}
		end += begin + len(endMarker)
		// Consume one trailing newline so we don't leave a blank line behind.
		if end < len(conf) && conf[end] == '\n' {
			end++
		}
		conf = conf[:begin] + conf[end:]
	}
	return conf
}

// collapseToLastOccurrence keeps only the last complete begin…end block in conf
// and removes all earlier copies.  When there is only one (or zero) occurrence
// the string is returned unchanged.
func collapseToLastOccurrence(conf, beginMarker, endMarker string) string {
	lastBegin := strings.LastIndex(conf, beginMarker)
	if lastBegin < 0 {
		return conf // no managed section present
	}
	lastEnd := strings.LastIndex(conf, endMarker)
	if lastEnd <= lastBegin {
		return conf // malformed — leave untouched
	}
	sectionEnd := lastEnd + len(endMarker)
	if sectionEnd < len(conf) && conf[sectionEnd] == '\n' {
		sectionEnd++
	}
	// Count occurrences — nothing to do when there is only one.
	if strings.Index(conf, beginMarker) == lastBegin {
		return conf
	}
	canonical := conf[lastBegin:sectionEnd]
	conf = stripManagedSection(conf, beginMarker, endMarker)
	return strings.TrimRight(conf, "\n") + "\n\n" + canonical
}

// DeduplicateSMBConf collapses any duplicate managed sections that may have
// accumulated in smb.conf from older versions of the software.  It keeps the
// last (most-recently written) copy of each section and is safe to call when
// there are zero or one copies already present.
func DeduplicateSMBConf() error {
	existing, err := os.ReadFile(smbConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read smb.conf: %w", err)
	}
	conf := collapseToLastOccurrence(string(existing), smbBeginMarker, smbEndMarker)
	conf = collapseToLastOccurrence(conf, smbGlobalBeginMarker, smbGlobalEndMarker)
	return writeFileSudo(smbConfPath, conf)
}

// removeShareDuplicatesOutsideManaged scans conf line-by-line and removes any
// [sharename] section that exists OUTSIDE the managed shares block and whose
// name matches one of the provided shares.  This cleans up stale hand-written
// or previously-leaked share entries so each share appears exactly once.
func removeShareDuplicatesOutsideManaged(conf string, shares []SMBShare) string {
	names := make(map[string]bool, len(shares))
	for _, s := range shares {
		names[strings.ToLower(s.Name)] = true
	}

	lines := strings.Split(conf, "\n")
	var out strings.Builder
	inManaged := false
	inDrop := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track all managed section boundaries (shares and global).
		if strings.Contains(line, smbBeginMarker) || strings.Contains(line, smbGlobalBeginMarker) {
			inManaged = true
			inDrop = false
			out.WriteString(line + "\n")
			continue
		}
		if strings.Contains(line, smbEndMarker) || strings.Contains(line, smbGlobalEndMarker) {
			inManaged = false
			out.WriteString(line + "\n")
			continue
		}

		// Inside a managed block — always keep as-is.
		if inManaged {
			out.WriteString(line + "\n")
			continue
		}

		// Outside managed blocks: detect section headers.
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section := strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			inDrop = names[section]
		}

		if !inDrop {
			out.WriteString(line + "\n")
		}
	}

	result := strings.ReplaceAll(out.String(), "\n\n\n", "\n\n")
	return strings.TrimSuffix(result, "\n")
}

// renderManagedShares builds the managed shares block that gets written into
// /etc/samba/smb.conf. Kept a pure function so the emitted directives — in
// particular the VFS module stack — are unit-testable without touching /etc.
func renderManagedShares(shares []SMBShare) string {
	var sb strings.Builder
	sb.WriteString(smbBeginMarker + "\n")
	for _, s := range shares {
		sb.WriteString(fmt.Sprintf("\n[%s]\n", s.Name))
		// Always write the available line so the value is explicit in the file.
		// Samba needs an explicit "available = yes" (not just absence of "no")
		// to reliably un-hide a share that was previously marked unavailable.
		if s.Disabled {
			sb.WriteString("   available = no\n")
		} else {
			sb.WriteString("   available = yes\n")
		}
		if s.Comment != "" {
			sb.WriteString("   comment = " + s.Comment + "\n")
		}
		sb.WriteString("   path = " + s.Path + "\n")
		sb.WriteString("   browseable = " + boolSMB(s.Browseable) + "\n")
		sb.WriteString("   read only = " + boolSMB(s.ReadOnly) + "\n")
		sb.WriteString("   guest ok = " + boolSMB(s.GuestOK) + "\n")
		if len(s.ValidUsers) > 0 {
			var names, readList, writeList []string
			for _, u := range s.ValidUsers {
				names = append(names, u.Username)
				if u.ReadOnly {
					readList = append(readList, u.Username)
				} else {
					writeList = append(writeList, u.Username)
				}
			}
			sb.WriteString("   valid users = " + strings.Join(names, " ") + "\n")
			if len(readList) > 0 {
				sb.WriteString("   read list = " + strings.Join(readList, " ") + "\n")
			}
			if len(writeList) > 0 {
				sb.WriteString("   write list = " + strings.Join(writeList, " ") + "\n")
			}
		}
		if s.WindowsACL {
			sb.WriteString("   create mask = 0744\n")
		} else {
			sb.WriteString("   create mask = 0664\n")
		}
		sb.WriteString("   directory mask = 0775\n")
		sb.WriteString("   force group = sambashare\n")

		// SMB2/3 Durable Handles — requires posix locking = no
		if s.DurableHandles {
			sb.WriteString("   posix locking = no\n")
		}

		// Host access control
		if s.AllowedHosts != "" {
			sb.WriteString("   hosts allow = " + s.AllowedHosts + "\n")
		}
		if s.HostsDeny != "" {
			sb.WriteString("   hosts deny = " + s.HostsDeny + "\n")
		}

		// VFS objects (combine as needed; shadow_copy2 must be first)
		var vfsObjs []string
		if s.ShadowCopy {
			vfsObjs = append(vfsObjs, "shadow_copy2")
		}
		if s.AppleEncoding {
			vfsObjs = append(vfsObjs, "catia")
		}
		if s.RecycleBin {
			vfsObjs = append(vfsObjs, "recycle")
		}
		// NB: the Windows ACL option deliberately stacks NO ACL VFS module.
		// zfsacl does not exist on Debian/Ubuntu (shares refused all
		// connections), and nfs4acl_xattr imposes NFSv4 DELETE semantics whose
		// POSIX-synthesized ACL withholds delete from non-owners — so a second
		// user with full write could not move/rename/delete another user's
		// files. With no module, Samba governs delete by POSIX directory write
		// like every other share. See smb_windows_acl_test.go.
		if s.TimeMachine || s.WindowsACL || s.AppleEncoding {
			vfsObjs = append(vfsObjs, "fruit", "streams_xattr")
		}
		if len(vfsObjs) > 0 {
			sb.WriteString("   vfs objects = " + strings.Join(vfsObjs, " ") + "\n")
		}
		// Shadow copy parameters
		if s.ShadowCopy {
			shadowFmt := s.ShadowCopyFormat
			if shadowFmt == "" {
				shadowFmt = "auto-%Y%m%d-%H%M%S"
			}
			sb.WriteString("   shadow:snapdir = .zfs/snapshot\n")
			sb.WriteString("   shadow:sort = desc\n")
			sb.WriteString("   shadow:format = " + shadowFmt + "\n")
			sb.WriteString("   shadow:localtime = no\n")
		}

		// Windows ACL compatibility — ensures executables keep the execute bit.
		// No ACL VFS module or nfs4:* wiring is emitted on purpose (see the
		// note by the vfs objects block above): those enforce NFSv4 DELETE
		// semantics that block cross-user move/rename/delete.
		if s.WindowsACL {
			sb.WriteString("   force create mode = 0755\n")
		}

		// Apple-style character encoding (catia) + fruit settings for macOS
		// extended-attribute compatibility (prevents read-only errors on macOS).
		if s.AppleEncoding {
			sb.WriteString("   catia:mappings = 0x22:0xf022,0x2a:0xf02a,0x2f:0xf02f,0x3a:0xf03a,0x3c:0xf03c,0x3e:0xf03e,0x3f:0xf03f,0x5c:0xf05c,0x7c:0xf07c\n")
			sb.WriteString("   fruit:aapl = yes\n")
			sb.WriteString("   fruit:nfs_aces = no\n")
			sb.WriteString("   fruit:metadata = stream\n")
			sb.WriteString("   fruit:encoding = native\n")
		}

		// Recycle Bin
		if s.RecycleBin {
			sb.WriteString("   recycle:repository = .recycle\n")
			sb.WriteString("   recycle:keeptree = yes\n")
			sb.WriteString("   recycle:versions = yes\n")
			sb.WriteString("   recycle:touch = yes\n")
			sb.WriteString("   recycle:directory_mode = 2770\n")
			sb.WriteString("   recycle:subdir_mode = 2770\n")
			sb.WriteString("   recycle:maxsize = 0\n")
		}

		// Time Machine
		if s.TimeMachine {
			sb.WriteString("   fruit:time machine = yes\n")
			if s.TMQuotaGB > 0 {
				sb.WriteString(fmt.Sprintf("   fruit:time machine max size = %dG\n", s.TMQuotaGB))
			}
		}
	}
	sb.WriteString("\n" + smbEndMarker + "\n")
	return sb.String()
}

// stripZfsaclVFSObject removes the zfsacl module from every "vfs objects" line
// in conf, leaving the rest of the file byte-identical. Versions 6.7.15–6.7.22
// wrote "vfs objects = zfsacl …" for Windows ACL shares; zfsacl.so does not
// exist on Debian or Ubuntu, so smbd answered tree connects to those shares
// with NT_STATUS_BAD_NETWORK_NAME.
//
// The managed block is regenerated from shares.json on every startup and so
// heals itself, but a stale zfsacl can also sit OUTSIDE the managed markers —
// in a hand-written share, or in a managed block whose markers were damaged.
// Those copies would keep breaking their shares forever, hence this pass.
func stripZfsaclVFSObject(conf string) string {
	lines := strings.Split(conf, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		key, value, ok := strings.Cut(line, "=")
		// Normalize whitespace/case so "VFS OBJECTS", "vfs objects" and
		// "vfs  objects" all match, then require an exact parameter match so
		// a [zfsacl] share or a path containing the word is never touched.
		if !ok || strings.Join(strings.Fields(strings.ToLower(key)), " ") != "vfs objects" {
			out = append(out, line)
			continue
		}
		kept := make([]string, 0, len(strings.Fields(value)))
		var found bool
		for _, mod := range strings.Fields(value) {
			if strings.EqualFold(mod, "zfsacl") {
				found = true
				continue
			}
			kept = append(kept, mod)
		}
		if !found {
			out = append(out, line)
			continue
		}
		if len(kept) == 0 {
			// zfsacl was the only module — drop the line entirely rather than
			// leave an empty "vfs objects =" for Samba to complain about.
			continue
		}
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
		out = append(out, indent+strings.TrimSpace(key)+" = "+strings.Join(kept, " "))
	}
	return strings.Join(out, "\n")
}

// RepairSMBConfZfsacl rewrites /etc/samba/smb.conf if it still references the
// unloadable zfsacl VFS module. Safe to run on every startup: it is a no-op
// (no write at all) when the file is already clean.
func RepairSMBConfZfsacl() error {
	existing, err := os.ReadFile(smbConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read smb.conf: %w", err)
	}
	repaired := stripZfsaclVFSObject(string(existing))
	if repaired == string(existing) {
		return nil
	}
	log.Printf("smb.conf: removing unloadable zfsacl VFS module (shares using it refused all connections)")
	return writeFileSudo(smbConfPath, repaired)
}

// applySMBConf writes the managed section into /etc/samba/smb.conf.
func applySMBConf(shares []SMBShare) error {
	managed := renderManagedShares(shares)

	// Read existing smb.conf (readable without sudo on most systems).
	existing, err := os.ReadFile(smbConfPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read smb.conf: %w", err)
	}
	conf := string(existing)

	// Strip all existing managed-shares sections (handles first-write and duplicates).
	conf = stripManagedSection(conf, smbBeginMarker, smbEndMarker)
	newConf := strings.TrimRight(conf, "\n") + "\n\n" + managed

	// Remove any stray [sharename] sections outside the managed block so that
	// each share appears exactly once in the file.
	newConf = removeShareDuplicatesOutsideManaged(newConf, shares)

	// If the managed global section is not yet in the file, seed it now with
	// the default value (100) so the parameter is always present from the
	// moment the first share is configured.
	if !strings.Contains(newConf, smbGlobalBeginMarker) {
		global := fmt.Sprintf("%s\n[global]\n   max smbd processes = 100\n   workgroup = WORKGROUP\n%s\n",
			smbGlobalBeginMarker, smbGlobalEndMarker)
		newConf = strings.TrimRight(newConf, "\n") + "\n\n" + global
	}

	// Comment out any [global] section outside the managed block so our block wins.
	newConf = removeSectionsOutsideManaged(newConf, smbGlobalBeginMarker, smbGlobalEndMarker,
		nil, []string{"global"})

	return writeFileSudo(smbConfPath, newConf)
}

// ApplySmbGlobal writes a managed block into smb.conf that contains the
// [global] performance parameters and, when homeDataset is non-empty and
// homeUsers is non-empty, a [homes] section restricted to those users.
// Samba merges multiple [global] sections (later values win), so this block
// is safe alongside the distro-written [global].
// When cleanDefaults is true the distro-default [homes], [printers], and
// [print$] sections outside the managed block are commented out.
func ApplySmbGlobal(configDir string, maxSmbdProcesses int, workgroup string, customGlobal string, homeDataset string, homeUsers []string, cleanDefaults bool, socketOptions bool) error {
	if workgroup == "" {
		workgroup = "WORKGROUP"
	}
	var sb strings.Builder
	sb.WriteString(smbGlobalBeginMarker + "\n")
	sb.WriteString(fmt.Sprintf("[global]\n   max smbd processes = %d\n   workgroup = %s\n", maxSmbdProcesses, workgroup))

	if socketOptions {
		sb.WriteString("   socket options = TCP_NODELAY IPTOS_THROUGHPUT SO_RCVBUF=131072 SO_SNDBUF=131072\n")
	}

	// Append expert-supplied custom lines, filtering out section headers to prevent
	// injection of new sections inside our managed block.
	if customGlobal != "" {
		for _, line := range strings.Split(customGlobal, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			// Skip any line that looks like a section header — those belong outside [global].
			if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
				continue
			}
			sb.WriteString("   " + trimmed + "\n")
		}
	}

	if homeDataset != "" && len(homeUsers) > 0 {
		mountpoint := datasetMountpoint(homeDataset)
		if mountpoint != "" {
			sb.WriteString("\n[homes]\n")
			sb.WriteString("   comment = User Home Directories\n")
			sb.WriteString(fmt.Sprintf("   path = %s/%%U\n", mountpoint))
			sb.WriteString("   valid users = " + strings.Join(homeUsers, " ") + "\n")
			sb.WriteString("   read only = no\n")
			sb.WriteString("   browseable = no\n")
			sb.WriteString("   create mask = 0700\n")
			sb.WriteString("   directory mask = 0700\n")
		}
	}
	sb.WriteString(smbGlobalEndMarker + "\n")
	managed := sb.String()

	existing, err := os.ReadFile(smbConfPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read smb.conf: %w", err)
	}
	conf := string(existing)

	// Strip all existing managed-global sections (handles first-write and duplicates).
	conf = stripManagedSection(conf, smbGlobalBeginMarker, smbGlobalEndMarker)
	newConf := strings.TrimRight(conf, "\n") + "\n\n" + managed

	// Always comment out any [global] section outside the managed block so that
	// our managed [global] is the only active one.  This also silences any
	// conflicting workgroup= or other parameters set by the distro installer.
	commentOut := []string{"global"}
	removeOut := []string(nil)
	if cleanDefaults {
		removeOut = []string{"printers", "print$"}
		commentOut = append(commentOut, "homes")
	} else if homeDataset != "" {
		commentOut = append(commentOut, "homes")
	}
	newConf = removeSectionsOutsideManaged(newConf, smbGlobalBeginMarker, smbGlobalEndMarker,
		removeOut, commentOut)

	// Remove any stray [sharename] sections outside the managed shares block so
	// that each share appears exactly once.  This runs on every Configure save,
	// not just on share edits.
	if shares, err := ListSMBShares(configDir); err == nil && len(shares) > 0 {
		newConf = removeShareDuplicatesOutsideManaged(newConf, shares)
	}

	return writeFileSudo(smbConfPath, newConf)
}

// removeSectionsOutsideManaged scans conf line-by-line and deletes any section
// in removeSections that lies outside the managed markers. The section header
// and all its content lines are omitted from the output.
// Sections in commentSections are commented out with "; " instead of deleted.
// ExtractExternalGlobalParams reads smb.conf and returns the active (non-commented)
// parameter lines found inside [global] sections that lie OUTSIDE the ZFS NAS
// managed block.  Lines whose key is already managed by ZFS NAS (workgroup,
// max smbd processes) are skipped so they are not duplicated in the textarea.
// The result is suitable for merging into SMBCustomGlobal before the external
// [global] is commented out.
func ExtractExternalGlobalParams() (string, error) {
	existing, err := os.ReadFile(smbConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("read smb.conf: %w", err)
	}

	// Keys that ZFS NAS manages directly — never migrate these.
	ownedKeys := map[string]bool{
		"max smbd processes": true,
		"workgroup":          true,
	}

	lines := strings.Split(string(existing), "\n")
	var out strings.Builder
	inManaged := false
	inGlobal := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track managed section boundaries.
		if strings.Contains(line, smbBeginMarker) || strings.Contains(line, smbGlobalBeginMarker) {
			inManaged = true
			inGlobal = false
			continue
		}
		if strings.Contains(line, smbEndMarker) || strings.Contains(line, smbGlobalEndMarker) {
			inManaged = false
			inGlobal = false
			continue
		}
		if inManaged {
			continue
		}

		// Only recognise ACTIVE section headers (not already commented out).
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			section := strings.ToLower(strings.TrimSpace(trimmed[1 : len(trimmed)-1]))
			inGlobal = section == "global"
			continue // never include the header line itself
		}

		if !inGlobal {
			continue
		}
		// Skip blank lines and comments.
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		// Skip keys ZFS NAS owns.
		if idx := strings.IndexByte(trimmed, '='); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(trimmed[:idx]))
			if ownedKeys[key] {
				continue
			}
		}
		out.WriteString(trimmed + "\n")
	}

	return strings.TrimSpace(out.String()), nil
}

func removeSectionsOutsideManaged(conf, managedBegin, managedEnd string, removeSections, commentSections []string) string {
	remove := make(map[string]bool, len(removeSections))
	comment := make(map[string]bool, len(commentSections))
	for _, s := range removeSections {
		remove[strings.ToLower(s)] = true
	}
	for _, s := range commentSections {
		comment[strings.ToLower(s)] = true
	}

	lines := strings.Split(conf, "\n")
	var out strings.Builder
	inManaged := false
	inRemove := false
	inComment := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(line, managedBegin) {
			inManaged = true
			inRemove = false
			inComment = false
			out.WriteString(line + "\n")
			continue
		}
		if strings.Contains(line, managedEnd) {
			inManaged = false
			out.WriteString(line + "\n")
			continue
		}
		if inManaged {
			out.WriteString(line + "\n")
			continue
		}
		// Outside managed block: detect section headers (active or commented-out, e.g. #[printers]).
		sectionLine := trimmed
		if strings.HasPrefix(sectionLine, "#") || strings.HasPrefix(sectionLine, ";") {
			sectionLine = strings.TrimLeft(sectionLine, "#; \t")
		}
		if strings.HasPrefix(sectionLine, "[") && strings.HasSuffix(sectionLine, "]") {
			section := strings.ToLower(strings.TrimSpace(sectionLine[1 : len(sectionLine)-1]))
			inRemove = remove[section]
			inComment = !inRemove && comment[section]
		}
		if inRemove {
			continue // delete this line entirely
		}
		if inComment && trimmed != "" && !strings.HasPrefix(trimmed, "#") && !strings.HasPrefix(trimmed, ";") {
			out.WriteString("; " + line + "\n")
		} else {
			out.WriteString(line + "\n")
		}
	}
	// Collapse runs of 3+ blank lines that removal may leave behind.
	result := strings.ReplaceAll(out.String(), "\n\n\n", "\n\n")
	return strings.TrimSuffix(result, "\n")
}

// datasetMountpoint returns the mountpoint of a ZFS dataset, or "" on error.
func datasetMountpoint(dataset string) string {
	out, err := exec.Command("sudo", "zfs", "get", "-H", "-o", "value", "mountpoint", dataset).Output()
	if err != nil {
		return ""
	}
	mp := strings.TrimSpace(string(out))
	if mp == "none" || mp == "-" || mp == "" {
		return ""
	}
	return mp
}

// EnsureSMBHomeDir creates <mountpoint>/<username>/ under the given ZFS dataset
// if it does not already exist, sets 0700 permissions, and chowns it to the user.
// It ensures the Linux system account exists first so that chown always succeeds.
func EnsureSMBHomeDir(dataset, username string) error {
	mountpoint := datasetMountpoint(dataset)
	if mountpoint == "" {
		return fmt.Errorf("cannot determine mountpoint for dataset %q", dataset)
	}

	// Ensure the Linux system account exists so chown works.
	if err := exec.Command("id", username).Run(); err != nil {
		out, err2 := exec.Command("sudo", "useradd",
			"-M",                      // no home directory managed by useradd
			"-s", "/usr/sbin/nologin", // no shell login
			username).CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("useradd %s: %s", username, strings.TrimSpace(string(out)))
		}
	}

	dir := mountpoint + "/" + username
	if out, err := exec.Command("mkdir", "-p", dir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir %s: %s", dir, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("chmod", "0700", dir).CombinedOutput(); err != nil {
		return fmt.Errorf("chmod %s: %s", dir, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("chown", username+":"+username, dir).CombinedOutput(); err != nil {
		return fmt.Errorf("chown %s: %s", dir, strings.TrimSpace(string(out)))
	}
	return nil
}

// RemoveSMBHomeDirIfEmpty removes <mountpoint>/<username>/ under the given ZFS
// dataset using rmdir, which silently succeeds only when the directory is empty.
func RemoveSMBHomeDirIfEmpty(dataset, username string) error {
	mountpoint := datasetMountpoint(dataset)
	if mountpoint == "" {
		return fmt.Errorf("cannot determine mountpoint for dataset %q", dataset)
	}
	dir := mountpoint + "/" + username
	out, err := exec.Command("rmdir", dir).CombinedOutput()
	if err != nil {
		// rmdir exits non-zero when the dir is non-empty or doesn't exist — both are fine.
		_ = out
	}
	return nil
}

// ReloadSamba reloads the Samba configuration without dropping connections.
// SetSMBShareDisabled marks a share as disabled or enabled in the JSON config
// and rewrites smb.conf. The caller is responsible for calling ReloadSamba()
// after all desired share changes have been applied.
func SetSMBShareDisabled(configDir, name string, disabled bool) error {
	shares, err := ListSMBShares(configDir)
	if err != nil {
		return err
	}
	for i := range shares {
		if shares[i].Name == name {
			shares[i].Disabled = disabled
			return SaveSMBShares(configDir, shares)
		}
	}
	return fmt.Errorf("SMB share not found: %s", name)
}

func ReloadSamba() error {
	out, err := exec.Command("sudo", "systemctl", "reload", "smbd").CombinedOutput()
	if err != nil {
		// Fall back to restart if reload fails (smbd not running yet).
		out2, err2 := exec.Command("sudo", "systemctl", "restart", "smbd").CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("%s / %s", strings.TrimSpace(string(out)), strings.TrimSpace(string(out2)))
		}
	}
	return nil
}

// RestartSamba performs a full restart of smbd. Required when changes affect
// virtual shares such as [homes] that are not picked up by a mere reload.
func RestartSamba() error {
	out, err := exec.Command("sudo", "systemctl", "restart", "smbd").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// IsSambaInstalled checks if the smbd binary is available.
func IsSambaInstalled() bool {
	return binaryInstalled("smbd")
}

// SambaStatus returns "active", "inactive", "unknown", or "not-installed".
//
// `systemctl is-active` prints the state word to stdout ("inactive", "failed",
// …) even when it exits non-zero for a genuinely-stopped service, so we trust
// any non-empty output. Empty output means the command never produced a verdict
// — almost always because the host is too busy to fork (load ~24 during a big
// zfs receive). In that case we return "unknown" rather than "inactive" so the
// UI shows a neutral "couldn't determine, busy" hint instead of a false
// "smbd is down" alarm. See feedback_high_load_false_negatives.
func SambaStatus() string {
	if !IsSambaInstalled() {
		return "not-installed"
	}
	out, _ := exec.Command("systemctl", "is-active", "smbd").Output()
	if state := strings.TrimSpace(string(out)); state != "" {
		return state
	}
	return "unknown"
}

// ControlSamba runs systemctl start/stop/restart on smbd (and nmbd if present).
func ControlSamba(action string) error {
	if action != "start" && action != "stop" && action != "restart" {
		return fmt.Errorf("invalid action: %s", action)
	}
	out, err := exec.Command("sudo", "systemctl", action, "smbd").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s smbd: %s", action, strings.TrimSpace(string(out)))
	}
	// nmbd (NetBIOS name service) is optional; ignore errors.
	_ = exec.Command("sudo", "systemctl", action, "nmbd").Run()
	return nil
}

// EnsureSambaUser creates a Linux system account (if absent) and sets its
// Samba password, making the user ready for SMB authentication.
// uid and gid are optional; pass nil for automatic assignment.
func EnsureSambaUser(username, password string, uid, gid *int) error {
	// Create a no-login Linux system account if it doesn't exist yet.
	// id exits 0 if user exists, non-zero otherwise.
	if err := exec.Command("id", username).Run(); err != nil {
		// When a specific GID is requested the group must exist before useradd
		// can reference it. Create it now (no-op if it already exists).
		if gid != nil {
			out, err2 := exec.Command("sudo", "groupadd", "-g", fmt.Sprintf("%d", *gid), username).CombinedOutput()
			if err2 != nil {
				msg := strings.TrimSpace(string(out))
				// Exit code 9 = group already exists — safe to ignore.
				if !strings.Contains(msg, "already exists") {
					return fmt.Errorf("groupadd: %s", msg)
				}
			}
		}

		args := []string{"-M", "-s", "/usr/sbin/nologin"}
		if uid != nil {
			args = append(args, "--uid", fmt.Sprintf("%d", *uid))
		}
		if gid != nil {
			// Group already exists; tell useradd not to create a new one.
			args = append(args, "--gid", fmt.Sprintf("%d", *gid), "--no-user-group")
		}
		args = append(args, username)
		out, err2 := exec.Command("sudo", append([]string{"useradd"}, args...)...).CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("useradd: %s", strings.TrimSpace(string(out)))
		}
	}

	// Ensure sambashare group exists, then add the user to it.
	ensureSambashareGroup()
	_ = exec.Command("sudo", "usermod", "-aG", "sambashare", username).Run()

	// Set / update the Samba password only when smbpasswd is available.
	smbpasswdPath, lookErr := exec.LookPath("smbpasswd")
	if lookErr == nil {
		cmd := exec.Command("sudo", smbpasswdPath, "-s", "-a", username)
		cmd.Stdin = strings.NewReader(password + "\n" + password + "\n")
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("smbpasswd: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// DeleteSambaUser removes the Samba password entry, the Linux system account,
// and the primary group for the given username.
func DeleteSambaUser(username string) error {
	// Remove from Samba password database. Non-fatal: user may never have had
	// an SMB password, or smbpasswd may not be installed.
	if smbpasswdPath, err := exec.LookPath("smbpasswd"); err == nil {
		if out, err := exec.Command("sudo", smbpasswdPath, "-x", username).CombinedOutput(); err != nil {
			log.Printf("smb: smbpasswd -x %s: %v: %s", username, err, strings.TrimSpace(string(out)))
		}
	}

	// First check if the Linux account actually exists; nothing to do if not.
	if exec.Command("id", username).Run() != nil {
		return nil
	}

	// Remove supplementary group memberships first so userdel has no blockers.
	_ = exec.Command("sudo", "gpasswd", "-d", username, "sambashare").Run()

	// Delete the Linux system account. -f forces removal even if the user is
	// currently logged in. We do NOT use -r because home directories under
	// ZFS datasets are managed separately.
	if out, err := exec.Command("sudo", "userdel", "-f", username).CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		if !strings.Contains(msg, "does not exist") {
			return fmt.Errorf("userdel %s: %s", username, msg)
		}
	}

	// Clean up the primary group (same name as user). userdel normally handles
	// this, but on some systems it is left behind — remove it explicitly.
	_ = exec.Command("sudo", "groupdel", username).Run()

	return nil
}

// UIDExistsOnSystem returns true if the given UID is already present in /etc/passwd.
func UIDExistsOnSystem(uid int) (bool, error) {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return false, fmt.Errorf("read /etc/passwd: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		// /etc/passwd format: name:pw:uid:gid:gecos:home:shell — uid is field index 2
		if len(parts) >= 4 && parts[2] == fmt.Sprintf("%d", uid) {
			return true, nil
		}
	}
	return false, nil
}

// GIDExistsOnSystem returns true if the given GID is already present in /etc/group.
func GIDExistsOnSystem(gid int) (bool, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return false, fmt.Errorf("read /etc/group: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		// /etc/group format: name:pw:gid:members — gid is field index 2
		if len(parts) >= 3 && parts[2] == fmt.Sprintf("%d", gid) {
			return true, nil
		}
	}
	return false, nil
}

// UsernameExistsOnSystem returns true if the given username is already present
// in /etc/passwd (covers root, system service accounts, and regular OS users).
func UsernameExistsOnSystem(username string) (bool, error) {
	_, _, exists, err := LookupSystemUser(username)
	return exists, err
}

// LookupSystemUser parses /etc/passwd and returns the UID and GID for username.
// exists is false (with no error) when the username is not present.
func LookupSystemUser(username string) (uid, gid int, exists bool, err error) {
	data, rerr := os.ReadFile("/etc/passwd")
	if rerr != nil {
		return 0, 0, false, fmt.Errorf("read /etc/passwd: %w", rerr)
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		// /etc/passwd format: name:pw:uid:gid:gecos:home:shell
		if len(parts) >= 4 && parts[0] == username {
			u, err1 := strconv.Atoi(parts[2])
			g, err2 := strconv.Atoi(parts[3])
			if err1 != nil || err2 != nil {
				return 0, 0, true, fmt.Errorf("malformed /etc/passwd entry for %s", username)
			}
			return u, g, true, nil
		}
	}
	return 0, 0, false, nil
}

// ensureSambashareGroup creates the sambashare group if it does not already
// exist. The Samba package creates this group on Debian/Ubuntu, but it may be
// absent on minimal installs or before Samba is fully set up.
func ensureSambashareGroup() {
	// getent exits 0 when the group exists.
	if exec.Command("getent", "group", "sambashare").Run() == nil {
		return
	}
	_ = exec.Command("sudo", "groupadd", "--system", "sambashare").Run()
}

// ChmodSharePath sets group=sambashare and permissions 0770 on the share
// directory so that SMB clients authenticating as sambashare members can
// read and write, with no access for other users.
func ChmodSharePath(path string) error {
	ensureSambashareGroup()
	if out, err := exec.Command("sudo", "chgrp", "sambashare", path).CombinedOutput(); err != nil {
		return fmt.Errorf("chgrp %s: %s", path, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "chmod", "0770", path).CombinedOutput(); err != nil {
		return fmt.Errorf("chmod %s: %s", path, strings.TrimSpace(string(out)))
	}
	return nil
}

// boolSMB converts a bool to Samba "yes"/"no".
func boolSMB(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// StartRecycleCleaner starts a goroutine that runs at 2 AM daily and removes
// files older than RecycleRetainDays from each share's .recycle directory.
// configDir is passed so it can reload shares dynamically each night.
func StartRecycleCleaner(configDir string) {
	go func() {
		for {
			now := time.Now()
			next := time.Date(now.Year(), now.Month(), now.Day(), 2, 0, 0, 0, now.Location())
			if !next.After(now) {
				next = next.Add(24 * time.Hour)
			}
			time.Sleep(time.Until(next))
			runRecycleCleaner(configDir)
		}
	}()
}

func runRecycleCleaner(configDir string) {
	shares, err := ListSMBShares(configDir)
	if err != nil {
		log.Printf("recycle cleaner: load shares: %v", err)
		return
	}
	for _, s := range shares {
		if !s.RecycleBin || s.RecycleRetainDays <= 0 {
			continue
		}
		recycleDir := filepath.Join(s.Path, ".recycle")
		cutoff := time.Now().AddDate(0, 0, -s.RecycleRetainDays)
		if err := cleanOlderThan(recycleDir, cutoff); err != nil {
			log.Printf("recycle cleaner: %s: %v", recycleDir, err)
		} else {
			log.Printf("recycle cleaner: cleaned %s (older than %d days)", recycleDir, s.RecycleRetainDays)
		}
	}
}

// CleanShareRecycleBin immediately runs the recycle-bin cleanup for a single
// named share, honouring its configured RecycleRetainDays.
func CleanShareRecycleBin(configDir, name string) error {
	shares, err := ListSMBShares(configDir)
	if err != nil {
		return err
	}
	for _, s := range shares {
		if !strings.EqualFold(s.Name, name) {
			continue
		}
		if !s.RecycleBin {
			return fmt.Errorf("share %q does not have a recycle bin configured", name)
		}
		if s.RecycleRetainDays <= 0 {
			return nil // no retention limit — nothing to prune
		}
		recycleDir := filepath.Join(s.Path, ".recycle")
		cutoff := time.Now().AddDate(0, 0, -s.RecycleRetainDays)
		return cleanOlderThan(recycleDir, cutoff)
	}
	return fmt.Errorf("share %q not found", name)
}

// cleanOlderThan removes files (and then empty directories) under dir whose
// mtime is before cutoff.  It uses sudo find so that it can delete files
// owned by arbitrary SMB users without the service account needing ownership.
func cleanOlderThan(dir string, cutoff time.Time) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	days := int(time.Since(cutoff).Hours() / 24)
	mtimeArg := "+" + strconv.Itoa(days)

	// Delete files (and symlinks) older than the cutoff.
	out, err := exec.Command("sudo", "find", dir,
		"-not", "-type", "d",
		"-mtime", mtimeArg,
		"-delete").CombinedOutput()
	if err != nil {
		return fmt.Errorf("find -delete files: %s", strings.TrimSpace(string(out)))
	}

	// Remove any directories that are now empty (ignore errors — best effort).
	_ = exec.Command("sudo", "find", dir,
		"-mindepth", "1", "-type", "d", "-empty", "-delete").Run()

	return nil
}

// ShareClient holds the IP address and optional reverse-DNS hostname of a
// connected SMB or NFS client.
type ShareClient struct {
	IP   string `json:"ip"`
	FQDN string `json:"fqdn,omitempty"`
}

// GetSMBSessions returns active Samba connections grouped by share name.
// It parses "smbstatus -S" output and performs a reverse-DNS lookup for each
// unique client IP.
func GetSMBSessions() map[string][]ShareClient {
	result := make(map[string][]ShareClient)
	out, err := exec.Command("sudo", "smbstatus", "-S").Output()
	if err != nil {
		return result
	}
	seen := make(map[string]map[string]bool)
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		svc := fields[0]
		// Skip the header line, separator lines, and the internal IPC$ service.
		if svc == "Service" || strings.HasPrefix(svc, "-") || svc == "IPC$" {
			continue
		}
		machine := fields[2]
		// Strip port suffix when present (e.g. "192.168.1.5:445").
		if h, _, e := net.SplitHostPort(machine); e == nil {
			machine = h
		}
		if seen[svc] == nil {
			seen[svc] = make(map[string]bool)
		}
		if seen[svc][machine] {
			continue
		}
		seen[svc][machine] = true
		result[svc] = append(result[svc], ShareClient{
			IP:   machine,
			FQDN: reverseLookup(machine),
		})
	}
	return result
}

// reverseLookup returns the first PTR record for ip, stripped of its trailing
// dot.  Returns "" when no record exists or DNS is unavailable.
// A 1-second timeout prevents slow/broken reverse-DNS from stalling the table.
func reverseLookup(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimRight(names[0], ".")
}

// FindDatasetByMountpoint returns the ZFS dataset name whose mountpoint exactly
// matches path. Returns ("", false) if no dataset is found.
func FindDatasetByMountpoint(path string) (string, bool) {
	out, err := exec.Command("sudo", "zfs", "list", "-H", "-o", "name,mountpoint", "-t", "filesystem").Output()
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[1]) == path {
			return strings.TrimSpace(parts[0]), true
		}
	}
	return "", false
}

// SetWindowsACLDatasetProps enables or disables Windows ACL-compatible ZFS
// properties on the dataset whose mountpoint matches path.
// On enable: sets acltype=nfsv4, aclinherit=passthrough, aclmode=passthrough, xattr=sa.
// On disable: resets those properties to their inherited pool defaults.
// If no ZFS dataset matches path (custom path scenario) the function returns nil.
func SetWindowsACLDatasetProps(path string, enable bool) error {
	ds, ok := FindDatasetByMountpoint(path)
	if !ok {
		return nil // custom path — no dataset to configure
	}
	if enable {
		return SetDatasetProps(ds, map[string]string{
			"acltype":    "nfsv4",
			"aclinherit": "passthrough",
			"aclmode":    "passthrough",
			"xattr":      "sa",
		})
	}
	// Reset to inherited pool defaults.
	for _, p := range []string{"acltype", "aclinherit", "aclmode", "xattr"} {
		out, err := exec.Command("sudo", "zfs", "inherit", p, ds).CombinedOutput()
		if err != nil {
			return fmt.Errorf("zfs inherit %s %s: %s", p, ds, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// writeFileSudo writes content to a path using sudo tee.
func writeFileSudo(path, content string) error {
	cmd := exec.Command("sudo", "tee", path)
	cmd.Stdin = strings.NewReader(content)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("write %s: %s", path, strings.TrimSpace(stderr.String()))
	}
	return nil
}
