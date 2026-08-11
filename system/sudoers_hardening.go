package system

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// experimentalSudoersAliases lists Cmnd_Aliases that are only required when
// the portal runs with --experimental (i.e. for the virtualization feature).
// When --experimental is off these sections are stripped from the required
// template (and from the trailing User_Alias spec), together with their
// preceding comment blocks, so a non-virtualization host never sees any
// virtualization-related command or explanation.
//
// NOTE: the one-time *install* of virtualization (ZFSNAS_VMSETUP, removed in
// v6.6.16) no longer has any sudoers entries: enabling the feature now requires
// full passwordless sudo ("sudo all"), so the install commands run under that
// grant and never need a dedicated hardened rule. Memory compression (zram /
// ZFSNAS_MEMCOMP) is part of the virtualization feature set and is gated here
// too, so its commands never appear on a host without virtualization enabled.
var experimentalSudoersAliases = map[string]bool{
	"ZFSNAS_MEMCOMP":  true, // zram memory compression — part of the virtualization feature
	"ZFSNAS_INCUSNET": true,
	"ZFSNAS_INCUS":    true,
	"ZFSNAS_SYNCOID":  true, // v6.5.19 — VM/Container Backup
}

// mergerfsSudoersAlias is gated independently of virtualization: present iff
// the MergerFS feature is installed (see RequiredSudoersContent).
var mergerfsSudoersAlias = map[string]bool{"ZFSNAS_MERGERFS": true}

// SudoersDiff is the result of comparing the installed sudoers file against
// the required template.
type SudoersDiff struct {
	UpToDate     bool              `json:"up_to_date"`
	FileExists   bool              `json:"file_exists"`
	MatchedLines []SudoersLineDiff `json:"matched_lines"` // in both required template and current file
	MissingLines []SudoersLineDiff `json:"missing_lines"`
	ExtraLines   []SudoersLineDiff `json:"extra_lines"`
}

// SudoersLineDiff describes a single logical sudoers command entry that differs.
type SudoersLineDiff struct {
	Line            string `json:"line"`
	Explanation     string `json:"explanation"`
	Section         string `json:"section"`          // Cmnd_Alias name, e.g. "ZFSNAS_SMB"
	SectionLabel    string `json:"section_label"`    // human-readable label
	SectionOptional bool   `json:"section_optional"` // true = optional feature
	Silenced        bool   `json:"silenced"`
	Forced          bool   `json:"forced,omitempty"` // always required; cannot be silenced or removed
}

type sudoersSectionInfo struct {
	Label    string
	Optional bool
}

var sudoersSectionInfoMap = map[string]sudoersSectionInfo{
	"ZFSNAS_ZFS":       {Label: "ZFS Pool & Dataset Management"},
	"ZFSNAS_SMB":       {Label: "Samba (SMB Shares)"},
	"ZFSNAS_NFS":       {Label: "NFS Shares"},
	"ZFSNAS_ISCSI":     {Label: "iSCSI Sharing", Optional: true},
	"ZFSNAS_MINIO":     {Label: "S3 Object Server (MinIO)", Optional: true},
	"ZFSNAS_UPS":       {Label: "UPS Management (NUT)", Optional: true},
	"ZFSNAS_DISKPOWER": {Label: "Disk Power Management", Optional: true},
	"ZFSNAS_SYSPOWER":  {Label: "System Power Management", Optional: true},
	"ZFSNAS_SMART":     {Label: "SMART & Hardware Monitoring"},
	"ZFSNAS_DISK":      {Label: "Disk Preparation & Wipe"},
	"ZFSNAS_SCAN":      {Label: "Folder Usage Scanning"},
	"ZFSNAS_FILES":     {Label: "File Browser"},
	"ZFSNAS_SYSTEM":    {Label: "System Management"},
	"ZFSNAS_JOURNAL":   {Label: "System Journal Log Viewer"},
	"ZFSNAS_NTP":       {Label: "Network Time (chrony NTP)", Optional: true},
	"ZFSNAS_MEMCOMP":   {Label: "Memory Compression (zram)", Optional: true},
	"ZFSNAS_INCUSNET":  {Label: "Incus Network Bridges (VLAN interfaces)", Optional: true},
	"ZFSNAS_INCUS":     {Label: "Incus Compute (Proxmox Import + ISO Management)", Optional: true},
	"ZFSNAS_SYNCOID":   {Label: "ZFS Replication (syncoid)", Optional: true},
	"ZFSNAS_MERGERFS":  {Label: "MergerFS Support", Optional: true},
	"ZFSNAS_RSYNC":     {Label: "External Storage & Filesystem rsync", Optional: true},
	"ZFSNAS_APT":       {Label: "OS Updates & Installation"},
	"ZFSNAS_SECURITY":  {Label: "Sudoers Self-Management"},
}

// buildCommandToSectionMap parses the *full* required sudoers template
// (including experimental-gated sections) and returns a map of normalized
// command → Cmnd_Alias name (e.g. "/usr/bin/tee /etc/exports" → "ZFSNAS_NFS").
//
// We use the unfiltered template here on purpose: when --experimental is off
// the gated sections are stripped from RequiredSudoersContent(), but if the
// host happens to have those lines lingering in /etc/sudoers.d/zfsnas they
// surface as Extra Lines and we still want to label them with their proper
// section so the review UI shows a meaningful badge.
func buildCommandToSectionMap() map[string]string {
	required := strings.Replace(requiredSudoersTemplate, "{{ZFSNAS_FILES}}", buildFilesAlias(), 1)
	required = strings.Replace(required, "{{LXD_CAT_LINE}}", lxdConsoleCatLine(), 1)
	required = applySudoRSSubstitutions(required)
	m := make(map[string]string)
	currentAlias := ""
	for _, line := range strings.Split(required, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Cmnd_Alias ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				currentAlias = parts[1]
			}
			continue
		}
		if currentAlias != "" && strings.HasPrefix(trimmed, "/") {
			cmd := normalizeSudoLine(trimmed)
			if cmd != "" {
				m[cmd] = currentAlias
			}
		}
	}
	return m
}

// forcedSudoersLines are commands that must always be present when the Sudoers
// Hardening UI is active — they are needed for the UI itself to read and write
// the sudoers file. The user cannot silence or reject them.
var forcedSudoersLines = map[string]bool{
	"/usr/bin/tee /etc/sudoers.d/zfsnas": true,
	"/usr/bin/cat /etc/sudoers.d/zfsnas": true,
}

// CanManageSudoers returns true when the current process can overwrite
// /etc/sudoers.d/zfsnas. True in three situations:
//  1. Running as root (UID 0)
//  2. Blanket NOPASSWD: ALL sudoers
//  3. Hardened sudoers that already contains tee /etc/sudoers.d/zfsnas
func CanManageSudoers(status SudoStatus) bool {
	switch status.Type {
	case "root", "all":
		return true
	case "hardened":
		out, err := exec.Command("sudo", "-l", "-n").Output()
		if err != nil {
			return false
		}
		sudoList := string(out)
		teePath, err := exec.LookPath("tee")
		if err != nil {
			teePath = "/usr/bin/tee"
		}
		needle := teePath + " /etc/sudoers.d/zfsnas"
		return strings.Contains(sudoList, needle) ||
			strings.Contains(sudoList, "/tee /etc/sudoers.d/zfsnas")
	}
	return false
}

// RequiredSudoersContent returns the canonical sudoers file content for this
// portal. The ZFSNAS_FILES section is generated dynamically: it always includes
// /mnt/* entries, and also adds entries for any ZFS pool mounted directly under
// / (i.e. not under /mnt/). The LXD console-log read line is also dynamic
// because sudo-rs and classic sudo accept different wildcard shapes — see
// lxdConsoleCatLine.
func RequiredSudoersContent() string {
	s := strings.Replace(requiredSudoersTemplate, "{{ZFSNAS_FILES}}", buildFilesAlias(), 1)
	s = strings.Replace(s, "{{LXD_CAT_LINE}}", lxdConsoleCatLine(), 1)
	s = applySudoRSSubstitutions(s)
	// The virtualization aliases (ZFSNAS_INCUS*, ZFSNAS_VMSETUP, ZFSNAS_SYNCOID)
	// only matter once virtualization is actually installed. As of v6.6.26 the
	// feature is no longer gated behind --experimental, so the decisive signal is
	// purely whether Incus is on the box: a host that never enabled VMs &
	// Containers must NOT report a pile of missing VM-import / virtualization
	// sudoers it can't satisfy. The enable flow itself runs under full sudo (the
	// mandatory "sudo all" prerequisite), so these hardened rules are only needed
	// AFTER incus is installed.
	if !IncusInstalled() {
		s = stripExperimentalSudoersSections(s)
	}
	// MergerFS is gated independently of virtualization: its sudoers block is
	// only required once the feature's binary is installed. A host can have
	// mergerfs without incus (and vice-versa), so it gets its own gate rather
	// than riding the virtualization one.
	if !MergerFSInstalled() {
		s = stripSudoersAliasSet(s, mergerfsSudoersAlias)
	}
	return s
}

// stripExperimentalSudoersSections removes Cmnd_Alias blocks listed in
// experimentalSudoersAliases and drops their tokens from the trailing
// `zfsnas ALL=…` User_Spec spec list (which spans the line containing
// `NOPASSWD:` and any backslash-continuation lines that follow). Used when
// --experimental is off so the host doesn't surface virtualisation /
// memory-compression sudoers lines that aren't actually needed.
func stripExperimentalSudoersSections(content string) string {
	return stripSudoersAliasSet(content, experimentalSudoersAliases)
}

// stripSudoersAliasSet removes the Cmnd_Alias blocks named in `set` (and their
// preceding comment block) and drops their tokens from the trailing User_Spec.
// Used to gate optional features independently (virtualization via
// experimentalSudoersAliases, MergerFS via mergerfsSudoersAlias).
func stripSudoersAliasSet(content string, set map[string]bool) string {
	var out []string
	lines := strings.Split(content, "\n")
	skip := false       // inside a gated Cmnd_Alias block
	inUserSpec := false // inside the trailing User_Spec (multi-line OK)
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		endsContinuation := strings.HasSuffix(strings.TrimRight(line, " "), "\\")

		if skip {
			// Wait until the current physical line is NOT a continuation; the
			// next line then closes the block.
			if !endsContinuation {
				skip = false
			}
			continue
		}

		if inUserSpec {
			// We're inside the alias list of the User_Spec — strip gated
			// tokens here too.
			out = append(out, filterAliasTokensInLine(line, set))
			if !endsContinuation {
				inUserSpec = false
			}
			continue
		}

		// Detect start of a gated Cmnd_Alias block.
		if strings.HasPrefix(trimmed, "Cmnd_Alias ") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 && set[parts[1]] {
				// Also drop this block's preceding comment lines so a
				// non-virtualization host's sudoers file carries no leftover
				// virtualization wording (the comment block runs from its
				// "# ──" header down to this Cmnd_Alias, with no blank line
				// between). Stops at the blank separator before the header.
				for len(out) > 0 && strings.HasPrefix(strings.TrimSpace(out[len(out)-1]), "#") {
					out = out[:len(out)-1]
				}
				if endsContinuation {
					skip = true
				}
				continue
			}
		}

		// Detect the User_Spec line. After we strip tokens from this line,
		// keep filtering subsequent continuation lines until the spec ends.
		if strings.HasPrefix(trimmed, "zfsnas ") && strings.Contains(line, "NOPASSWD:") {
			out = append(out, filterAliasTokensInLine(line, set))
			if endsContinuation {
				inUserSpec = true
			}
			continue
		}

		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// filterAliasTokensInLine drops gated alias names from a comma-separated alias
// list while preserving the line's prefix, indentation, and trailing
// continuation marker.
func filterAliasTokensInLine(line string, set map[string]bool) string {
	// Preserve any leading "<prefix>NOPASSWD:" (User_Spec head) verbatim.
	prefix := ""
	rest := line
	if idx := strings.Index(line, "NOPASSWD:"); idx >= 0 {
		prefix = line[:idx+len("NOPASSWD:")]
		rest = line[idx+len("NOPASSWD:"):]
	}
	// Detect and detach a trailing continuation marker so it survives the
	// token rewrite.
	trailing := ""
	stripped := strings.TrimRight(rest, " ")
	if strings.HasSuffix(stripped, "\\") {
		trailing = " \\"
		// Cut everything from the backslash onwards.
		bs := strings.LastIndex(rest, "\\")
		rest = rest[:bs]
	}

	// Detect a leading whitespace run (indent for continuation lines).
	indent := ""
	for i, c := range rest {
		if c == ' ' || c == '\t' {
			continue
		}
		indent = rest[:i]
		rest = rest[i:]
		break
	}

	tokens := strings.Split(rest, ",")
	var kept []string
	for _, t := range tokens {
		name := strings.TrimSpace(t)
		if set[name] {
			continue
		}
		if name == "" && len(kept) > 0 {
			// Empty trailing token after the last comma — drop it; we'll
			// re-add the trailing continuation below.
			continue
		}
		kept = append(kept, name)
	}
	if len(kept) == 0 {
		return prefix + trailing
	}
	return prefix + indent + strings.Join(kept, ", ") + trailing
}

// lxdConsoleCatLine returns the sudoers entry that lets the portal read
// /var/log/incus/<name>/console.log for the Container Console tab. Two forms:
//
//   - classic sudo: "/usr/bin/cat /var/log/incus/*/console.log" — sudo's
//     fnmatch accepts a literal prefix and a literal "/console.log" suffix
//     around the `*`, so the rule only matches that one filename pattern.
//   - sudo-rs: "/usr/bin/cat *" — sudo-rs only accepts `*` as the entire
//     trailing argument; any prefix or suffix is rejected by visudo. We have
//     to widen the rule to `cat *` (read any file as root) to keep the feature
//     working. Path is still validated server-side before invocation
//     (lxdNameRe in system/lxd.go) so the broader rule is only reachable to
//     someone who can already shell as the zfsnas service account.
func lxdConsoleCatLine() string {
	// Always emit the sudo-rs-compatible form. The narrower
	// "/usr/bin/cat /var/log/incus/*/console.log" is rejected by sudo-rs (a
	// literal suffix after `*` is not allowed), and we want every generated
	// sudoers file to load on both sudo flavors. The instance name is still
	// regex-validated server-side before invocation (system/lxd.go).
	return "/usr/bin/cat *"
}

// applySudoRSSubstitutions widens sudoers entries that use wildcards in
// non-trailing positions. sudo-rs (Ubuntu 26.04+) only accepts `*` as the
// entire trailing argument — any prefix (`--since=*`), suffix (`* scope global`),
// or middle position (`/proc/*/smaps_rollup`) trips visudo with
// "wildcards are not allowed in command arguments" and refuses to load the
// file, which kills every sudo call the portal needs.
//
// This is applied UNCONDITIONALLY: ZNAS always writes a sudoers file that loads
// on both sudo flavors, so a host can switch sudo implementation (or be
// re-imaged onto Ubuntu 26.04) without the file silently becoming unparseable.
// The widened forms are accepted by classic sudo too. Each replacement broadens
// the rule to a form sudo-rs accepts; path scoping is still enforced in Go
// before each invocation (filebrowser.go SafeJoin, netplan_migrate.go fixed
// paths, lxd_backups.go mount dir, system/memprocs.go pid filter, etc.), so the
// broader sudoers rule is only reachable to someone who can already execute as
// the zfsnas service account.
func applySudoRSSubstitutions(s string) string {
	return widenWildcardsForSudoRS(s)
}

// widenWildcardsForSudoRS performs the substitutions unconditionally. Split
// from applySudoRSSubstitutions so unit tests can exercise the rewrite
// without depending on the host's sudo flavor.
func widenWildcardsForSudoRS(s string) string {
	repls := [...][2]string{
		// ZFSNAS_SMART (always present) — /proc/<pid>/smaps_rollup read for
		// the swap-aware MEM topbar gauge. Wildcard in middle.
		{"/usr/bin/cat /proc/*/smaps_rollup", "/usr/bin/cat *"},
		// ZFSNAS_INCUS — journalctl --since=<ts> for the OOM-kill attribution
		// in the VMs & Containers state watcher. `--since=` prefix before *.
		{"/usr/bin/journalctl --since=*", "/usr/bin/journalctl *"},
		// ZFSNAS_SYNCOID — VM/Container backup mounts a snapshot read-only into
		// a private /tmp dir to read its files. The "/tmp/znas-bkup-mount-*"
		// argument has a prefix before the `*`, which sudo-rs rejects. Path
		// scoping is enforced in Go (system/lxd_backups.go builds the dir name
		// from the sanitized dataset name) so the wider rule is only reachable to
		// the zfsnas service account.
		{"/usr/bin/mkdir -p /tmp/znas-bkup-mount-*", "/usr/bin/mkdir -p *"},
		{"/usr/bin/rmdir /tmp/znas-bkup-mount-*", "/usr/bin/rmdir *"},
		{"/usr/bin/umount /tmp/znas-bkup-mount-*", "/usr/bin/umount *"},
		{"/usr/bin/cat /tmp/znas-bkup-mount-*", "/usr/bin/cat *"},
		{"/usr/bin/tee /tmp/znas-bkup-mount-*", "/usr/bin/tee *"},
		// ZFSNAS_RSYNC (v6.7.7) — external-storage unmount/cleanup is
		// path-scoped to /mnt/zfsnas-ext, whose trailing wildcard has a
		// prefix in the same token; sudo-rs rejects that shape. Path scoping
		// remains enforced in Go (system/extstorage.go ValidExtID + the
		// ExtMountBase prefix check).
		{"/usr/bin/umount /mnt/zfsnas-ext/*", "/usr/bin/umount *"},
		{"/usr/bin/rmdir /mnt/zfsnas-ext/*", "/usr/bin/rmdir *"},
	}
	for _, r := range repls {
		s = strings.Replace(s, r[0], r[1], 1)
	}
	return s
}

var (
	sudoIsRS     bool
	sudoIsRSOnce sync.Once
)

// IsSudoRS reports whether /usr/bin/sudo on this host is the sudo-rs
// reimplementation (default on Ubuntu 26.04+). Detected once via
// `sudo --version` — sudo-rs prints "sudo-rs" in its banner; classic sudo from
// sudo.ws prints "Sudo version N.N.N".
func IsSudoRS() bool {
	sudoIsRSOnce.Do(func() {
		out, err := exec.Command("sudo", "--version").CombinedOutput()
		if err != nil {
			return
		}
		if strings.Contains(strings.ToLower(string(out)), "sudo-rs") {
			sudoIsRS = true
		}
	})
	return sudoIsRS
}

// buildFilesAlias generates the ZFSNAS_FILES Cmnd_Alias block.
// sudo-rs (Ubuntu 26.04+) does not support wildcards in command arguments
// other than as the entire trailing argument, so the previous "/mnt/*" path
// scoping cannot be expressed in sudoers. Path scoping is enforced in Go
// (see SafeJoin and the dataset/share root validation in handlers/filebrowser.go).
func buildFilesAlias() string {
	return "Cmnd_Alias ZFSNAS_FILES = \\\n" +
		"    /usr/bin/find *, \\\n" +
		"    /usr/bin/chown *, \\\n" +
		"    /usr/bin/chown -R *, \\\n" +
		"    /usr/bin/chmod *, \\\n" +
		"    /usr/bin/chmod -R *, \\\n" +
		// v6.5.29 — full file browser mutations.
		"    /usr/bin/mkdir -p *, \\\n" +
		"    /usr/bin/rm -rf *, \\\n" +
		"    /usr/bin/rm -f *, \\\n" +
		"    /usr/bin/mv -f *, \\\n" +
		"    /usr/bin/mv -n *, \\\n" +
		"    /usr/bin/cp -a -f *, \\\n" +
		"    /usr/bin/cp -a -n *, \\\n" +
		"    /usr/bin/cp -a *, \\\n" +
		// File Browser transfer jobs: rsync gives copy/move a real progress
		// percentage and a clean cancel, kill terminates the process group when
		// the user cancels. Both live here rather than only in the optional
		// ZFSNAS_RSYNC alias, which a host without external storage never gets.
		"    /usr/bin/rsync *, \\\n" +
		"    /usr/bin/kill *, \\\n" +
		// v6.5.29 — raw-file preview endpoint streams allow-listed MIME
		// types from inside knownRoots; uses stat for size+mtime,
		// head for the 512-byte MIME sniff, cat for the body.
		"    /usr/bin/stat -c *, \\\n" +
		"    /usr/bin/head -c *, \\\n" +
		"    /usr/bin/cat *\n"
}

// GetCurrentSudoersContent reads /etc/sudoers.d/zfsnas.
// Returns ("", nil) when the file does not exist.
func GetCurrentSudoersContent() (string, error) {
	const path = "/etc/sudoers.d/zfsnas"
	data, err := os.ReadFile(path)
	if err == nil {
		return string(data), nil
	}
	if !os.IsNotExist(err) {
		// File exists but isn't readable by us — try via sudo cat.
		out, err2 := exec.Command("sudo", "cat", path).Output()
		if err2 == nil {
			return string(out), nil
		}
	}
	return "", nil
}

// ComputeSudoersDiff diffs current against required, marking silenced entries.
func ComputeSudoersDiff(current, required string, silenced []string) SudoersDiff {
	silencedSet := make(map[string]bool, len(silenced))
	for _, s := range silenced {
		silencedSet[s] = true
	}

	cmdSections := buildCommandToSectionMap()

	reqCmds := extractSudoCommands(required)
	curCmds := extractSudoCommands(current)

	curSet := make(map[string]bool, len(curCmds))
	for _, c := range curCmds {
		curSet[c] = true
	}
	reqSet := make(map[string]bool, len(reqCmds))
	for _, c := range reqCmds {
		reqSet[c] = true
	}

	makeDiff := func(cmd string, silenced, forced bool) SudoersLineDiff {
		sec := cmdSections[cmd]
		info := sudoersSectionInfoMap[sec]
		return SudoersLineDiff{
			Line:            cmd,
			Explanation:     lookupSudoersExplanation(cmd),
			Section:         sec,
			SectionLabel:    info.Label,
			SectionOptional: info.Optional,
			Silenced:        silenced,
			Forced:          forced,
		}
	}

	var matched, missing, extra []SudoersLineDiff

	for _, c := range reqCmds {
		if curSet[c] {
			matched = append(matched, makeDiff(c, false, forcedSudoersLines[c]))
		} else {
			missing = append(missing, makeDiff(c, silencedSet[c] && !forcedSudoersLines[c], forcedSudoersLines[c]))
		}
	}
	for _, c := range curCmds {
		if !reqSet[c] {
			extra = append(extra, makeDiff(c, silencedSet[c], false))
		}
	}

	// Up-to-date means no unsilenced diffs.
	upToDate := true
	for _, d := range missing {
		if !d.Silenced {
			upToDate = false
			break
		}
	}
	if upToDate {
		for _, d := range extra {
			if !d.Silenced {
				upToDate = false
				break
			}
		}
	}

	return SudoersDiff{
		UpToDate:     upToDate,
		FileExists:   current != "",
		MatchedLines: matched,
		MissingLines: missing,
		ExtraLines:   extra,
	}
}

// ApplySudoers assembles the final sudoers content, writes it via sudo tee,
// and validates it with visudo. On validation failure it rolls back.
// silencedMissing: lines from the required template the user chose NOT to add.
// silencedExtra:   lines from the current file the user chose to KEEP.
func ApplySudoers(required string, silencedMissing, silencedExtra []string) error {
	content := buildSudoersContent(required, silencedMissing, silencedExtra)

	// Basic pre-write sanity check: content must have at least one alias and a grant line.
	if err := validateSudoersContent(content); err != nil {
		return fmt.Errorf("content validation failed: %w", err)
	}

	const sudoersPath = "/etc/sudoers.d/zfsnas"

	// When running as root, write the file directly — sudo as root requires a
	// password on many systems and cannot be used non-interactively.
	if os.Getuid() == 0 {
		if err := os.WriteFile(sudoersPath, []byte(content), 0440); err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		return nil
	}

	// Write via sudo tee (runs tee as root so it can create/overwrite the file).
	teeCmd := exec.Command("sudo", "tee", sudoersPath)
	teeCmd.Stdin = strings.NewReader(content)
	if out, err := teeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tee failed: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Ensure 0440 permissions. sudo tee creates new files with umask-derived
	// permissions (typically 0644); sudoers files must not be world-writable and
	// should be 0440 to follow convention. This is a best-effort call: it is
	// allowed by ZFSNAS_SECURITY in the hardened template and by NOPASSWD:ALL
	// on first-time setup. Failure is non-fatal (0644 is accepted by sudo).
	exec.Command("sudo", "chmod", "0440", sudoersPath).Run() //nolint:errcheck

	return nil
}

// SudoAllContent returns the minimal single-line sudoers file that grants
// the zfsnas service account unrestricted passwordless sudo access.
func SudoAllContent() string {
	return "# ZFS NAS Portal — unrestricted sudo access\n" +
		"# Applied via the \"Convert to sudo all\" option in the Sudoers Hardening UI.\n" +
		"# This is the most frictionless configuration: the zfsnas service account can\n" +
		"# run any command as root without a password prompt.\n" +
		"zfsnas ALL=(ALL) NOPASSWD: ALL\n"
}

// ApplySudoAll writes the minimal NOPASSWD:ALL sudoers entry for the zfsnas
// user. It bypasses the normal template + visudo pipeline and writes directly
// via sudo tee (or directly when running as root).
func ApplySudoAll() error {
	const sudoersPath = "/etc/sudoers.d/zfsnas"
	content := SudoAllContent()
	if os.Getuid() == 0 {
		return os.WriteFile(sudoersPath, []byte(content), 0440)
	}
	teeCmd := exec.Command("sudo", "tee", sudoersPath)
	teeCmd.Stdin = strings.NewReader(content)
	if out, err := teeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tee failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	exec.Command("sudo", "chmod", "0440", sudoersPath).Run() //nolint:errcheck
	return nil
}

// RemoveSudoersWriteAccess rewrites /etc/sudoers.d/zfsnas removing the
// "tee /etc/sudoers.d/zfsnas" entry so ZNAS can no longer self-modify sudoers,
// while keeping "cat /etc/sudoers.d/zfsnas" so the diff view still works.
func RemoveSudoersWriteAccess() error {
	const teeLine = "/usr/bin/tee /etc/sudoers.d/zfsnas"

	current, err := GetCurrentSudoersContent()
	if err != nil || current == "" {
		// Nothing to remove.
		return nil
	}

	lines := strings.Split(current, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		norm := normalizeSudoLine(strings.TrimSpace(line))
		if norm == teeLine {
			continue
		}
		kept = append(kept, line)
	}

	// Fix orphaned trailing ", \" on the line that preceded the removed entry.
	for i := 0; i < len(kept); i++ {
		stripped := strings.TrimRight(kept[i], " ")
		if !strings.HasSuffix(stripped, ", \\") {
			continue
		}
		nextIsCmd := false
		for j := i + 1; j < len(kept); j++ {
			t := strings.TrimSpace(kept[j])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			nextIsCmd = strings.HasPrefix(t, "/")
			break
		}
		if !nextIsCmd {
			kept[i] = strings.TrimRight(stripped[:len(stripped)-3], " ")
		}
	}

	content := strings.Join(kept, "\n")
	if err := validateSudoersContent(content); err != nil {
		return fmt.Errorf("content validation after removal failed: %w", err)
	}

	const sudoersPath = "/etc/sudoers.d/zfsnas"
	if os.Getuid() == 0 {
		return os.WriteFile(sudoersPath, []byte(content), 0440)
	}
	teeCmd := exec.Command("sudo", "tee", sudoersPath)
	teeCmd.Stdin = strings.NewReader(content)
	if out, err := teeCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("tee failed: %s: %w", strings.TrimSpace(string(out)), err)
	}
	exec.Command("sudo", "chmod", "0440", sudoersPath).Run() //nolint:errcheck
	return nil
}

// FilterForcedLines removes any forced (always-required) lines from a list of
// silenced/pending command strings, so they can never be excluded from the file.
func FilterForcedLines(lines []string) []string {
	out := lines[:0:0]
	for _, l := range lines {
		if !forcedSudoersLines[l] {
			out = append(out, l)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// BuildSudoersContent is the exported version of buildSudoersContent.
func BuildSudoersContent(required string, silencedMissing, silencedExtra []string) string {
	return buildSudoersContent(required, silencedMissing, silencedExtra)
}

// SudoersContentHash returns the SHA-256 hex digest of the given content.
func SudoersContentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h)
}

// validateSudoersContent does a lightweight pre-write check on the assembled content.
func validateSudoersContent(content string) error {
	if strings.TrimSpace(content) == "" {
		return fmt.Errorf("assembled content is empty")
	}
	hasAlias := false
	hasGrant := false
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "Cmnd_Alias ") {
			hasAlias = true
		}
		if strings.Contains(t, "NOPASSWD:") && !strings.HasPrefix(t, "#") {
			hasGrant = true
		}
	}
	if !hasAlias {
		return fmt.Errorf("no Cmnd_Alias entries found — file would be invalid")
	}
	if !hasGrant {
		return fmt.Errorf("grant line (NOPASSWD:) not found — file would be invalid")
	}
	return nil
}

// buildSudoersContent constructs the final file content from the required template
// minus silenced-missing lines, plus silenced-extra lines appended as a preserved block.
func buildSudoersContent(required string, silencedMissing, silencedExtra []string) string {
	if len(silencedMissing) == 0 && len(silencedExtra) == 0 {
		return required
	}

	silMissingSet := make(map[string]bool, len(silencedMissing))
	for _, cmd := range silencedMissing {
		silMissingSet[cmd] = true
	}

	rawLines := strings.Split(required, "\n")
	kept := make([]string, 0, len(rawLines))
	for _, line := range rawLines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "/") {
			cmd := normalizeSudoLine(trimmed)
			if silMissingSet[cmd] {
				continue // silenced — do not include
			}
		}
		kept = append(kept, line)
	}

	// Fix orphaned trailing ", \" — if a command line ends with ", \" but the
	// next non-blank non-comment line is not another command path, strip it.
	for i := 0; i < len(kept); i++ {
		stripped := strings.TrimRight(kept[i], " ")
		if !strings.HasSuffix(stripped, ", \\") {
			continue
		}
		nextIsCmd := false
		for j := i + 1; j < len(kept); j++ {
			t := strings.TrimSpace(kept[j])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			nextIsCmd = strings.HasPrefix(t, "/")
			break
		}
		if !nextIsCmd {
			kept[i] = strings.TrimRight(stripped[:len(stripped)-3], " ")
		}
	}

	// Remove Cmnd_Alias blocks that have become empty (all their commands were
	// silenced).  An alias is empty when its header line is not followed by any
	// command line ("/…") before the next non-blank, non-comment line.
	// Also collect the alias names so they can be removed from the grant line.
	kept, emptyAliases := removeEmptyCmndAliases(kept)
	if len(emptyAliases) > 0 {
		kept = removeAliasesFromGrant(kept, emptyAliases)
	}

	content := strings.Join(kept, "\n")

	// Append silenced-extra lines as a preserved section.
	if len(silencedExtra) > 0 {
		var sb strings.Builder
		sb.WriteString("\n# ── Preserved entries (kept by Sudoers Hardening) ────────────────────────────\n")
		sb.WriteString("Cmnd_Alias ZFSNAS_EXTRA = \\\n")
		for i, cmd := range silencedExtra {
			if i < len(silencedExtra)-1 {
				sb.WriteString("    " + cmd + ", \\\n")
			} else {
				sb.WriteString("    " + cmd + "\n")
			}
		}
		// Add ZFSNAS_EXTRA to the grant line.
		content = strings.Replace(content, "ZFSNAS_SECURITY", "ZFSNAS_SECURITY, ZFSNAS_EXTRA", 1)
		content = strings.TrimRight(content, "\n") + "\n" + sb.String()
	}

	return content
}

// removeEmptyCmndAliases scans lines for Cmnd_Alias blocks that contain no
// command entries (i.e. all their "/…" lines were removed by silencing).
// It removes the alias header and its immediately-preceding comment block from
// lines, and returns the cleaned slice plus the list of removed alias names.
func removeEmptyCmndAliases(lines []string) ([]string, []string) {
	type emptyAlias struct {
		name         string
		headerIdx    int
		commentStart int // first index of the preceding comment block to remove
	}

	var found []emptyAlias
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Cmnd_Alias ") {
			continue
		}
		parts := strings.Fields(trimmed)
		if len(parts) < 3 {
			continue
		}
		aliasName := parts[1]

		// Check whether any command ("/…") follows before the next structural line.
		hasCmd := false
		for j := i + 1; j < len(lines); j++ {
			t := strings.TrimSpace(lines[j])
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			hasCmd = strings.HasPrefix(t, "/")
			break
		}
		if hasCmd {
			continue
		}

		// Walk backwards to find the start of the preceding comment block.
		commentStart := i
		for k := i - 1; k >= 0; k-- {
			t := strings.TrimSpace(lines[k])
			if t == "" || strings.HasPrefix(t, "#") {
				commentStart = k
			} else {
				break
			}
		}

		found = append(found, emptyAlias{
			name:         aliasName,
			headerIdx:    i,
			commentStart: commentStart,
		})
	}

	if len(found) == 0 {
		return lines, nil
	}

	removeIdx := make(map[int]bool)
	names := make([]string, 0, len(found))
	for _, ea := range found {
		names = append(names, ea.name)
		for k := ea.commentStart; k <= ea.headerIdx; k++ {
			removeIdx[k] = true
		}
	}

	result := make([]string, 0, len(lines)-len(removeIdx))
	for i, l := range lines {
		if !removeIdx[i] {
			result = append(result, l)
		}
	}
	return result, names
}

// removeAliasesFromGrant removes the given alias names from the NOPASSWD grant
// line(s) at the end of the sudoers file.  It handles both ", NAME" and "NAME, "
// patterns so the comma/space bookkeeping stays correct.
func removeAliasesFromGrant(lines []string, aliasNames []string) []string {
	result := make([]string, len(lines))
	copy(result, lines)

	for i, line := range result {
		if !strings.Contains(line, "ZFSNAS_") {
			continue
		}
		for _, name := range aliasNames {
			// Try to remove as a non-first item first: ", NAME"
			if strings.Contains(line, ", "+name) {
				line = strings.ReplaceAll(line, ", "+name, "")
			} else if strings.Contains(line, name+", ") {
				// First item followed by another: "NAME, "
				line = strings.ReplaceAll(line, name+", ", "")
			} else {
				line = strings.ReplaceAll(line, name, "")
			}
		}
		// Clean up any double spaces or orphaned commas left behind.
		line = strings.ReplaceAll(line, ",  ", ", ")
		line = strings.TrimRight(line, ", ")
		result[i] = line
	}
	return result
}

// extractSudoCommands extracts and normalizes individual command paths from
// sudoers content. Only lines that start with "/" (command entries within
// Cmnd_Alias blocks) are extracted.
func extractSudoCommands(content string) []string {
	var cmds []string
	seen := map[string]bool{}
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "/") {
			continue
		}
		cmd := normalizeSudoLine(trimmed)
		if cmd != "" && !seen[cmd] {
			seen[cmd] = true
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

// normalizeSudoLine strips trailing syntax characters (, \ space) and
// normalizes internal whitespace.
func normalizeSudoLine(line string) string {
	s := strings.TrimRight(line, " ,\\")
	s = strings.TrimSpace(s)
	return strings.Join(strings.Fields(s), " ")
}

// lookupSudoersExplanation returns a human-readable explanation for a command.
func lookupSudoersExplanation(cmd string) string {
	if exp, ok := sudoersExplanations[cmd]; ok {
		return exp
	}
	// Wildcard prefix match for other patterns ending in " *".
	for pattern, exp := range sudoersExplanations {
		if strings.HasSuffix(pattern, " *") {
			base := strings.TrimSuffix(pattern, " *")
			if strings.HasPrefix(cmd, base+" ") || cmd == base {
				return exp
			}
		}
	}
	return "Command required by the portal — no detailed explanation available for this entry."
}

var sudoersExplanations = map[string]string{
	// ── Samba service control ─────────────────────────────────────────────────
	"/usr/bin/systemctl reload smbd":  "Reloads Samba configuration without dropping active connections.",
	"/usr/bin/systemctl restart smbd": "Restarts the Samba SMB daemon.",
	"/usr/bin/systemctl start smbd":   "Starts the Samba SMB daemon.",
	"/usr/bin/systemctl stop smbd":    "Stops the Samba SMB daemon.",
	"/usr/bin/systemctl start nmbd":   "Starts the Samba NetBIOS name daemon.",
	"/usr/bin/systemctl stop nmbd":    "Stops the Samba NetBIOS name daemon.",

	// ── NFS service control ───────────────────────────────────────────────────
	"/usr/bin/systemctl start nfs-server":   "Starts the Linux NFS kernel server.",
	"/usr/bin/systemctl stop nfs-server":    "Stops the Linux NFS kernel server.",
	"/usr/bin/systemctl restart nfs-server": "Restarts the Linux NFS kernel server.",

	// ── iSCSI service control (three backend variants) ────────────────────────
	"/usr/bin/systemctl start rtslib-fb-targetctl":   "Starts the LIO iSCSI target service (rtslib-fb-targetctl).",
	"/usr/bin/systemctl stop rtslib-fb-targetctl":    "Stops the LIO iSCSI target service.",
	"/usr/bin/systemctl restart rtslib-fb-targetctl": "Restarts the LIO iSCSI target service.",
	"/usr/bin/systemctl start targetclid":            "Starts the targetcli persistent daemon.",
	"/usr/bin/systemctl stop targetclid":             "Stops the targetcli persistent daemon.",
	"/usr/bin/systemctl restart targetclid":          "Restarts the targetcli persistent daemon.",
	"/usr/bin/systemctl start tgt":                   "Starts the SCSI target framework daemon (tgt).",
	"/usr/bin/systemctl stop tgt":                    "Stops the SCSI target framework daemon (tgt).",
	"/usr/bin/systemctl restart tgt":                 "Restarts the SCSI target framework daemon (tgt).",

	// ── MinIO install / setup ─────────────────────────────────────────────────
	"/usr/bin/chmod +x /usr/local/bin/minio":                                "Makes the downloaded MinIO server binary executable.",
	"/usr/bin/chmod +x /usr/local/bin/mc":                                   "Makes the downloaded MinIO client (mc) binary executable.",
	"/usr/bin/mkdir -p /var/lib/minio":                                      "Creates the MinIO data directory.",
	"/usr/bin/mkdir -p /var/lib/minio/.minio/certs":                         "Creates the MinIO TLS certificate directory.",
	"/usr/bin/mkdir -p *":                                                   "Creates directories on demand for the File Browser — the 'New Folder' action and the destination directory when uploading files. Also used by other features that provision their own directories (e.g. the MinIO/S3 object server's data directories). Path validation enforced in Go (SafeJoin against dataset/share roots).",
	"/usr/bin/chown minio-user\\:minio-user /var/lib/minio":                 "Transfers ownership of the MinIO data directory to the minio-user account.",
	"/usr/bin/chown -R minio-user\\:minio-user /var/lib/minio/.minio/certs": "Transfers ownership of the MinIO TLS certificate directory to minio-user.",
	"/usr/bin/chown -R minio-user\\:minio-user *":                           "Transfers ownership of MinIO data directories to the minio-user account.",
	"/usr/bin/chown root\\:minio-user /etc/default/minio":                   "Sets MinIO environment file ownership so minio-user can read it.",
	"/usr/bin/chmod 640 /etc/default/minio":                                 "Restricts the MinIO environment file to root and minio-user.",
	"/usr/bin/chmod 640 /var/lib/minio/.minio/certs/private.key":            "Protects the MinIO TLS private key from world-read access.",
	"/usr/bin/tee /var/lib/minio/.minio/certs/public.crt":                   "Installs the MinIO TLS public certificate at a fixed destination. The source is read in-process and piped through sudo tee, so no source-path wildcard is granted.",
	"/usr/bin/tee /var/lib/minio/.minio/certs/private.key":                  "Installs the MinIO TLS private key at a fixed destination. The source is read in-process and piped through sudo tee, so no source-path wildcard is granted.",
	"/usr/bin/rm -f /var/lib/minio/.minio/certs/public.crt":                 "Removes the MinIO TLS certificate when TLS is disabled.",
	"/usr/bin/rm -f /var/lib/minio/.minio/certs/private.key":                "Removes the MinIO TLS private key when TLS is disabled.",
	"/usr/bin/systemctl enable minio":                                       "Enables MinIO to start automatically at boot.",
	"/usr/bin/systemctl disable minio":                                      "Prevents MinIO from starting automatically at boot.",
	"/usr/bin/systemctl start minio":                                        "Starts the MinIO S3 object server.",
	"/usr/bin/systemctl stop minio":                                         "Stops the MinIO S3 object server.",
	"/usr/bin/systemctl restart minio":                                      "Restarts the MinIO S3 object server.",

	// ── UPS / NUT install, config, service control ────────────────────────────
	"/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get purge -y nut nut-client nut-server": "Removes all NUT UPS packages during feature uninstall.",
	"/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get remove -y nut nut-client":           "Removes NUT client packages during partial feature removal.",
	"/usr/bin/udevadm control --reload-rules":                                                "Reloads udev rules after writing USB rules for UPS device detection.",
	"/usr/bin/udevadm trigger --subsystem-match=usb":                                         "Re-applies udev USB rules so the UPS device is recognised immediately.",
	"/usr/bin/systemctl enable nut-server":                                                   "Enables the NUT UPS server daemon at boot.",
	"/usr/bin/systemctl disable nut-server":                                                  "Prevents the NUT UPS server from starting at boot.",
	"/usr/bin/systemctl start nut-server":                                                    "Starts the NUT UPS server daemon (upsd).",
	"/usr/bin/systemctl stop nut-server":                                                     "Stops the NUT UPS server daemon.",
	"/usr/bin/systemctl restart nut-server":                                                  "Restarts the NUT UPS server daemon.",
	"/usr/bin/systemctl enable nut-client":                                                   "Enables the NUT UPS monitoring client at boot.",
	"/usr/bin/systemctl disable nut-client":                                                  "Prevents the NUT UPS client from starting at boot.",
	"/usr/bin/systemctl start nut-client":                                                    "Starts the NUT UPS monitoring client (upsmon).",
	"/usr/bin/systemctl stop nut-client":                                                     "Stops the NUT UPS monitoring client.",
	"/usr/bin/systemctl enable nut-monitor":                                                  "Enables the NUT monitor service at boot.",
	"/usr/bin/systemctl start nut-monitor":                                                   "Starts the NUT monitor service.",
	"/usr/bin/systemctl reset-failed":                                                        "Clears systemd failed-unit state so services can be restarted cleanly.",
	"/usr/bin/chown root\\:nut /etc/nut":                                                     "Sets group ownership of /etc/nut to the nut group.",
	"/usr/bin/chmod 750 /etc/nut":                                                            "Restricts /etc/nut to root and nut group; prevents world access.",
	"/usr/bin/chown root\\:nut /etc/nut/nut.conf":                                            "Sets nut-group ownership on the NUT mode configuration file.",
	"/usr/bin/chown root\\:nut /etc/nut/ups.conf":                                            "Sets nut-group ownership on the UPS device configuration file.",
	"/usr/bin/chown root\\:nut /etc/nut/upsd.conf":                                           "Sets nut-group ownership on the NUT daemon listen configuration.",
	"/usr/bin/chown root\\:nut /etc/nut/upsd.users":                                          "Sets nut-group ownership on the NUT user authentication file.",
	"/usr/bin/chown root\\:nut /etc/nut/upsmon.conf":                                         "Sets nut-group ownership on the UPS monitor configuration.",
	"/usr/bin/chmod 640 /etc/nut/nut.conf":                                                   "Restricts the NUT mode config to root and nut group.",
	"/usr/bin/chmod 640 /etc/nut/ups.conf":                                                   "Restricts the UPS device config to root and nut group.",
	"/usr/bin/chmod 640 /etc/nut/upsd.conf":                                                  "Restricts the NUT daemon config to root and nut group.",
	"/usr/bin/chmod 640 /etc/nut/upsd.users":                                                 "Restricts the NUT user auth file to root and nut group.",
	"/usr/bin/chmod 640 /etc/nut/upsmon.conf":                                                "Restricts the UPS monitor config to root and nut group.",
	"/usr/bin/rm -rf /etc/nut":                                                               "Removes the NUT configuration directory during feature uninstall.",
	"/usr/bin/rm -rf /etc/systemd/system/nut-driver.target.wants":                            "Removes NUT driver target symlinks during uninstall.",
	"/usr/bin/rm -rf /etc/systemd/system/nut-driver@.service.d":                              "Removes the NUT driver service drop-in directory during uninstall.",

	// ── Service registration (APT / systemd setup) ────────────────────────────
	"/usr/bin/systemctl daemon-reload": "Reloads systemd unit files after writing the zfsnas service file.",
	"/usr/bin/systemctl enable zfsnas": "Enables the ZNAS portal to start automatically at boot.",

	"/usr/sbin/zpool *":                                                      "All ZFS pool operations: create, import, export, scrub, status, offline/online (v1.0.0+). Covers Pool Fixer Wizard clear/replace actions (v6.3.21+).",
	"/usr/sbin/zfs *":                                                        "All ZFS dataset operations: create, destroy, set, get, snapshot, rollback, load-key/unload-key (encryption v5.0.0+), send/recv (replication v6.1.0+), allow (delegation v6.3.26+).",
	"/usr/sbin/smartctl *":                                                   "SMART disk health data for SAS/SATA drives. Required for the Disk Health and SMART detail pages.",
	"/usr/bin/nvme smart-log -o json *":                                      "NVMe drive health and temperature data (v3.0.0+).",
	"/usr/sbin/dmidecode *":                                                  "Reads DMI/SMBIOS firmware tables for motherboard, BIOS, and per-DIMM memory details (v6.5.3+ SysInfo popup).",
	"/usr/bin/journalctl -k *":                                               "Reads the kernel ring buffer (read-only) so the VMs & Containers state watcher can attribute a Running→Stopped transition to a kernel OOM-kill (v6.5.3+, virtualization-only).",
	"/usr/bin/journalctl --since=*":                                          "Reads the systemd journal (read-only) so the VMs & Containers state watcher can attribute a Running→Stopped transition to a kernel OOM-kill (v6.5.3+, virtualization-only).",
	"/usr/bin/journalctl *":                                                  "Read-only access to the systemd journal for the Log Viewer screen (Activity & Events → journal tabs). Runs `journalctl` with -n / -p / --since / -u / -k filters to display the kernel ring buffer and service logs from the portal. journalctl is read-only and never modifies system state.",
	"/usr/bin/cat /proc/*/smaps_rollup":                                      "Reads /proc/<pid>/smaps_rollup so the MEM topbar gauge can show complete swap usage (incl. shmem) for QEMU/KVM workers — VmSwap in /proc/<pid>/status only counts anonymous private swap (v6.5.3+).",
	"/usr/bin/mount -t cifs *":                                               "Mounts a remote SMB/Windows share under /mnt/zfsnas-ext for the Protect → Filesystem rsync feature (browsing + sync jobs). Credentials are read from a root-only file, never from the command line.",
	"/usr/bin/mount -t nfs *":                                                "Mounts a remote NFS export under /mnt/zfsnas-ext for the Protect → Filesystem rsync feature (browsing + sync jobs).",
	"/usr/bin/sshfs *":                                                       "Mounts a remote SSH/SFTP location under /mnt/zfsnas-ext for the Protect → Filesystem rsync feature (browsing + sync jobs).",
	"/usr/bin/curlftpfs *":                                                   "Mounts a remote FTP server under /mnt/zfsnas-ext for the Protect → Filesystem rsync feature (browsing + sync jobs).",
	"/usr/bin/umount /mnt/zfsnas-ext/*":                                      "Unmounts external storages of the Filesystem rsync feature — on-demand mounts are detached automatically after ~15 minutes idle. Path-scoped to the feature's mount directory.",
	"/usr/bin/rmdir /mnt/zfsnas-ext/*":                                       "Removes empty external-storage mountpoint directories (connection-test probes). Path-scoped to the feature's mount directory.",
	"/usr/bin/rsync *":                                                       "Runs the actual file synchronization between local datasets and a mounted external storage (Protect → Filesystem rsync), and performs File Browser copy/move of large files and folders — rsync is what supplies the live progress percentage, transfer speed and ETA shown in the progress popup. Needs root so file ownership and permissions are preserved on both sides.",
	"/usr/bin/kill *":                                                        "Stops or pauses a running rsync synchronization (user Stop button, daily time-window enforcement) and terminates a File Browser copy/move the user cancels. Those processes run as root, so terminating them needs root too.",
	"/usr/bin/apt-get *":                                                     "Package installation and OS updates. Used by the Prerequisites tab and the Settings > OS Updates page.",
	"/usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get *":                  "OS package upgrade with debconf forced non-interactive (suppresses the 'unable to initialize frontend' warnings on the unattended Auto Update). Used by Settings > OS Updates.",
	"/usr/bin/tee /etc/apt/apt.conf.d/20auto-upgrades":                       "Turns the OS automatic-background-upgrade service (unattended-upgrades) on or off from the OS Packages card. Writes the same apt periodic config that `dpkg-reconfigure unattended-upgrades` manages (v6.6.27+).",
	"/usr/bin/tee /etc/samba/smb.conf":                                       "Writes the Samba configuration file when a share is created, edited, or deleted.",
	"/usr/bin/tee /etc/exports":                                              "Writes the NFS export table; exportfs -ra is called immediately after to apply the change.",
	"/usr/bin/tee /etc/systemd/system/zfsnas.service":                        "Writes the systemd unit file when the portal registers itself as a system service.",
	"/usr/bin/tee /etc/modprobe.d/zfs.conf":                                  "Persists ARC size limits across reboots (v6.3.22+).",
	"/usr/bin/tee /sys/module/zfs/parameters/zfs_arc_max":                    "Applies a new ARC maximum immediately via the ZFS sysfs interface without requiring a reboot.",
	"/usr/bin/tee /sys/module/zfs/parameters/zfs_arc_min":                    "Applies a new ARC minimum immediately via the ZFS sysfs interface without requiring a reboot.",
	"/usr/bin/tee /etc/sudoers.d/zfsnas":                                     "Lets the portal write its own sudoers file when using the Sudoers Hardening feature. Required so in-app changes continue to work after sudo is restricted.",
	"/usr/bin/cat /etc/sudoers.d/zfsnas":                                     "Lets the portal read its own sudoers file so the Sudoers Review diff is always accurate and detects manual edits (v6.3.32+).",
	"/usr/bin/chmod 0440 /etc/sudoers.d/zfsnas":                              "Sets the correct sudoers file permissions (0440) after each write. Required when the file is newly created — sudo tee inherits the process umask and may produce 0644; this corrects it to the recommended 0440.",
	"/usr/sbin/useradd *":                                                    "Creates the Linux account for a new portal user. Wildcards required for optional --uid/--gid/--no-user-group flags (v3.0.0+).",
	"/usr/sbin/usermod -aG sambashare *":                                     "Adds a user to the sambashare group for SMB access.",
	"/usr/sbin/userdel -f *":                                                 "Deletes a portal user's Linux account (force flag covers locked accounts).",
	"/usr/sbin/groupadd *":                                                   "Creates a Linux group. Used when creating users with a custom primary group (v3.0.0+).",
	"/usr/sbin/groupdel *":                                                   "Removes a Linux group when deleting the last user that owned it.",
	"/usr/bin/gpasswd *":                                                     "Manages Linux group membership; used during user deletion to remove users from the sambashare group (and other group-management operations).",
	"/usr/bin/smbpasswd *":                                                   "Sets or removes the Samba password for a user.",
	"/usr/bin/smbstatus -S":                                                  "Lists active SMB sessions per share (v6.1.0+).",
	"/usr/bin/chgrp sambashare *":                                            "Sets group ownership of a share directory to sambashare (v6.3.27+).",
	"/usr/sbin/exportfs -ra":                                                 "Reloads all NFS exports after the export table is updated.",
	"/usr/bin/timedatectl set-timezone *":                                    "Sets the system timezone from the Settings > System page.",
	"/usr/sbin/shutdown *":                                                   "Allows scheduled shutdown/reboot from the power menu and from the UPS shutdown watcher.",
	"/usr/sbin/modprobe zfs":                                                 "Loads the ZFS kernel module after installation if it is not already loaded.",
	"/usr/bin/systemctl restart zfsnas":                                      "Restarts the portal service from the power menu (v3.0.0+).",
	"/usr/bin/du -b -d 6 *":                                                  "Powers the Folder TreeMap — scans dataset mount points for per-folder disk usage.",
	"/usr/sbin/wipefs -a *":                                                  "Clears all disk signatures before adding a disk to a pool.",
	"/usr/sbin/sgdisk *":                                                     "Wipes the GPT partition table before pool creation. Path may differ by distribution.",
	"/usr/bin/dd if=/dev/zero *":                                             "Zero-fills the first sectors of a disk during the wipe-disk workflow.",
	"/usr/bin/dd *":                                                          "Proxmox Import: streams a raw disk image into a ZFS volume (zvol) backing an Incus VM disk (v6.4.21+; switched from LXD in v6.5.2). Broadened from `dd of=/dev/zd* *` because sudo-rs (Ubuntu 26.04+) does not allow wildcards in non-trailing argument positions.",
	"/usr/bin/partx *":                                                       "Proxmox Import: adds/removes partition block devices for a zvol (/dev/zdX → /dev/zdXp1 …) so the EFI System Partition can be mounted and the UEFI fallback boot path repaired after import (v6.4.21+). Broadened from `partx * /dev/zd*` for sudo-rs compatibility.",
	"/usr/bin/ntfsfix *":                                                     "Proxmox Import (v6.5.2+): clears the NTFS dirty bit and journal on a Windows partition before its first Incus boot. Without this, a Windows guest captured during fast-startup arrives with the volume marked \"kept in cache\" and alternates between normal boot and Windows RE on every second start. Targets a /dev/loop* device that fixUEFIWindows() attaches with offset+sizelimit over a single partition of the imported zvol.",
	"/usr/bin/ln -sf *":                                                      "Incus Compute (v6.6.16): creates the cross-distro OVMF UEFI firmware symlinks (Ubuntu's OVMF_CODE.4MB.fd ↔ Debian's OVMF_CODE_4M.fd) at portal startup, so a VM pushed between an Ubuntu host and a Debian host can find its firmware and boot on either. EnsureOVMFCompat() only ever links the /usr/share/OVMF/ pair; the broad trailing `*` is required because sudo-rs (Ubuntu 26.04+) accepts `*` only as a complete trailing argument and the command takes two path arguments.",
	"/usr/bin/blkid -o value -s TYPE *":                                      "Proxmox Import (v6.5.2+): reads the filesystem type of a single zvol partition so fixUEFIWindows() only runs ntfsfix against NTFS volumes (skipping ESP/MSR partitions on the same disk).",
	"/usr/bin/python3 - *":                                                   "Proxmox Import (v6.5.2+): runs a fixed-content libhivex (python3-hivex) script piped via stdin to patch the Windows BCD on the imported ESP — removes BootMgr's resumeobject and sets bootstatuspolicy=IgnoreAllFailures so first-boot doesn't loop into Windows RE. The trailing `-` forces python3 to read its program from stdin; the wildcard accepts only the BCD path argument. The script body is a Go string constant (system/proxmox_import.go patchWindowsBCD), not user input.",
	"/usr/sbin/losetup *":                                                    "Proxmox Import (v6.5.2+): attaches/detaches loop devices over individual partitions of an imported zvol so fixUEFIWindows() can mount the ESP and each NTFS partition without relying on `partx -a` — partx fails on zvols whose 16 KiB volblocksize doesn't line up with the GPT's 512-byte sector arithmetic.",
	"/usr/bin/tee /etc/default/zramswap":                                     "Memory Compression (v6.5.3+): writes the zram-tools persistent config (PERCENT, ALGO, PRIORITY) at the only path the package reads. Narrow path, no wildcard.",
	"/usr/bin/systemctl start zramswap":                                      "Memory Compression (v6.5.3+): starts the zram-tools systemd unit so /dev/zram0 comes up and the swap activates.",
	"/usr/bin/systemctl stop zramswap":                                       "Memory Compression (v6.5.3+): stops the zram-tools unit; runs swapoff /dev/zram0 and releases the device.",
	"/usr/bin/systemctl restart zramswap":                                    "Memory Compression (v6.5.3+): restarts after a config change so the new PERCENT/ALGO take effect (briefly tears the swap down — ZNAS guards this with a free-RAM safety check).",
	"/usr/bin/systemctl enable zramswap":                                     "Memory Compression (v6.5.3+): persists the unit across reboots after the first enable.",
	"/usr/bin/systemctl disable zramswap":                                    "Memory Compression (v6.5.3+): clears the unit from boot so a Disable in the UI is durable across reboots.",
	"/usr/sbin/swapoff /dev/zram0":                                           "Memory Compression (v6.5.5+): drains /dev/zram0 directly during a resize. Needed because `systemctl stop zramswap` is a no-op when the unit is in `failed` state (Type=oneshot RemainAfterExit=true), leaving the device armed and the next start failing with EBUSY. Narrow path — only the canonical zram device, no wildcard.",
	"/usr/sbin/modprobe -r zram":                                             "Memory Compression (v6.5.5+): unloads the zram kernel module after swapoff so the next start can recreate /dev/zram0 at the new PERCENT. Module name is fixed; no wildcard.",
	"/usr/bin/systemctl reset-failed zramswap":                               "Memory Compression (v6.5.5+): clears the `failed` state on the zramswap unit before retrying start, so systemd will actually launch ExecStart= instead of refusing.",
	"/usr/bin/systemctl enable systemd-networkd":                             "Netplan→ifupdown migration (v6.5.6+): re-enables systemd-networkd as part of rollback when the migration verification step fails.",
	"/usr/bin/systemctl disable systemd-networkd":                            "Netplan→ifupdown migration (v6.5.6+): disables systemd-networkd before handing the host over to ifupdown's `networking` service.",
	"/usr/bin/systemctl start systemd-networkd":                              "Netplan→ifupdown migration (v6.5.6+): rollback only — restarts systemd-networkd if the migration could not bring up an interface.",
	"/usr/bin/systemctl stop systemd-networkd":                               "Netplan→ifupdown migration (v6.5.6+): stops systemd-networkd after the new ifupdown config is in place.",
	"/usr/bin/systemctl disable systemd-networkd.service":                    "Netplan→ifupdown migration: disables systemd-networkd by its full unit name (the `.service` form the migration actually invokes).",
	"/usr/bin/systemctl stop systemd-networkd.service":                       "Netplan→ifupdown migration: stops systemd-networkd by its full unit name.",
	"/usr/bin/systemctl mask systemd-networkd.service":                       "Netplan→ifupdown migration: masks systemd-networkd so it can't be re-activated at boot by wait-online's Requires= once the host is on ifupdown.",
	"/usr/bin/systemctl unmask systemd-networkd.service":                     "Netplan→ifupdown migration: rollback — unmasks systemd-networkd if the migration verification step fails.",
	"/usr/bin/systemctl disable systemd-networkd-wait-online.service":        "Netplan→ifupdown migration: disables the networkd-wait-online unit that otherwise blocks boot ~2 min waiting for an interface networkd no longer manages.",
	"/usr/bin/systemctl stop systemd-networkd-wait-online.service":           "Netplan→ifupdown migration: stops the networkd-wait-online unit before masking it.",
	"/usr/bin/systemctl mask systemd-networkd-wait-online.service":           "Netplan→ifupdown migration: masks networkd-wait-online so network-online.target can't pull it (and so it can't revive systemd-networkd) — eliminates the multi-minute boot delay.",
	"/usr/bin/systemctl unmask systemd-networkd-wait-online.service":         "Netplan→ifupdown migration: rollback — unmasks networkd-wait-online if the migration is reverted.",
	"/usr/bin/systemctl enable systemd-networkd-wait-online.service":         "Netplan→ifupdown migration: rollback — re-enables networkd-wait-online when reverting to the systemd-networkd setup.",
	"/usr/bin/systemctl enable systemd-networkd.socket":                      "Netplan→ifupdown migration (v6.5.6+): rollback companion to enable systemd-networkd.",
	"/usr/bin/systemctl disable systemd-networkd.socket":                     "Netplan→ifupdown migration (v6.5.6+): disable companion socket so it can't trigger systemd-networkd back up.",
	"/usr/bin/systemctl start systemd-networkd.socket":                       "Netplan→ifupdown migration (v6.5.6+): rollback companion socket start.",
	"/usr/bin/systemctl stop systemd-networkd.socket":                        "Netplan→ifupdown migration (v6.5.6+): stops the systemd-networkd activation socket alongside the unit.",
	"/usr/bin/systemctl enable systemd-networkd-varlink.socket":              "Netplan→ifupdown migration (v6.5.6+): rollback companion for the varlink activation socket.",
	"/usr/bin/systemctl disable systemd-networkd-varlink.socket":             "Netplan→ifupdown migration (v6.5.6+): also disabled because it's a separate activation path that would otherwise re-spawn systemd-networkd after stop.",
	"/usr/bin/systemctl start systemd-networkd-varlink.socket":               "Netplan→ifupdown migration (v6.5.6+): rollback start.",
	"/usr/bin/systemctl stop systemd-networkd-varlink.socket":                "Netplan→ifupdown migration (v6.5.6+): stops the varlink socket so it can't trigger systemd-networkd back up.",
	"/usr/bin/systemctl enable systemd-networkd-resolve-hook.socket":         "Netplan→ifupdown migration (v6.5.6+): rollback companion for the resolve-hook activation socket.",
	"/usr/bin/systemctl disable systemd-networkd-resolve-hook.socket":        "Netplan→ifupdown migration (v6.5.6+): also disabled — same reason as the varlink socket.",
	"/usr/bin/systemctl start systemd-networkd-resolve-hook.socket":          "Netplan→ifupdown migration (v6.5.6+): rollback start.",
	"/usr/bin/systemctl stop systemd-networkd-resolve-hook.socket":           "Netplan→ifupdown migration (v6.5.6+): stops the resolve-hook socket alongside the rest.",
	"/usr/bin/rm -f /run/systemd/network/*.network":                          "Netplan→ifupdown migration (v6.5.6+): removes the netplan-generated systemd-networkd .network files left in tmpfs so a re-spawned networkd has nothing to apply against the host's NICs. /run is tmpfs — these would clear on reboot anyway, but the migration needs them gone now.",
	"/usr/bin/rm -f /etc/resolv.conf":                                        "Netplan→ifupdown migration (v6.5.6+): removes the systemd-resolved stub symlink at /etc/resolv.conf so the migration can replace it with a regular file containing the captured upstream DNS. Without this, `tee /etc/resolv.conf` would write through the symlink into the resolved-managed run-time file.",
	"/usr/bin/tee /etc/resolv.conf":                                          "Netplan→ifupdown migration (v6.5.6+): writes /etc/resolv.conf with the captured DNS servers so DNS resolution survives the disabling of systemd-networkd. Narrow path, no wildcard.",
	"/usr/bin/chmod -x /etc/network/if-up.d/resolved":                        "Netplan→ifupdown migration: makes systemd-resolved's ifup hook non-executable so ifup skips it. The hook calls resolvectl over D-Bus, which hangs networking.service ~5 min at boot when resolved/dbus aren't ready; we already write a static /etc/resolv.conf so the hook is redundant.",
	"/usr/bin/chmod +x /etc/network/if-up.d/resolved":                        "Netplan→ifupdown migration: rollback — restores the systemd-resolved ifup hook.",
	"/usr/bin/systemctl mask ifup@.service":                                  "Netplan→ifupdown migration: masks the udev-triggered per-interface ifup@ template so networking.service is the single interface bring-up path — eliminates the /run/network/ifstate lock race that hangs boot.",
	"/usr/bin/systemctl unmask ifup@.service":                                "Netplan→ifupdown migration: rollback — unmasks ifup@.service.",
	"/usr/bin/tee /etc/dhcpcd.conf":                                          "Netplan→ifupdown migration (v6.5.6+): appends a per-interface `clientid` block to /etc/dhcpcd.conf that mirrors the DHCP Client-Identifier systemd-networkd was sending (read from /run/systemd/netif/leases/<ifindex>). Without this, dhcpcd would announce itself with its default RFC-4361 DUID+IAID and the DHCP server would lease the host a different IP after the migration.",
	"/usr/bin/tee /etc/dhcpcd.exit-hook":                                     "Netplan→ifupdown migration (v6.5.6+): writes a small shell exit-hook that pushes DHCP-supplied DNS into systemd-resolved (`resolvectl dns <iface> <ip>`) so /etc/resolv.conf doesn't need a static DNS fallback when the user is on DHCP.",
	"/usr/bin/chmod 0755 /etc/dhcpcd.exit-hook":                              "Netplan→ifupdown migration (v6.5.6+): makes the dhcpcd exit-hook executable. Narrow path, no wildcard.",
	"/usr/bin/ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf": "Netplan→ifupdown migration (v6.5.6+): restores the standard Ubuntu/Debian /etc/resolv.conf symlink to systemd-resolved's stub when a previous ZNAS migration left a regular file behind. Single fixed source + destination — no wildcard.",
	"/usr/bin/systemctl enable systemd-resolved":                             "Netplan→ifupdown migration (v6.5.6+): keeps systemd-resolved enabled across reboots so the stub at 127.0.0.53 keeps owning /etc/resolv.conf.",
	"/usr/bin/systemctl start systemd-resolved":                              "Netplan→ifupdown migration (v6.5.6+): starts systemd-resolved if it isn't already running so DNS resolution survives the disabling of systemd-networkd.",
	"/usr/bin/ip addr flush dev * scope global":                              "Netplan→ifupdown migration (v6.5.6+): flushes managed interfaces' global IPv4 addresses just before `ifup -a` runs, so the address netplan/networkd left on the link doesn't collide with `ip addr add` and mark networking.service `failed`. Sub-second window with no IP — the new address comes back via ifup immediately after.",
	"/usr/bin/ip route flush dev * scope global":                             "Netplan→ifupdown migration (v6.5.6+): mirrors the addr flush above; clears stale routes from the same window so ifup's route adds don't error with `File exists`.",
	"/usr/bin/ip *":                                                          "sudo-rs fallback for `ip addr flush dev * scope global` and `ip route flush dev * scope global` (Ubuntu 26.04+): sudo-rs rejects the trailing `scope global` after `*` (only the entire trailing argument may be `*`), so the rule is widened to `ip *`. Used during the netplan→ifupdown migration window to drop netplan-set addresses/routes before ifup runs (v6.5.6+).",
	"/usr/bin/systemctl enable networking":                                   "Netplan→ifupdown migration (v6.5.6+): persists the ifupdown service across reboots after the migration succeeds.",
	"/usr/bin/systemctl disable networking":                                  "Netplan→ifupdown migration (v6.5.6+): paired with enable (rarely used, kept for symmetry / future rollback flow).",
	"/usr/bin/systemctl start networking":                                    "Netplan→ifupdown migration (v6.5.6+): brings up the new /etc/network/interfaces config.",
	"/usr/bin/systemctl stop networking":                                     "Netplan→ifupdown migration (v6.5.6+): paired with start; not used in the happy path.",
	"/usr/bin/mv /etc/netplan/*.yaml /etc/netplan/*.yaml.znas-disabled":      "Netplan→ifupdown migration (v6.5.6+): renames every netplan YAML to a .znas-disabled suffix so netplan stops generating systemd-networkd configs at boot. Scoped to /etc/netplan/.",
	"/usr/bin/mv *":                                                          "sudo-rs fallback for `mv /etc/netplan/*.yaml /etc/netplan/*.yaml.znas-disabled` (Ubuntu 26.04+): sudo-rs rejects wildcards in non-trailing positions, so the rule is widened to `mv *`. The exact source/destination paths are computed in Go from a glob of /etc/netplan/*.yaml before the sudo call (system/netplan_migrate.go). Used only during the one-shot netplan→ifupdown migration (v6.5.6+).",
	"/usr/bin/cat /etc/netplan/*.yaml":                                       "Netplan→ifupdown migration (v6.5.6+): reads netplan YAML files (root-owned 0600 on Ubuntu 26.04) so the migration can detect renderer + unsupported constructs.",
	"/usr/bin/tee /etc/network/interfaces":                                   "Netplan→ifupdown migration (v6.5.6+): writes the generated /etc/network/interfaces. Narrow path, no wildcard.",
	"/usr/bin/tee /etc/network/interfaces.pre-znas-*":                        "Netplan→ifupdown migration (v6.5.6+): timestamped backup of any pre-existing /etc/network/interfaces before the migration overwrites it.",
	"/usr/bin/tee /etc/cloud/cloud.cfg.d/99-znas-disable-network-config.cfg": "Netplan→ifupdown migration (v6.5.6+): drops a single cloud-init drop-in that disables cloud-init's network management so the next reboot doesn't regenerate the netplan YAML we just disabled.",
	"/usr/bin/mount *":                                                       "Proxmox Import: mounts the EFI System Partition (FAT32) from an imported VM's root zvol into a private /tmp directory so grub.cfg can be installed for UEFI fallback boot repair (v6.4.21+). Broadened from `mount -t vfat * /dev/zd*p* /tmp/.znas-esp-*` for sudo-rs compatibility.",
	"/usr/bin/umount *":                                                      "Proxmox Import: unmounts the EFI System Partition after the UEFI fallback boot repair is complete (v6.4.21+). Broadened from `umount * /tmp/.znas-esp-*` for sudo-rs compatibility.",
	"/usr/bin/chmod 0775 *":                                                  "ISO Management: sets group-write permission on the .isos directory so the zfsnas process user can upload ISO files without requiring root on each transfer (v6.4.22+).",
	"/usr/bin/rm -f *":                                                       "File Browser: deletes a file, and removes a partially-written upload if it is interrupted (v6.4.3+). Path validated in Go (SafeJoin against dataset/share roots); broad trailing `*` required because sudo-rs (Ubuntu 26.04+) accepts `*` only as a complete trailing argument.",
	"/usr/bin/mv -f *":                                                       "File Browser: atomic rename overwriting the destination — finalizing an uploaded file (temp name → final name) and the rename/move action when the user chooses to overwrite an existing target. Single trailing wildcard required because sudo-rs (Ubuntu 26.04+) does not allow wildcards in non-trailing positions; the source/destination paths are validated in Go before invocation (no path traversal, no shell metacharacters).",
	"/usr/bin/mv -n *":                                                       "Rename/move without overwriting an existing destination (`-n` = no-clobber). Used by the File Browser rename/move action when the user does not opt to overwrite the target. Single trailing wildcard required because sudo-rs (Ubuntu 26.04+) does not allow wildcards in non-trailing positions; the source/destination paths are validated in Go before invocation (no path traversal, no shell metacharacters).",
	"/usr/bin/cat /var/log/incus/*/console.log":                              "Container Console tab: reads /var/log/incus/<name>/console.log (root-owned 0600) so the per-container Console pane can show the boot/console output (v6.4.28+). Pattern is locked to /var/log/incus/<single-segment>/console.log — sudo blocks every other path including /etc/shadow and traversal attempts (verified). Instance name is also regex-validated before invocation. (Used on classic sudo only; on sudo-rs hosts the wider `cat *` form is used because sudo-rs rejects any prefix before `*`.)",
	"/usr/bin/cat *":                                                         "File Browser: streams a previewable file's contents to the in-app viewer for the allow-listed text/image MIME types (after `stat`/`head` report its size and sniff its type). The path is validated in Go (SafeJoin against dataset/share roots) before invocation. Broad trailing `*` is required because sudo-rs (Ubuntu 26.04+) accepts `*` only as a complete trailing argument, so the narrower per-path forms cannot be expressed in sudoers.",
	"/usr/sbin/partprobe *":                                                  "Refreshes the kernel partition table after disk changes.",
	"/usr/bin/udevadm settle *":                                              "Waits for udev to settle after disk operations before proceeding.",
	"/usr/sbin/blkid -o export":                                              "Reads disk UUIDs and filesystem types after partitioning.",
	"/usr/bin/targetcli":                                                     "Configures iSCSI LIO targets, backstores, and ACLs (v6.1.0+).",
	"/usr/sbin/nut-scanner *":                                                "Scans USB and SNMP buses for attached UPS devices. Requires raw USB access.",
	"/usr/bin/nut-scanner":                                                   "Scans for attached UPS devices (Debian/Ubuntu path for nut-scanner binary).",
	"/usr/bin/systemctl stop nut-monitor":                                    "Stops the NUT monitor service (nut-monitor) during UPS config changes or uninstall.",
	"/usr/bin/systemctl disable nut-monitor":                                 "Disables the NUT monitor service from starting at boot during uninstall.",
	"/usr/bin/tee /etc/nut/ups.conf":                                         "Writes the NUT UPS device configuration file.",
	"/usr/bin/tee /etc/nut/nut.conf":                                         "Writes the NUT mode configuration file (MODE=standalone or MODE=none).",
	"/usr/bin/tee /etc/nut/upsd.conf":                                        "Writes the NUT daemon configuration (listen address, port).",
	"/usr/bin/tee /etc/nut/upsd.users":                                       "Writes the NUT user authentication file for upsmon.",
	"/usr/bin/tee /etc/nut/upsmon.conf":                                      "Writes the UPS monitor configuration.",
	"/usr/bin/find *":                                                        "File Browser: lists directory contents (v6.4.4+). The portal validates the target path against known dataset mountpoints and share roots before calling this command. Path-scoping moved from sudoers to Go because sudo-rs (Ubuntu 26.04+) does not allow wildcards in non-trailing argument positions.",
	"/usr/bin/chown *":                                                       "File Browser: non-recursive ownership change (v6.4.3+). Path validation enforced in Go (SafeJoin against dataset/share roots). Broadened from `chown * /mnt/*` for sudo-rs compatibility.",
	"/usr/bin/chown -R *":                                                    "File Browser: recursive ownership change on a directory tree (v6.4.3+). Path validation enforced in Go.",
	"/usr/bin/chmod *":                                                       "File Browser: non-recursive permission change (v6.4.3+). Path validation enforced in Go.",
	"/usr/bin/chmod -R *":                                                    "File Browser: recursive permission change on a directory tree (v6.4.3+). Path validation enforced in Go.",
	"/usr/bin/wget -q -O /usr/local/bin/minio *":                             "Downloads the MinIO binary during feature install.",
	"/usr/bin/wget -q -O /usr/local/bin/mc *":                                "Downloads the MinIO client (mc) binary during feature install.",
	"/usr/bin/tee /etc/systemd/system/minio.service":                         "Writes the MinIO systemd service unit file.",
	"/usr/bin/tee /etc/default/minio":                                        "Writes the MinIO environment configuration file.",
	"/usr/sbin/hdparm *":                                                     "Disk Power Management: applies APM, spindown, write-cache, and acoustic settings immediately to SATA/SAS drives (optional feature, v6.3.22+).",
	"/usr/bin/tee /etc/hdparm.conf":                                          "Disk Power Management: persists hdparm settings across reboots via /etc/hdparm.conf (optional feature, v6.3.22+).",
	"/usr/bin/tee *":                                                         "Writes feature config files where the path is determined at runtime: per-CPU scaling governor (/sys/devices/system/cpu/cpu*/...), PCIe ASPM policy, USB autosuspend, /etc/rc.local persistence block, and ISO Management uploads. Single trailing wildcard required because sudo-rs (Ubuntu 26.04+) does not allow wildcards in non-trailing argument positions.",
	"/usr/bin/chmod +x /etc/rc.local":                                        "System Power Management: ensures /etc/rc.local is executable after writing the persistence block (v6.3.22+).",
	"/usr/bin/systemctl enable rc-local":                                     "System Power Management: enables the rc-local systemd service so /etc/rc.local runs at boot. Only called once when the file is first created (v6.3.22+).",
	"/usr/bin/systemctl start rc-local":                                      "System Power Management: starts rc-local immediately after creation so power settings take effect without a reboot (v6.3.22+).",

	// ── Network Time (chrony NTP) ─────────────────────────────────────────────
	"/usr/bin/tee /etc/chrony/chrony.conf": "Network Time: writes updated NTP server/pool configuration to chrony.conf (v6.4.18+).",
	"/usr/bin/systemctl restart chronyd":   "Network Time: restarts the chrony daemon to apply new NTP server configuration (v6.4.18+).",
}

// requiredSudoersTemplate is the canonical sudoers file content for ZFS NAS Portal.
const requiredSudoersTemplate = `# ── ZFS pool & dataset management ────────────────────────────────────────────
# since v1.0.0 — pool creation, import, status, dataset CRUD, snapshots
# since v2.0.0 — zpool scrub (Scrub Management page)
# since v4.0.0 — zpool offline/online/clear (Pool Fixer Wizard)
# since v5.0.0 — zfs load-key / unload-key (native encryption)
# since v6.1.0 — zfs send / zfs recv (remote & local dataset replication)
# since v6.3.21 — zpool replace (Pool Fixer Wizard: disk replacement for DEGRADED pools)
# since v6.3.26 — zfs allow (InterLink push & schedule replication: ZFS delegation to service user)
Cmnd_Alias ZFSNAS_ZFS = \
    /usr/sbin/zpool *, \
    /usr/sbin/zfs *

# ── Samba (SMB shares) ────────────────────────────────────────────────────────
# since v1.0.0 — Samba service control, user provisioning, share config write
# since v3.0.0 — useradd with optional --uid/--gid/--no-user-group (custom UID/GID feature);
#                groupadd -g <gid> for primary group pre-creation;
#                userdel -f / groupdel / gpasswd -d for user deletion
# since v6.0.0 — find (recycle bin cleanup: delete files older than retention in .recycle/)
# since v6.1.0 — smbstatus -S (active session listing on the SMB shares page)
# since v6.3.27 — chgrp/chmod 0770 replace chmod 777 for share path setup;
#                 groupadd --system sambashare ensures the group exists
Cmnd_Alias ZFSNAS_SMB = \
    /usr/bin/systemctl reload smbd, \
    /usr/bin/systemctl restart smbd, \
    /usr/bin/systemctl start smbd, \
    /usr/bin/systemctl stop smbd, \
    /usr/bin/systemctl start nmbd, \
    /usr/bin/systemctl stop nmbd, \
    /usr/sbin/useradd *, \
    /usr/sbin/usermod -aG sambashare *, \
    /usr/sbin/userdel -f *, \
    /usr/sbin/groupadd *, \
    /usr/sbin/groupdel *, \
    /usr/bin/gpasswd *, \
    /usr/bin/smbpasswd *, \
    /usr/bin/chgrp sambashare *, \
    /usr/bin/tee /etc/samba/smb.conf, \
    /usr/bin/smbstatus -S

# ── NFS shares ────────────────────────────────────────────────────────────────
# since v2.0.0 — NFS share management and export config write
# since v6.3.22 — chmod 0777 on dataset path no longer required
Cmnd_Alias ZFSNAS_NFS = \
    /usr/sbin/exportfs -ra, \
    /usr/bin/systemctl start nfs-server, \
    /usr/bin/systemctl stop nfs-server, \
    /usr/bin/systemctl restart nfs-server, \
    /usr/bin/tee /etc/exports

# ── SMART & hardware monitoring ───────────────────────────────────────────────
# since v1.0.0 — SMART disk health data (SAS/SATA)
# since v3.0.0 — NVMe health and temperature monitoring
Cmnd_Alias ZFSNAS_SMART = \
    /usr/sbin/smartctl *, \
    /usr/bin/nvme smart-log -o json *, \
    /usr/sbin/dmidecode *, \
    /usr/bin/cat /proc/*/smaps_rollup

# ── Disk preparation & wipe ───────────────────────────────────────────────────
# since v1.0.0 — wipe and partition a disk before adding it to a pool;
#   wipefs clears signatures, sgdisk creates GPT layout, dd zero-fills,
#   partprobe + udevadm settle kernel/udev state, blkid reads UUIDs
# NOTE: sgdisk lives at /usr/sbin/sgdisk on Debian 12 and at /usr/bin/sgdisk on
#   some Ubuntu releases. Verify the correct path with "which sgdisk" and adjust
#   the two sgdisk lines below if needed.
Cmnd_Alias ZFSNAS_DISK = \
    /usr/sbin/wipefs -a *, \
    /usr/sbin/sgdisk *, \
    /usr/bin/dd if=/dev/zero *, \
    /usr/sbin/partprobe *, \
    /usr/bin/udevadm settle *, \
    /usr/sbin/blkid -o export

# ── iSCSI sharing ─────────────────────────────────────────────────────────────
# since v6.1.0 — iSCSI target management via targetcli-fb; service control for
#   rtslib-fb-targetctl / targetclid / tgt (whichever is installed)
Cmnd_Alias ZFSNAS_ISCSI = \
    /usr/bin/targetcli, \
    /usr/bin/systemctl start rtslib-fb-targetctl, \
    /usr/bin/systemctl stop rtslib-fb-targetctl, \
    /usr/bin/systemctl restart rtslib-fb-targetctl, \
    /usr/bin/systemctl start targetclid, \
    /usr/bin/systemctl stop targetclid, \
    /usr/bin/systemctl restart targetclid, \
    /usr/bin/systemctl start tgt, \
    /usr/bin/systemctl stop tgt, \
    /usr/bin/systemctl restart tgt

# ── S3 Object Server (MinIO) ──────────────────────────────────────────────────
# since v6.3.20 — optional MinIO S3 server; binary download, system account
#   setup, service unit, env file, data directory, TLS certs, and service control
Cmnd_Alias ZFSNAS_MINIO = \
    /usr/bin/wget -q -O /usr/local/bin/minio *, \
    /usr/bin/wget -q -O /usr/local/bin/mc *, \
    /usr/bin/chmod +x /usr/local/bin/minio, \
    /usr/bin/chmod +x /usr/local/bin/mc, \
    /usr/sbin/useradd --system --home-dir /var/lib/minio --shell /usr/sbin/nologin minio-user, \
    /usr/bin/mkdir -p /var/lib/minio, \
    /usr/bin/mkdir -p /var/lib/minio/.minio/certs, \
    /usr/bin/mkdir -p *, \
    /usr/bin/chown minio-user\:minio-user /var/lib/minio, \
    /usr/bin/chown -R minio-user\:minio-user /var/lib/minio/.minio/certs, \
    /usr/bin/chown -R minio-user\:minio-user *, \
    /usr/bin/chown root\:minio-user /etc/default/minio, \
    /usr/bin/chmod 640 /etc/default/minio, \
    /usr/bin/chmod 640 /var/lib/minio/.minio/certs/private.key, \
    /usr/bin/tee /var/lib/minio/.minio/certs/public.crt, \
    /usr/bin/tee /var/lib/minio/.minio/certs/private.key, \
    /usr/bin/rm -f /var/lib/minio/.minio/certs/public.crt, \
    /usr/bin/rm -f /var/lib/minio/.minio/certs/private.key, \
    /usr/bin/tee /etc/systemd/system/minio.service, \
    /usr/bin/tee /etc/default/minio, \
    /usr/bin/systemctl enable minio, \
    /usr/bin/systemctl disable minio, \
    /usr/bin/systemctl start minio, \
    /usr/bin/systemctl stop minio, \
    /usr/bin/systemctl restart minio

# ── UPS Management (NUT) ──────────────────────────────────────────────────────
# since v6.3.22 — optional NUT daemon; install, auto-detect UPS, write /etc/nut/
#   config files, service control; uninstall purges packages and removes /etc/nut;
#   udevadm control/trigger used after writing USB udev rules for UPS detection
Cmnd_Alias ZFSNAS_UPS = \
    /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get purge -y nut nut-client nut-server, \
    /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get remove -y nut nut-client, \
    /usr/bin/udevadm control --reload-rules, \
    /usr/bin/udevadm trigger --subsystem-match=usb, \
    /usr/bin/systemctl enable nut-server, \
    /usr/bin/systemctl disable nut-server, \
    /usr/bin/systemctl start nut-server, \
    /usr/bin/systemctl stop nut-server, \
    /usr/bin/systemctl restart nut-server, \
    /usr/bin/systemctl enable nut-client, \
    /usr/bin/systemctl disable nut-client, \
    /usr/bin/systemctl start nut-client, \
    /usr/bin/systemctl stop nut-client, \
    /usr/bin/systemctl enable nut-monitor, \
    /usr/bin/systemctl disable nut-monitor, \
    /usr/bin/systemctl start nut-monitor, \
    /usr/bin/systemctl stop nut-monitor, \
    /usr/bin/systemctl reset-failed, \
    /usr/sbin/nut-scanner *, \
    /usr/bin/nut-scanner, \
    /usr/bin/chown root\:nut /etc/nut, \
    /usr/bin/chmod 750 /etc/nut, \
    /usr/bin/chown root\:nut /etc/nut/nut.conf, \
    /usr/bin/chown root\:nut /etc/nut/ups.conf, \
    /usr/bin/chown root\:nut /etc/nut/upsd.conf, \
    /usr/bin/chown root\:nut /etc/nut/upsd.users, \
    /usr/bin/chown root\:nut /etc/nut/upsmon.conf, \
    /usr/bin/chmod 640 /etc/nut/nut.conf, \
    /usr/bin/chmod 640 /etc/nut/ups.conf, \
    /usr/bin/chmod 640 /etc/nut/upsd.conf, \
    /usr/bin/chmod 640 /etc/nut/upsd.users, \
    /usr/bin/chmod 640 /etc/nut/upsmon.conf, \
    /usr/bin/tee /etc/nut/nut.conf, \
    /usr/bin/tee /etc/nut/upsd.conf, \
    /usr/bin/tee /etc/nut/upsd.users, \
    /usr/bin/tee /etc/nut/upsmon.conf, \
    /usr/bin/tee /etc/nut/ups.conf, \
    /usr/bin/rm -rf /etc/nut, \
    /usr/bin/rm -rf /etc/systemd/system/nut-driver.target.wants, \
    /usr/bin/rm -rf /etc/systemd/system/nut-driver@.service.d

# ── Disk Power Management (hdparm) ────────────────────────────────────────────
# since v6.3.22 — optional hdparm feature; APM level, spindown timeout,
#   write-cache, and acoustic management applied immediately to SATA/SAS drives;
#   persisted in /etc/hdparm.conf. Only relevant when hdparm is installed.
Cmnd_Alias ZFSNAS_DISKPOWER = \
    /usr/sbin/hdparm *, \
    /usr/bin/tee /etc/hdparm.conf

# ── System Power Management (CPU governor, PCIe ASPM, USB autosuspend) ────────
# since v6.3.22 — CPU frequency governor applied immediately to all cores and
#   persisted via /etc/rc.local managed block; PCIe ASPM policy and USB
#   autosuspend likewise applied live and persisted in the same rc.local block.
Cmnd_Alias ZFSNAS_SYSPOWER = \
    /usr/bin/tee *, \
    /usr/bin/chmod +x /etc/rc.local, \
    /usr/bin/systemctl enable rc-local, \
    /usr/bin/systemctl start rc-local

# ── ZFS Replication (syncoid) ─────────────────────────────────────────────────
# since v6.5.19 — VM/Container Backup feature uses syncoid to send ZFS-aware
#   incremental snapshot streams either locally (cross-pool on the same host)
#   or to a peer ZNAS over SSH. The handler also runs "incus admin recover"
#   to register newly received backup datasets. Optional feature gated by the
#   --experimental flag.
Cmnd_Alias ZFSNAS_SYNCOID = \
    /usr/sbin/syncoid *, \
    /usr/bin/incus admin recover, \
    /usr/bin/mkdir -p /tmp/znas-bkup-mount-*, \
    /usr/bin/rmdir /tmp/znas-bkup-mount-*, \
    /usr/bin/mount -t zfs *, \
    /usr/bin/umount /tmp/znas-bkup-mount-*, \
    /usr/bin/cat /tmp/znas-bkup-mount-*, \
    /usr/bin/tee /tmp/znas-bkup-mount-*

# ── MergerFS union filesystem (v6.7.13, optional) ─────────────────────────────
# Installs the mergerfs package/binary, writes its systemd .mount unit, and
# mounts/unmounts the union under /mnt or a pool path. Source data is never
# modified. Only present when the MergerFS feature is installed.
Cmnd_Alias ZFSNAS_MERGERFS = \
    /usr/bin/apt-get install -y /tmp/znas-mergerfs/*, \
    /usr/bin/apt-get remove -y mergerfs, \
    /usr/bin/tar -xzf /tmp/znas-mergerfs/* -C /usr/local *, \
    /usr/bin/install -m0755 /tmp/znas-mergerfs/* *, \
    /usr/bin/rm -f /usr/local/bin/mergerfs, \
    /usr/bin/rm -f /usr/local/bin/mergerfs-fusermount, \
    /usr/bin/tee /etc/fuse.conf, \
    /usr/bin/tee /etc/systemd/system/*.mount, \
    /usr/bin/rm -f /etc/systemd/system/*.mount, \
    /usr/bin/mergerfs *, \
    /usr/bin/setfattr -n user.mergerfs.* *, \
    /usr/bin/mount /mnt/*, /usr/bin/umount /mnt/*, \
    /usr/bin/systemctl daemon-reload, \
    /usr/bin/systemctl enable --now *.mount, \
    /usr/bin/systemctl disable --now *.mount

# ── Folder usage scanning ─────────────────────────────────────────────────────
# since v6.0.0 — Folder TreeMap feature; scans dataset mount points for per-folder sizes
Cmnd_Alias ZFSNAS_SCAN = \
    /usr/bin/du -b -d 6 *

# ── File Browser (v6.4.3+) ────────────────────────────────────────────────────
# since v6.4.3 — chown/chmod on files and folders within dataset mountpoints,
#   SMB share paths, and NFS share paths via the File Browser feature.
# since v6.4.4 — find used to list directory contents so paths not owned by the
#   zfsnas service account can still be browsed.
# since v6.4.4 — paths scoped to /mnt/* (and any pool mounted directly under /)
#   instead of the broad wildcard, limiting access to dataset mount areas only.
#   The portal validates the target path against known share/dataset roots before
#   calling these commands; arbitrary paths cannot be targeted via the UI.
{{ZFSNAS_FILES}}
# ── System management ─────────────────────────────────────────────────────────
# since v1.0.0 — timezone setting, shutdown/reboot from power menu, ZFS kernel module load
# since v3.0.0 — systemctl restart zfsnas ("Restart Portal" in the power menu)
# since v6.3.22 — tee entries for ARC Level 1 tuning (modprobe.d + sysfs parameters)
Cmnd_Alias ZFSNAS_SYSTEM = \
    /usr/bin/timedatectl set-timezone *, \
    /usr/sbin/shutdown *, \
    /usr/sbin/modprobe zfs, \
    /usr/bin/systemctl restart zfsnas, \
    /usr/bin/tee /etc/modprobe.d/zfs.conf, \
    /usr/bin/tee /sys/module/zfs/parameters/zfs_arc_max, \
    /usr/bin/tee /sys/module/zfs/parameters/zfs_arc_min

# ── System journal log viewer ─────────────────────────────────────────────────
# since v6.6.12 — read-only journalctl access for the Log Viewer screen (the
#   Activity & Events page journal tabs) so an admin can inspect the kernel ring
#   buffer and service logs from the portal. A core feature, always present; the
#   journal tabs are simply hidden in the UI when this grant is absent.
Cmnd_Alias ZFSNAS_JOURNAL = \
    /usr/bin/journalctl *

# ── Network Time (chrony NTP) ─────────────────────────────────────────────────
# since v6.4.18 — NTP server configuration via Settings > General > Network Time
#   (card is only visible when chrony is installed and running)
Cmnd_Alias ZFSNAS_NTP = \
    /usr/bin/tee /etc/chrony/chrony.conf, \
    /usr/bin/systemctl restart chronyd

# ── Incus Network Bridges — VLAN interface management ──────────────────────
# since v6.4.19 — ifup/ifdown bring VLAN sub-interfaces up/down without reboot.
# /etc/network/interfaces edits are performed in-process (root only); no sudo entry
# is granted for that path.
#   Only needed when using the Networking mode in the Compute section.
Cmnd_Alias ZFSNAS_INCUSNET = \
    /usr/sbin/ifup *, \
    /usr/sbin/ifdown *

# ── Incus Compute (Proxmox Import + ISO Management + Migration) ────────────
# since v6.4.21 — Proxmox live VM import streams raw disk images directly into
#   the ZFS volumes (zvols) that back Incus VM instance disks.
#   volmode=dev is set on each zvol so ZFS creates a /dev/zdX block device.
#   dd reads from stdin and writes to /dev/zdX (bypasses /dev/zvol/ symlinks
#   which may be blocked by stale files from a prior failed import).
#   partx exposes partition block devices (/dev/zdXp1 …) so the EFI System
#   Partition can be mounted and the fallback GRUB boot path repaired for UEFI VMs.
# since v6.4.22 — ISO Management creates a .isos directory inside the ZFS pool
#   root (owned by root). mkdir -p creates it on first upload; chmod 0775 lets
#   the zfsnas process user write ISO files into it without requiring root for
#   every upload.
# since v6.4.28 — the trailing cat line is generated dynamically:
#     classic sudo →  /usr/bin/cat /var/log/incus/*/console.log  (tight)
#     sudo-rs      →  /usr/bin/cat *                           (wider — sudo-rs
#                                                              rejects any
#                                                              prefix before *)
#   Used by the Container Console tab to read /var/log/incus/<name>/console.log
#   (root-owned 0600). Instance name is regex-validated server-side regardless.
# since v6.5.3 — journalctl reads (kernel ring buffer + systemd journal) let
#   the state watcher attribute a Running→Stopped VM/container transition to
#   a kernel OOM-kill. Read-only and confined to this virtualization-gated
#   block so non-VM hosts don't see them surfaced in Sudoers Review.
# NOTE: partx, mount, umount may live under /usr/bin/ or /sbin/ depending on
#   the distribution. Verify with "which partx" if a sudoers error occurs.
Cmnd_Alias ZFSNAS_INCUS = \
    /usr/bin/dd *, \
    /usr/bin/partx *, \
    /usr/bin/mount *, \
    /usr/bin/umount *, \
    /usr/bin/mkdir -p *, \
    /usr/bin/chmod 0775 *, \
    /usr/bin/tee *, \
    /usr/bin/rm -f *, \
    /usr/bin/mv -f *, \
    /usr/bin/ntfsfix *, \
    /usr/bin/blkid -o value -s TYPE *, \
    /usr/bin/python3 - *, \
    /usr/sbin/losetup *, \
    /usr/bin/journalctl -k *, \
    /usr/bin/journalctl --since=*, \
    /usr/bin/ln -sf *, \
    {{LXD_CAT_LINE}}

# ── Memory Compression (zram) ─────────────────────────────────────────────────
# since v6.5.3 — the "Memory Compression" feature, part of the VMs & Containers
#   (virtualization) feature set: zram compressed swap raises guest memory density
#   on the host. Toggles the zram-tools "zramswap" service and its device at
#   runtime and writes the persistent config; swapoff + modprobe tear the device
#   down when the feature is turned off. Gated with --experimental, so it is
#   absent on a host without virtualization enabled.
Cmnd_Alias ZFSNAS_MEMCOMP = \
    /usr/bin/systemctl start zramswap, \
    /usr/bin/systemctl stop zramswap, \
    /usr/bin/systemctl restart zramswap, \
    /usr/bin/systemctl enable zramswap, \
    /usr/bin/systemctl disable zramswap, \
    /usr/bin/systemctl reset-failed zramswap, \
    /usr/sbin/swapoff /dev/zram0, \
    /usr/sbin/modprobe -r zram, \
    /usr/bin/tee /etc/default/zramswap

# ── External Storage & Filesystem rsync ──────────────────────────────────────
# since v6.7.7 — the Protect → "Filesystem rsync" feature mounts remote
#   SMB / NFS / FTP / SSH storage under /mnt/zfsnas-ext/<id> (the File Browser
#   and rsync jobs both operate on that local path) and runs rsync between
#   local datasets and the mounted remote. umount and rmdir are path-scoped
#   to the feature's mount base.
Cmnd_Alias ZFSNAS_RSYNC = \
    /usr/bin/mount -t cifs *, \
    /usr/bin/mount -t nfs *, \
    /usr/bin/sshfs *, \
    /usr/bin/curlftpfs *, \
    /usr/bin/umount /mnt/zfsnas-ext/*, \
    /usr/bin/rmdir /mnt/zfsnas-ext/*, \
    /usr/bin/rsync *, \
    /usr/bin/kill *

# ── OS updates & service installation ────────────────────────────────────────
# since v1.0.0 — prerequisite package install (apt-get install) and
#   systemd service setup (tee + daemon-reload + enable)
# since v3.0.0 — OS package updates (apt-get upgrade) from the Settings page
# since v6.1.0 — apt-get remove / autoremove for optional feature uninstall
Cmnd_Alias ZFSNAS_APT = \
    /usr/bin/apt-get *, \
    /usr/bin/env DEBIAN_FRONTEND=noninteractive apt-get *, \
    /usr/bin/tee /etc/apt/apt.conf.d/20auto-upgrades, \
    /usr/bin/tee /etc/systemd/system/zfsnas.service, \
    /usr/bin/systemctl daemon-reload, \
    /usr/bin/systemctl enable zfsnas

# ── Sudoers self-management (Sudoers Hardening feature) ───────────────────────
# since v6.3.31 — lets the portal overwrite its own sudoers file when the
#   Sudoers Hardening feature is enabled in the Prerequisites tab.
# since v6.3.32 — cat /etc/sudoers.d/zfsnas lets the portal read its own file
#   so the Sudoers Review diff is always accurate (detects manual edits).
# since v6.4.25 — chmod 0440 /etc/sudoers.d/zfsnas corrects the file
#   permissions after each write; sudo tee creates new files with umask-derived
#   permissions (typically 0644) and this restores the recommended 0440.
Cmnd_Alias ZFSNAS_SECURITY = \
    /usr/bin/tee /etc/sudoers.d/zfsnas, \
    /usr/bin/cat /etc/sudoers.d/zfsnas, \
    /usr/bin/chmod 0440 /etc/sudoers.d/zfsnas

# ── Grant all of the above, passwordless, to the service account ──────────────
zfsnas ALL=(ALL) NOPASSWD: \
    ZFSNAS_ZFS, ZFSNAS_SMB, ZFSNAS_NFS, ZFSNAS_ISCSI, ZFSNAS_MINIO, ZFSNAS_UPS, ZFSNAS_DISKPOWER, ZFSNAS_SYSPOWER, ZFSNAS_MEMCOMP, ZFSNAS_SMART, ZFSNAS_DISK, ZFSNAS_SCAN, ZFSNAS_FILES, ZFSNAS_SYSTEM, ZFSNAS_JOURNAL, ZFSNAS_NTP, ZFSNAS_INCUSNET, ZFSNAS_INCUS, ZFSNAS_SYNCOID, ZFSNAS_MERGERFS, ZFSNAS_RSYNC, ZFSNAS_APT, ZFSNAS_SECURITY
`
