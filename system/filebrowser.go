package system

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// FileEntry describes one file or directory returned by ListDir.
type FileEntry struct {
	Name         string `json:"name"`
	IsDir        bool   `json:"is_dir"`
	IsSymlink    bool   `json:"is_symlink,omitempty"`
	SizeBytes    int64  `json:"size_bytes"`
	Permissions  string `json:"permissions"` // e.g. "-rw-r--r--"
	ModeOctal    string `json:"mode_octal"`  // e.g. "644"
	Owner        string `json:"owner"`
	OwnerUID     int    `json:"owner_uid"`
	Group        string `json:"group"`
	GroupGID     int    `json:"group_gid"`
	ModifiedUnix int64  `json:"modified_unix"`
	// v6.5.29 — additional timestamps + a coarse Kind hint so the FE
	// can sort/filter without re-deriving from the extension on every
	// view-mode switch. CreatedUnix is 0 when the filesystem doesn't
	// expose btime (find prints "?" — we coerce to 0). Kind values:
	// "dir" | "file" | "link" | "image" | "video" | "audio" |
	// "archive" | "document" | "exec".
	AccessedUnix int64  `json:"accessed_unix,omitempty"`
	ChangedUnix  int64  `json:"changed_unix,omitempty"`
	CreatedUnix  int64  `json:"created_unix,omitempty"`
	Kind         string `json:"kind,omitempty"`
}

// FileBrowserResult is returned by the list API.
type FileBrowserResult struct {
	RootLabel  string      `json:"root_label"`
	Subpath    string      `json:"subpath"`
	CurrentDir *FileEntry  `json:"current_dir,omitempty"` // stats for the directory being listed
	Entries    []FileEntry `json:"entries"`
}

// idMaps holds bidirectional name↔ID lookups for users and groups.
type idMaps struct {
	nameToUID map[string]int
	uidToName map[int]string
	nameToGID map[string]int
	gidToName map[int]string
}

// buildIDMaps reads /etc/passwd and /etc/group and builds bidirectional lookups.
// find's %U/%G may return either a name or a raw numeric ID string when name
// resolution fails; the bidirectional maps handle both cases.
func buildIDMaps() idMaps {
	m := idMaps{
		nameToUID: map[string]int{},
		uidToName: map[int]string{},
		nameToGID: map[string]int{},
		gidToName: map[int]string{},
	}
	if f, err := os.Open("/etc/passwd"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// format: name:password:uid:gid:gecos:home:shell
			parts := strings.Split(sc.Text(), ":")
			if len(parts) >= 3 {
				if id, err := strconv.Atoi(parts[2]); err == nil {
					m.nameToUID[parts[0]] = id
					m.uidToName[id] = parts[0]
				}
			}
		}
	}
	if f, err := os.Open("/etc/group"); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// format: name:password:gid:members
			parts := strings.Split(sc.Text(), ":")
			if len(parts) >= 3 {
				if id, err := strconv.Atoi(parts[2]); err == nil {
					m.nameToGID[parts[0]] = id
					m.gidToName[id] = parts[0]
				}
			}
		}
	}
	return m
}

// resolveOwner returns the canonical name and numeric UID for a value returned
// by find's %U. If find resolved the name, val is a username; if it couldn't,
// val is a numeric string. Both cases are handled.
func (m idMaps) resolveOwner(val string) (name string, uid int) {
	if id, err := strconv.Atoi(val); err == nil {
		// find returned a raw numeric UID — look up the name.
		if n, ok := m.uidToName[id]; ok {
			return n, id
		}
		return val, id
	}
	// find returned a name — look up the UID.
	return val, m.nameToUID[val]
}

// resolveGroup returns the canonical name and numeric GID for a value returned
// by find's %G.
func (m idMaps) resolveGroup(val string) (name string, gid int) {
	if id, err := strconv.Atoi(val); err == nil {
		if n, ok := m.gidToName[id]; ok {
			return n, id
		}
		return val, id
	}
	return val, m.nameToGID[val]
}

// ── ListDir ───────────────────────────────────────────────────────────────────

// ListDir reads the contents of root/subpath using sudo find so that directory
// permission restrictions on the zfsnas service account are bypassed.
// Entries are sorted: directories first, then files, both alphabetically.
func ListDir(root, subpath, rootLabel string) (*FileBrowserResult, error) {
	absPath, err := SafeJoin(root, subpath)
	if err != nil {
		return nil, err
	}

	// Build bidirectional name↔ID maps once for this request.
	ids := buildIDMaps()

	// sudo find <path> -maxdepth 1 -mindepth 1
	//   -printf '%y\t%s\t%m\t%M\t%U\t%G\t%T@\t%A@\t%C@\t%B@\t%P\n'
	// Fields: type | size | octal-mode | symbolic-mode | owner | group |
	//         mtime-epoch | atime-epoch | ctime-epoch | btime-epoch | name
	// %m gives the plain octal permissions (e.g. "755"), %M the symbolic string.
	// %T@ / %A@ / %C@ / %B@ are mtime / atime / ctime / btime as Unix
	// seconds with fractional part. btime ("?" on filesystems without
	// support — coerced to 0 below).
	// %P is the filename relative to the starting path (no leading slash).
	out, err := exec.Command("sudo", "find", absPath,
		"-maxdepth", "1", "-mindepth", "1",
		"-printf", "%y\t%s\t%m\t%M\t%U\t%G\t%T@\t%A@\t%C@\t%B@\t%P\n",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	var result []FileEntry
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		// SplitN with n=11 so a filename containing tabs ends up as-is
		// in parts[10] (the trailing %P).
		parts := strings.SplitN(line, "\t", 11)
		if len(parts) < 11 {
			continue
		}
		ftype, sizeStr, modeOctal, perms, owner, group :=
			parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
		mtimeStr, atimeStr, ctimeStr, btimeStr, name :=
			parts[6], parts[7], parts[8], parts[9], parts[10]

		isDir := ftype == "d"
		isLink := ftype == "l"

		var size int64
		if !isDir {
			size, _ = strconv.ParseInt(sizeStr, 10, 64)
		}

		// Normalise octal to exactly 3 digits ("755", "644", "000").
		octal := strings.TrimLeft(modeOctal, "0")
		if len(octal) < 3 {
			octal = strings.Repeat("0", 3-len(octal)) + octal
		}
		if len(octal) > 3 {
			octal = octal[len(octal)-3:]
		}

		mtime, _ := strconv.ParseFloat(mtimeStr, 64)
		atime, _ := strconv.ParseFloat(atimeStr, 64)
		ctime, _ := strconv.ParseFloat(ctimeStr, 64)
		// btime is "?" when the filesystem doesn't track creation
		// time (e.g. older NFS exports); ParseFloat returns 0 on
		// failure, which is what we want.
		btime, _ := strconv.ParseFloat(btimeStr, 64)
		ownerName, ownerUID := ids.resolveOwner(owner)
		groupName, groupGID := ids.resolveGroup(group)

		result = append(result, FileEntry{
			Name:         name,
			IsDir:        isDir,
			IsSymlink:    isLink,
			SizeBytes:    size,
			Permissions:  perms,
			ModeOctal:    octal,
			Owner:        ownerName,
			OwnerUID:     ownerUID,
			Group:        groupName,
			GroupGID:     groupGID,
			ModifiedUnix: int64(mtime),
			AccessedUnix: int64(atime),
			ChangedUnix:  int64(ctime),
			CreatedUnix:  int64(btime),
			Kind:         deriveKind(isDir, isLink, perms, name),
		})
	}

	// Sort: directories first, then files, both alphabetically.
	sort.Slice(result, func(i, j int) bool {
		if result[i].IsDir != result[j].IsDir {
			return result[i].IsDir
		}
		return strings.ToLower(result[i].Name) < strings.ToLower(result[j].Name)
	})

	// Stat the current directory itself (for the folder-level edit action).
	var currentDir *FileEntry
	if dirOut, err2 := exec.Command("sudo", "find", absPath, "-maxdepth", "0",
		"-printf", "%y\t%s\t%m\t%M\t%U\t%G\t%T@\t%A@\t%C@\t%B@\t%f\n").Output(); err2 == nil {
		line := strings.TrimRight(string(dirOut), "\n")
		if parts := strings.SplitN(line, "\t", 11); len(parts) == 11 {
			var sz int64
			sz, _ = strconv.ParseInt(parts[1], 10, 64)
			octal := strings.TrimLeft(parts[2], "0")
			if len(octal) < 3 {
				octal = strings.Repeat("0", 3-len(octal)) + octal
			}
			if len(octal) > 3 {
				octal = octal[len(octal)-3:]
			}
			mtime, _ := strconv.ParseFloat(parts[6], 64)
			atime, _ := strconv.ParseFloat(parts[7], 64)
			ctime, _ := strconv.ParseFloat(parts[8], 64)
			btime, _ := strconv.ParseFloat(parts[9], 64)
			ownerName, ownerUID := ids.resolveOwner(parts[4])
			groupName, groupGID := ids.resolveGroup(parts[5])
			currentDir = &FileEntry{
				Name:         parts[10],
				IsDir:        true,
				SizeBytes:    sz,
				Permissions:  parts[3],
				ModeOctal:    octal,
				Owner:        ownerName,
				OwnerUID:     ownerUID,
				Group:        groupName,
				GroupGID:     groupGID,
				ModifiedUnix: int64(mtime),
				AccessedUnix: int64(atime),
				ChangedUnix:  int64(ctime),
				CreatedUnix:  int64(btime),
				Kind:         "dir",
			}
		}
	}

	return &FileBrowserResult{
		RootLabel:  rootLabel,
		Subpath:    subpath,
		CurrentDir: currentDir,
		Entries:    result,
	}, nil
}

// ── GetSystemUsersGroups ──────────────────────────────────────────────────────

// UserEntry holds a system user's name and numeric UID.
type UserEntry struct {
	Name string `json:"name"`
	UID  int    `json:"uid"`
}

// GroupEntry holds a system group's name and numeric GID.
type GroupEntry struct {
	Name string `json:"name"`
	GID  int    `json:"gid"`
}

// GetSystemUsersGroups reads /etc/passwd and /etc/group and returns entries
// with UIDs/GIDs. Only root (UID/GID 0) and accounts with UID/GID ≥ 1000 are
// included. The "sambashare" group is always included regardless of its GID.
// root is always listed first; the rest are sorted alphabetically.
func GetSystemUsersGroups() (users []UserEntry, groups []GroupEntry, err error) {
	all, allGroups, err := getAllSystemUsersGroupsWithIDs()
	if err != nil {
		return
	}
	for _, u := range all {
		if u.Name == "root" || u.UID >= 1000 {
			users = append(users, u)
		}
	}
	// root first
	sort.Slice(users, func(i, j int) bool {
		if users[i].Name == "root" {
			return true
		}
		if users[j].Name == "root" {
			return false
		}
		return users[i].Name < users[j].Name
	})
	for _, g := range allGroups {
		if g.Name == "root" || g.GID >= 1000 || g.Name == "sambashare" {
			groups = append(groups, g)
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Name == "root" {
			return true
		}
		if groups[j].Name == "root" {
			return false
		}
		return groups[i].Name < groups[j].Name
	})
	return
}

// GetAllSystemUsersGroups returns all users and groups with no filtering.
func GetAllSystemUsersGroups() (users []UserEntry, groups []GroupEntry, err error) {
	return getAllSystemUsersGroupsWithIDs()
}

// getAllSystemUsersGroupsWithIDs reads all entries from /etc/passwd and /etc/group,
// returning name + numeric ID for each. root first, rest sorted alphabetically.
func getAllSystemUsersGroupsWithIDs() (users []UserEntry, groups []GroupEntry, err error) {
	{
		f, ferr := os.Open("/etc/passwd")
		if ferr != nil {
			return nil, nil, ferr
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		var regular []UserEntry
		var rootEntry *UserEntry
		for sc.Scan() {
			parts := strings.Split(sc.Text(), ":")
			if len(parts) < 3 || parts[0] == "" {
				continue
			}
			uid, _ := strconv.Atoi(parts[2])
			e := UserEntry{Name: parts[0], UID: uid}
			if parts[0] == "root" {
				rootEntry = &e
			} else {
				regular = append(regular, e)
			}
		}
		sort.Slice(regular, func(i, j int) bool { return regular[i].Name < regular[j].Name })
		if rootEntry != nil {
			users = append([]UserEntry{*rootEntry}, regular...)
		} else {
			users = regular
		}
	}
	{
		f, ferr := os.Open("/etc/group")
		if ferr != nil {
			return nil, nil, ferr
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		var regular []GroupEntry
		var rootEntry *GroupEntry
		for sc.Scan() {
			parts := strings.Split(sc.Text(), ":")
			if len(parts) < 3 || parts[0] == "" {
				continue
			}
			gid, _ := strconv.Atoi(parts[2])
			e := GroupEntry{Name: parts[0], GID: gid}
			if parts[0] == "root" {
				rootEntry = &e
			} else {
				regular = append(regular, e)
			}
		}
		sort.Slice(regular, func(i, j int) bool { return regular[i].Name < regular[j].Name })
		if rootEntry != nil {
			groups = append([]GroupEntry{*rootEntry}, regular...)
		} else {
			groups = regular
		}
	}
	return users, groups, nil
}

// ── userGroupExists ───────────────────────────────────────────────────────────

// numericIDRe matches a bare unsigned integer up to 10 digits — wide enough
// for any Linux UID/GID (they're uint32, max 4294967295, 10 digits) but
// narrow enough to keep ChownPath's owner/group strings free of shell
// metacharacters before they reach `sudo chown`.
var numericIDRe = regexp.MustCompile(`^[0-9]{1,10}$`)

// userExists accepts either a name present in /etc/passwd OR a bare
// numeric UID. The numeric path supports the File Browser's "Custom ID"
// dropdown entry — chown(1) takes numeric UIDs natively, and the
// `chown *` sudoers rule already covers them. Path scoping for the
// resulting chown is enforced by SafeJoin in the handler, so a numeric
// UID can't escape the dataset/share root the user is currently inside.
func userExists(owner string) bool {
	if numericIDRe.MatchString(owner) {
		return true
	}
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) >= 1 && parts[0] == owner {
			return true
		}
	}
	return false
}

// groupExists accepts either a name present in /etc/group OR a bare
// numeric GID — same rationale as userExists above.
func groupExists(group string) bool {
	if numericIDRe.MatchString(group) {
		return true
	}
	f, err := os.Open("/etc/group")
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ":")
		if len(parts) >= 1 && parts[0] == group {
			return true
		}
	}
	return false
}

// ── ChownPath ─────────────────────────────────────────────────────────────────

// ChownPath runs: sudo chown [-R] owner:group <absPath>
func ChownPath(absPath, owner, group string, recursive bool) error {
	if !userExists(owner) {
		return fmt.Errorf("user %q not found in /etc/passwd", owner)
	}
	if !groupExists(group) {
		return fmt.Errorf("group %q not found in /etc/group", group)
	}
	args := []string{"sudo", "chown"}
	if recursive {
		args = append(args, "-R")
	}
	args = append(args, owner+":"+group, absPath)
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("chown failed: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ── ChmodPath ─────────────────────────────────────────────────────────────────

var validMode = regexp.MustCompile(`^[0-7]{3}$`)

// ChmodPath runs: sudo chmod [-R] mode <absPath>
func ChmodPath(absPath, mode string, recursive bool) error {
	if !validMode.MatchString(mode) {
		return fmt.Errorf("invalid mode %q: must be a 3-digit octal string (000–777)", mode)
	}
	args := []string{"sudo", "chmod"}
	if recursive {
		args = append(args, "-R")
	}
	args = append(args, mode, absPath)
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("chmod failed: %w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ── ResolveKnownRoots ─────────────────────────────────────────────────────────

// ResolveKnownRoots builds the set of legal root paths from the current state:
// ZFS dataset mountpoints, SMB share paths, NFS share paths.
// map key = absolute path, value = human-readable label (e.g. "tank/media")
func ResolveKnownRoots(configDir string) (map[string]string, error) {
	roots := map[string]string{}

	// ZFS dataset mountpoints.
	datasets, err := ListAllDatasets()
	if err == nil {
		for _, d := range datasets {
			mp := d.Mountpoint
			if mp == "" || mp == "none" || mp == "-" || mp == "legacy" {
				continue
			}
			roots[mp] = d.Name
		}
	}

	// SMB share paths.
	smbShares, err := ListSMBShares(configDir)
	if err == nil {
		for _, s := range smbShares {
			if s.Path == "" {
				continue
			}
			label := s.Name
			if label == "" {
				label = s.Path
			}
			roots[s.Path] = "SMB: " + label
		}
	}

	// NFS share paths.
	nfsShares, err := ListNFSShares(configDir)
	if err == nil {
		for _, s := range nfsShares {
			if s.Path == "" {
				continue
			}
			label := s.Path
			roots[s.Path] = "NFS: " + label
		}
	}

	// Mounted external storages (v6.7.7 Filesystem rsync) — browsable while
	// mounted; unmounted storages disappear from the root list.
	for mp, label := range extKnownRoots() {
		roots[mp] = label
	}

	// MergerFS union mountpoints (v6.7.13) — browsable via the tab's File
	// Browser button.
	for mp, label := range mergerfsKnownRoots() {
		roots[mp] = label
	}

	if len(roots) == 0 {
		return roots, fmt.Errorf("no known roots found")
	}
	return roots, nil
}

// ── ValidateRootToken ─────────────────────────────────────────────────────────

// ValidateRootToken decodes a base64url root token and checks it against the
// known roots map. Returns the absolute path and label, or an error.
func ValidateRootToken(token string, knownRoots map[string]string) (absPath, label string, err error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", "", fmt.Errorf("invalid root token")
	}
	absPath = string(b)
	label, ok := knownRoots[absPath]
	if !ok {
		return "", "", fmt.Errorf("root path is not a known share or dataset mountpoint")
	}
	return absPath, label, nil
}

// ── SafeJoin ──────────────────────────────────────────────────────────────────

// SafeJoin joins root + subpath and verifies the result is still under root.
// Returns an error if the joined path escapes root (directory traversal attempt).
func SafeJoin(root, subpath string) (string, error) {
	if subpath == "" || subpath == "." {
		return filepath.Clean(root), nil
	}
	clean := filepath.Clean(subpath)
	if strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("invalid subpath: directory traversal not allowed")
	}
	joined := filepath.Join(root, clean)
	rootClean := filepath.Clean(root)
	if !strings.HasPrefix(joined, rootClean+string(filepath.Separator)) && joined != rootClean {
		return "", fmt.Errorf("invalid subpath: escapes root directory")
	}
	return joined, nil
}

// ─── v6.5.29 — full file browser ─────────────────────────────────────────────

// deriveKind classifies one entry into a coarse bucket the FE uses for
// icons + the File-type sort key. The bucket is derived purely from
// type + extension; no MIME sniffing (which would require opening every
// file in a 5,000-entry directory).
func deriveKind(isDir, isLink bool, perms, name string) string {
	if isDir {
		return "dir"
	}
	if isLink {
		return "link"
	}
	// `find`'s symbolic perms include the file type char at position 0
	// ("-" for regular, "d" for dir, "l" for link, …). Anything else
	// (block device, char device, fifo, socket) is rare in the paths
	// we browse and gets "file" so we don't pretend to know more.
	if len(perms) >= 4 {
		// Executable bit set anywhere → exec bucket. The display still
		// shows a normal file icon, but sort-by-type groups them.
		if strings.ContainsAny(perms[1:], "xs") && !isDir {
			// fall through to extension check first; if no extension
			// matches we'll come back to "exec" at the bottom.
		}
	}
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".tiff", ".tif",
		".svg", ".heic", ".heif", ".avif", ".ico":
		return "image"
	case ".mp4", ".mkv", ".mov", ".avi", ".wmv", ".webm", ".m4v", ".mpg",
		".mpeg", ".flv", ".3gp", ".ts":
		return "video"
	case ".mp3", ".flac", ".wav", ".ogg", ".m4a", ".aac", ".wma", ".opus":
		return "audio"
	case ".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz2", ".xz", ".txz",
		".7z", ".rar", ".zst", ".zstd":
		return "archive"
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".odt", ".ods", ".odp", ".epub", ".rtf", ".txt", ".md", ".csv":
		return "document"
	}
	// No extension match. Treat exec bit as the last-chance tiebreaker.
	if len(perms) >= 4 && strings.ContainsAny(perms[1:4], "xs") {
		return "exec"
	}
	return "file"
}

// ── Per-root mutex ────────────────────────────────────────────────────────────
//
// Two admins simultaneously running mv / cp / rm against the same root
// can race in unobvious ways (rm racing a move into the same dir, two
// pastes into the same dir clobbering each other's overwrite prompt).
// We serialise per absolute-root path. The map is small (one entry per
// known root) and entries are never deleted, so lock churn is nil.
var (
	fbMutexMapMu sync.Mutex
	fbMutexMap   = map[string]*sync.Mutex{}
)

func fbRootMutex(absRoot string) *sync.Mutex {
	fbMutexMapMu.Lock()
	defer fbMutexMapMu.Unlock()
	if m, ok := fbMutexMap[absRoot]; ok {
		return m
	}
	m := &sync.Mutex{}
	fbMutexMap[absRoot] = m
	return m
}

// ── Folder name validation ────────────────────────────────────────────────────

// validFolderName matches the same regex the FE enforces: 1..255 chars,
// no slash, no NUL, no leading/trailing whitespace. "." and ".." are
// rejected separately.
var validFolderName = regexp.MustCompile(`^[^/\x00\s][^/\x00]{0,253}[^/\x00\s]$|^[^/\x00\s]$`)

// MakeDir creates `name` inside root/subpath via `sudo mkdir -p`.
func MakeDir(absRoot, subpath, name string) error {
	if name == "." || name == ".." {
		return fmt.Errorf("invalid name: %q", name)
	}
	if !validFolderName.MatchString(name) {
		return fmt.Errorf("invalid name: must be 1..255 chars and contain no slash or NUL")
	}
	parent, err := SafeJoin(absRoot, subpath)
	if err != nil {
		return err
	}
	abs := filepath.Join(parent, name)
	// SafeJoin would normally reject a path with a slash in subpath,
	// but the FE may legitimately compose `<existing-sub>/<new-name>` —
	// re-check the final path is still under root.
	rootClean := filepath.Clean(absRoot)
	if !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) {
		return fmt.Errorf("invalid destination: escapes root")
	}
	mu := fbRootMutex(absRoot)
	mu.Lock()
	defer mu.Unlock()
	if _, err := os.Stat(abs); err == nil {
		return fmt.Errorf("a file or folder named %q already exists", name)
	}
	out, err := exec.Command("sudo", "mkdir", "-p", abs).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mkdir: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// UploadFile streams an uploaded file into root/subpath. relName is the
// file's name relative to subpath; for a folder drop it may contain
// "/"-separated path segments (intermediate directories are created with
// `sudo mkdir -p`). Every segment is validated with the same rule MakeDir
// uses. The bytes are first written to a temp file owned by the service
// account (the dataset roots are typically root:root mode 0770, so the
// service user can't write into them directly), then `sudo mv`'d into
// place and chowned to match the destination directory's owner/group so
// the new file behaves like its siblings over SMB/NFS.
//
// When overwrite is false and the destination already exists the error
// message contains "exists" so the FE can offer an overwrite prompt —
// mirroring the move/copy flow.
func UploadFile(absRoot, subpath, relName string, overwrite bool, src io.Reader) error {
	relName = strings.ReplaceAll(relName, `\`, "/") // tolerate Windows separators
	segs := strings.Split(relName, "/")
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return fmt.Errorf("invalid file name: %q", relName)
		}
		if !validFolderName.MatchString(s) {
			return fmt.Errorf("invalid file name segment %q: must be 1..255 chars and contain no slash or NUL", s)
		}
	}
	parentDir, err := SafeJoin(absRoot, subpath)
	if err != nil {
		return err
	}
	abs := filepath.Join(parentDir, filepath.FromSlash(relName))
	// SafeJoin only validated subpath; re-check the composed destination
	// (relName may add nested segments) is still under the root.
	rootClean := filepath.Clean(absRoot)
	if abs != rootClean && !strings.HasPrefix(abs, rootClean+string(filepath.Separator)) {
		return fmt.Errorf("invalid destination: escapes root")
	}

	mu := fbRootMutex(absRoot)
	mu.Lock()
	defer mu.Unlock()

	// Existence check (sudo stat works inside traverse-denied roots).
	if _, err := exec.Command("sudo", "stat", "-c", "%F", abs).Output(); err == nil {
		if !overwrite {
			return fmt.Errorf("a file or folder named %q already exists", filepath.Base(abs))
		}
	}

	// Make sure the (possibly nested) destination directory exists.
	destDir := filepath.Dir(abs)
	if out, err := exec.Command("sudo", "mkdir", "-p", destDir).CombinedOutput(); err != nil {
		return fmt.Errorf("mkdir: %s", strings.TrimSpace(string(out)))
	}

	// Stream the upload to a temp file owned by the service account.
	tmp, err := os.CreateTemp("", "znas-upload-*")
	if err != nil {
		return fmt.Errorf("temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the mv succeeds
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return fmt.Errorf("write upload: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write upload: %w", err)
	}
	// 0644 so the file is readable after the cross-device mv preserves
	// the temp's mode.
	_ = os.Chmod(tmpName, 0o644)

	// Move into place (mv -f: we've already enforced the overwrite policy
	// above). `--` guards against a destination beginning with '-'.
	if out, err := exec.Command("sudo", "mv", "-f", "--", tmpName, abs).CombinedOutput(); err != nil {
		return fmt.Errorf("mv: %s", strings.TrimSpace(string(out)))
	}

	// Match the destination directory's owner/group so the upload looks
	// like a native file in that share. Best-effort — a failure here
	// leaves the file owned by the service account, which is harmless.
	if out, err := exec.Command("sudo", "stat", "-c", "%u %g", destDir).Output(); err == nil {
		ug := strings.Fields(strings.TrimSpace(string(out)))
		if len(ug) == 2 {
			exec.Command("sudo", "chown", ug[0]+":"+ug[1], abs).Run() //nolint:errcheck
		}
	}
	return nil
}

// RemovePaths removes a list of subpaths under absRoot. The shell-out
// is a single invocation: `sudo rm -rf -- <abs1> <abs2> …` (-rf so
// non-empty dirs are handled and missing entries don't error out).
func RemovePaths(absRoot string, subpaths []string, recursive bool) error {
	if len(subpaths) == 0 {
		return fmt.Errorf("no paths to remove")
	}
	abs := make([]string, 0, len(subpaths))
	for _, sp := range subpaths {
		if sp == "" || sp == "." || sp == "/" {
			return fmt.Errorf("invalid subpath: %q", sp)
		}
		p, err := SafeJoin(absRoot, sp)
		if err != nil {
			return err
		}
		// Refuse to remove the root itself.
		if p == filepath.Clean(absRoot) {
			return fmt.Errorf("refusing to remove the root path")
		}
		abs = append(abs, p)
	}
	mu := fbRootMutex(absRoot)
	mu.Lock()
	defer mu.Unlock()
	args := []string{"rm"}
	if recursive {
		args = append(args, "-rf")
	} else {
		args = append(args, "-f")
	}
	args = append(args, "--")
	args = append(args, abs...)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rm: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// MovePaths / CopyPaths share the same source / destination validation
// path. dst is `dstAbsRoot/dstSubpath` (a directory); each source is
// SafeJoin'd against srcAbsRoot. Drop-into-self is refused (a folder
// cannot be moved into itself or any of its descendants).
func validateMoveCopy(srcAbsRoot string, srcSubpaths []string, dstAbsRoot, dstSubpath string) ([]string, string, error) {
	if len(srcSubpaths) == 0 {
		return nil, "", fmt.Errorf("no sources")
	}
	srcs := make([]string, 0, len(srcSubpaths))
	for _, sp := range srcSubpaths {
		if sp == "" || sp == "." || sp == "/" {
			return nil, "", fmt.Errorf("invalid source: %q", sp)
		}
		p, err := SafeJoin(srcAbsRoot, sp)
		if err != nil {
			return nil, "", err
		}
		srcs = append(srcs, p)
	}
	dst, err := SafeJoin(dstAbsRoot, dstSubpath)
	if err != nil {
		return nil, "", err
	}
	// Destination must already exist as a directory. Use sudo stat so
	// the check still works inside traverse-denied roots (the same
	// reason the raw / list / chown paths shell through sudo).
	out, ferr := exec.Command("sudo", "stat", "-c", "%F", dst).Output()
	if ferr != nil {
		return nil, "", fmt.Errorf("destination not found: %s", dst)
	}
	if !strings.Contains(string(out), "directory") {
		return nil, "", fmt.Errorf("destination is not a directory: %s", dst)
	}
	// Drop-into-self / into-descendant guard.
	for _, s := range srcs {
		if dst == s || strings.HasPrefix(dst, s+string(filepath.Separator)) {
			return nil, "", fmt.Errorf("cannot move/copy %q into itself or a subfolder of itself", s)
		}
	}
	return srcs, dst, nil
}

// MovePaths runs `sudo mv -n|-f -- <src…> <dst>`.
func MovePaths(srcAbsRoot string, srcSubpaths []string, dstAbsRoot, dstSubpath string, overwrite bool) error {
	srcs, dst, err := validateMoveCopy(srcAbsRoot, srcSubpaths, dstAbsRoot, dstSubpath)
	if err != nil {
		return err
	}
	// Lock both roots in a stable order so concurrent ops on the same
	// pair can't deadlock.
	a, b := srcAbsRoot, dstAbsRoot
	if a > b {
		a, b = b, a
	}
	mu1 := fbRootMutex(a)
	mu1.Lock()
	defer mu1.Unlock()
	if a != b {
		mu2 := fbRootMutex(b)
		mu2.Lock()
		defer mu2.Unlock()
	}
	flag := "-n"
	if overwrite {
		flag = "-f"
	}
	args := []string{"mv", flag, "--"}
	args = append(args, srcs...)
	args = append(args, dst)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("mv: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// RenamePath renames a single entry in place (same directory) to newName.
// newName is a bare filename — no path separators, no traversal. Uses the same
// privileged `sudo mv -n` as MovePaths so root-owned entries can be renamed, and
// the -n + pre-check guarantees an existing target is never clobbered.
func RenamePath(absRoot, subpath, newName string) error {
	newName = strings.TrimSpace(newName)
	if newName == "" || newName == "." || newName == ".." || strings.ContainsAny(newName, "/\\") {
		return fmt.Errorf("invalid name %q", newName)
	}
	src, err := SafeJoin(absRoot, subpath)
	if err != nil {
		return err
	}
	rootClean := filepath.Clean(absRoot)
	if src == rootClean {
		return fmt.Errorf("cannot rename the root directory")
	}
	dst := filepath.Join(filepath.Dir(src), newName)
	if dst != rootClean && !strings.HasPrefix(dst, rootClean+string(filepath.Separator)) {
		return fmt.Errorf("invalid destination")
	}
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("a file or folder named %q already exists", newName)
	}
	mu := fbRootMutex(absRoot)
	mu.Lock()
	defer mu.Unlock()
	if out, err := exec.Command("sudo", "mv", "-n", "--", src, dst).CombinedOutput(); err != nil {
		return fmt.Errorf("mv: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// CopyPaths runs `sudo cp -a -n|-f -- <src…> <dst>`. -a preserves
// mode / ownership / timestamps / xattrs and recurses into directories.
func CopyPaths(srcAbsRoot string, srcSubpaths []string, dstAbsRoot, dstSubpath string, overwrite bool) error {
	srcs, dst, err := validateMoveCopy(srcAbsRoot, srcSubpaths, dstAbsRoot, dstSubpath)
	if err != nil {
		return err
	}
	a, b := srcAbsRoot, dstAbsRoot
	if a > b {
		a, b = b, a
	}
	mu1 := fbRootMutex(a)
	mu1.Lock()
	defer mu1.Unlock()
	if a != b {
		mu2 := fbRootMutex(b)
		mu2.Lock()
		defer mu2.Unlock()
	}
	flag := "-n"
	if overwrite {
		flag = "-f"
	}
	args := []string{"cp", "-a", flag, "--"}
	args = append(args, srcs...)
	args = append(args, dst)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("cp: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ── TreeNode + WalkTree ──────────────────────────────────────────────────────

// TreeNode is one folder in the left-pane tree. Children is non-nil
// exactly when the node has been expanded; nil means "lazy — fetch on
// click". Files are not surfaced in the tree.
type TreeNode struct {
	Name        string     `json:"name"`         // basename ("" for the root itself)
	Subpath     string     `json:"subpath"`      // relative to root, "" for the root
	HasChildren bool       `json:"has_children"` // true when this folder has at least one sub-folder
	Children    []TreeNode `json:"children,omitempty"`
}

// WalkTree returns the folder tree rooted at absRoot/subpath with the
// given depth (1 = children only; 0 = the requested node alone).
func WalkTree(absRoot, subpath string, depth int) (TreeNode, error) {
	start, err := SafeJoin(absRoot, subpath)
	if err != nil {
		return TreeNode{}, err
	}
	if depth < 0 {
		depth = 1
	}
	if depth > 4 {
		depth = 4 // protect against runaway clients
	}
	node := TreeNode{
		Name:    filepath.Base(start),
		Subpath: subpath,
	}
	if subpath == "" {
		node.Name = ""
	}
	if depth == 0 {
		// Caller just wants to know whether this node has children.
		node.HasChildren = folderHasSubdir(start)
		return node, nil
	}
	// One find call per level — cheap and avoids spawning N sub-finds
	// for a folder with hundreds of subdirectories.
	maxDepth := strconv.Itoa(depth + 1) // +1 so we can detect HasChildren on the leaves
	out, err := exec.Command("sudo", "find", start,
		"-mindepth", "1",
		"-maxdepth", maxDepth,
		"-type", "d",
		"-printf", "%p\n",
	).Output()
	if err != nil {
		return node, nil // missing perms / empty — return the bare node
	}
	rootClean := filepath.Clean(start)
	subpathClean := filepath.Clean(subpath)
	if subpathClean == "." {
		subpathClean = ""
	}
	type k struct{ parent, name string }
	children := map[string][]TreeNode{} // parent-subpath → child nodes
	for _, line := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if line == "" {
			continue
		}
		// Translate absolute path → subpath relative to absRoot.
		rel := strings.TrimPrefix(line, filepath.Clean(absRoot)+string(filepath.Separator))
		if rel == line {
			continue // outside the root (shouldn't happen)
		}
		parent, name := filepath.Split(rel)
		parent = strings.TrimSuffix(parent, string(filepath.Separator))
		// Filter to the depth requested
		depthFromStart := strings.Count(strings.TrimPrefix(line, rootClean), string(filepath.Separator))
		if depthFromStart > depth {
			children[parent] = append(children[parent], TreeNode{
				Name: name, Subpath: rel, HasChildren: true,
			})
		} else {
			children[parent] = append(children[parent], TreeNode{
				Name: name, Subpath: rel,
			})
		}
		_ = k{parent, name}
	}
	// Stitch the tree top-down from subpathClean.
	var stitch func(sp string) []TreeNode
	stitch = func(sp string) []TreeNode {
		raw := children[sp]
		if len(raw) == 0 {
			return nil
		}
		sort.Slice(raw, func(i, j int) bool {
			return strings.ToLower(raw[i].Name) < strings.ToLower(raw[j].Name)
		})
		// Deduplicate (the +1 depth produced grand-children entries
		// for HasChildren detection; we keep the parent node and
		// drop duplicates).
		seen := map[string]bool{}
		out := make([]TreeNode, 0, len(raw))
		for _, n := range raw {
			if seen[n.Subpath] {
				continue
			}
			seen[n.Subpath] = true
			// Expand one more level into Children unless this node
			// already came from the deepest level (HasChildren=true
			// without Children).
			kids := stitch(n.Subpath)
			if len(kids) > 0 {
				n.HasChildren = true
				n.Children = kids
			}
			out = append(out, n)
		}
		return out
	}
	node.Children = stitch(subpathClean)
	node.HasChildren = len(node.Children) > 0
	return node, nil
}

// folderHasSubdir returns true when `path` contains at least one
// sub-directory. Used by the lazy-tree path.
func folderHasSubdir(path string) bool {
	out, err := exec.Command("sudo", "find", path, "-mindepth", "1", "-maxdepth", "1", "-type", "d", "-printf", ".").Output()
	if err != nil {
		return false
	}
	return len(out) > 0
}
