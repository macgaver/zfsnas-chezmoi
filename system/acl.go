package system

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// ACL settings of a dataset — the four ZFS properties that decide which
// permission model the files on it follow. A pool imported from another
// product (TrueNAS above all) often carries settings that suit that product
// and not this one; these helpers let the UI show them, explain what they
// break, and switch them with one preset.

// ACLProps are the properties a preset sets, in display order.
var ACLProps = []string{"acltype", "aclmode", "aclinherit", "xattr"}

// ReviewProp is a user property on the pool's root dataset that remembers the
// import-review findings the admin chose to ignore (a hash of them). It
// travels with the pool, so a dismissed banner stays dismissed after a
// re-import, and a new finding brings it back.
const ReviewProp = "zfsnas:acl-review"

// ACL presets. The values written for "nfsv4" are the ones the SMB share's
// Windows ACL option writes (SetWindowsACLDatasetProps), so both stay one
// mode. aclmode and aclinherit only act on NFSv4 ACLs, so "posix" leaves them.
const (
	PresetPOSIX   = "posix"
	PresetNFSv4   = "nfsv4"
	PresetOff     = "off"
	PresetInherit = "inherit"
	PresetCustom  = "custom"
)

func presetProps(preset string) (map[string]string, bool) {
	switch preset {
	case PresetPOSIX:
		return map[string]string{"acltype": "posixacl", "xattr": "sa"}, true
	case PresetNFSv4:
		return map[string]string{"acltype": "nfsv4", "aclinherit": "passthrough", "aclmode": "passthrough", "xattr": "sa"}, true
	case PresetOff:
		return map[string]string{"acltype": "off"}, true
	case PresetInherit:
		m := map[string]string{}
		for _, p := range ACLProps {
			m[p] = "inherit"
		}
		return m, true
	}
	return nil, false
}

// ACLProp is one property: its value and where the value comes from.
type ACLProp struct {
	Value  string `json:"value"`
	Source string `json:"source"`         // local | default | inherited | received
	From   string `json:"from,omitempty"` // dataset it is inherited from
}

// DatasetACL is one filesystem dataset with its ACL settings.
type DatasetACL struct {
	Name       string             `json:"name"`
	Mountpoint string             `json:"mountpoint"`
	Props      map[string]ACLProp `json:"props"`
	Preset     string             `json:"preset"`
	Skip       string             `json:"skip,omitempty"` // left alone by recursive changes and the review
}

// ACLShareRef is one consumer of a dataset that cares about its ACL mode.
type ACLShareRef struct {
	Kind       string `json:"kind"` // smb | nfs | virtiofs
	Name       string `json:"name"` // share name, export path or VM name
	Path       string `json:"path"`
	WindowsACL bool   `json:"windows_acl,omitempty"`
}

// ACLIssue is a problem with a dataset's ACL settings for the way it is used.
type ACLIssue struct {
	Code  string `json:"code"`
	Level string `json:"level"` // error | warn | info
	Text  string `json:"text"`
	Fix   string `json:"fix"` // preset that solves it
}

// ClassifyACLPreset names the mode the properties put the dataset in.
func ClassifyACLPreset(props map[string]ACLProp) string {
	switch props["acltype"].Value {
	case "posix", "posixacl":
		return PresetPOSIX
	case "nfsv4":
		return PresetNFSv4
	case "off", "noacl":
		return PresetOff
	}
	return PresetCustom
}

// ACLIssues lists what is wrong with d for the consumers in use.
func ACLIssues(d DatasetACL, use []ACLShareRef) []ACLIssue {
	var winShares, vfs []string
	for _, u := range use {
		switch {
		case u.Kind == "smb" && u.WindowsACL:
			winShares = append(winShares, u.Name)
		case u.Kind == "virtiofs":
			vfs = append(vfs, u.Name)
		}
	}
	preset := ClassifyACLPreset(d.Props)
	var out []ACLIssue
	if len(vfs) > 0 && preset != PresetPOSIX {
		lvl, why := "warn", "VirtIO-FS needs POSIX ACLs on the host directory."
		if preset == PresetNFSv4 {
			lvl, why = "error", "With NFSv4 ACLs the VM can mount the share but listing its folders fails (\"Operation not supported\")."
		}
		out = append(out, ACLIssue{Code: "virtiofs-needs-posix", Level: lvl, Fix: PresetPOSIX,
			Text: "Shared to " + joinNames(vfs) + " over VirtIO-FS. " + why})
	}
	if len(winShares) > 0 && preset != PresetNFSv4 {
		out = append(out, ACLIssue{Code: "windows-acl-mismatch", Level: "warn", Fix: PresetNFSv4,
			Text: "SMB share " + joinNames(winShares) + " has Windows ACL on, which expects NFSv4 ACLs here."})
	}
	if preset == PresetNFSv4 && len(winShares) == 0 {
		out = append(out, ACLIssue{Code: "nfsv4-unused", Level: "warn", Fix: PresetPOSIX,
			Text: "NFSv4 ACLs without an SMB share using Windows ACL: Linux cannot edit them (setfacl fails with \"Operation not supported\"). Pools from TrueNAS usually come this way."})
	}
	if preset == PresetNFSv4 && d.Props["aclmode"].Value == "restricted" {
		fix := PresetPOSIX
		if len(winShares) > 0 {
			fix = PresetNFSv4
		}
		out = append(out, ACLIssue{Code: "aclmode-restricted", Level: "warn", Fix: fix,
			Text: "aclmode=restricted: chmod is refused on any file that carries an ACL (\"Operation not permitted\")."})
	}
	// Only "dir" is flagged: ZFS 2.2+ shows xattr=sa as "on" (on now means
	// sa), so "on" cannot tell the two apart there.
	if (preset == PresetPOSIX || preset == PresetNFSv4) && d.Props["xattr"].Value == "dir" {
		out = append(out, ACLIssue{Code: "xattr-not-sa", Level: "info", Fix: preset,
			Text: "ACLs are stored as hidden files (xattr=dir), which is slow; xattr=sa is faster. It only applies to files written after the change."})
	}
	return out
}

// SuggestedPreset is the preset that fixes the serious issues (or "" when
// there is nothing to fix). VirtIO-FS wins a conflict with a Windows ACL
// share: a VM that cannot list its folders is the worse outcome.
func SuggestedPreset(issues []ACLIssue) string {
	fix := ""
	for _, is := range issues {
		if is.Level == "info" {
			continue
		}
		if is.Code == "virtiofs-needs-posix" {
			return PresetPOSIX
		}
		if fix == "" {
			fix = is.Fix
		}
	}
	return fix
}

func joinNames(n []string) string {
	q := make([]string, len(n))
	for i, s := range n {
		q[i] = "\"" + s + "\""
	}
	if len(q) <= 3 {
		return strings.Join(q, ", ")
	}
	return strings.Join(q[:3], ", ") + fmt.Sprintf(" and %d more", len(q)-3)
}

// ACLUsageFor picks the consumers of dataset ds out of refs. A share covers
// the dataset its path resolves to and, because clients can walk into child
// datasets mounted below it, every dataset mounted under that path.
// mounts maps mountpoint → dataset name for every mounted filesystem.
func ACLUsageFor(ds DatasetACL, refs []ACLShareRef, mounts map[string]string) []ACLShareRef {
	var out []ACLShareRef
	mp := strings.TrimRight(ds.Mountpoint, "/")
	for _, r := range refs {
		p := strings.TrimRight(r.Path, "/")
		if p == "" {
			continue
		}
		if ResolveDatasetByPath(mounts, p) == ds.Name || (strings.HasPrefix(mp, "/") && strings.HasPrefix(mp, p+"/")) {
			out = append(out, r)
		}
	}
	return out
}

// ResolveDatasetByPath returns the dataset whose mountpoint holds path (the
// longest match), or "".
func ResolveDatasetByPath(mounts map[string]string, path string) string {
	path = strings.TrimRight(path, "/")
	best, bestLen := "", -1
	for mp, name := range mounts {
		if !strings.HasPrefix(mp, "/") {
			continue
		}
		m := strings.TrimRight(mp, "/")
		if path == m || strings.HasPrefix(path, m+"/") || m == "" {
			if len(m) > bestLen {
				best, bestLen = name, len(m)
			}
		}
	}
	return best
}

// MountMap returns mountpoint → dataset for every mounted filesystem.
func MountMap() map[string]string {
	out, err := exec.Command("sudo", "zfs", "list", "-H", "-t", "filesystem", "-o", "name,mountpoint").Output()
	m := map[string]string{}
	if err != nil {
		return m
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.SplitN(line, "\t", 2)
		if len(f) == 2 && strings.HasPrefix(f[1], "/") {
			m[f[1]] = f[0]
		}
	}
	return m
}

// ACLTree returns root and every filesystem below it with their ACL
// settings, parents first. Unmounted subtrees (Incus storage, backup targets)
// and replication destinations are marked Skip, as for recursive snapshots.
func ACLTree(root string, skipDest map[string]bool) ([]DatasetACL, error) {
	out, err := exec.Command("sudo", "zfs", "get", "-H", "-r", "-t", "filesystem",
		"-o", "name,property,value,source", strings.Join(append(ACLProps, "mountpoint"), ","), root).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return parseACLTree(string(out), skipDest), nil
}

func parseACLTree(out string, skipDest map[string]bool) []DatasetACL {
	var list []DatasetACL
	idx := map[string]int{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		i, ok := idx[f[0]]
		if !ok {
			i = len(list)
			idx[f[0]] = i
			list = append(list, DatasetACL{Name: f[0], Props: map[string]ACLProp{}})
		}
		if f[1] == "mountpoint" {
			list[i].Mountpoint = f[2]
			continue
		}
		list[i].Props[f[1]] = parseACLSource(f[2], f[3])
	}
	tree := make([]TreeDataset, len(list))
	for i, d := range list {
		tree[i] = TreeDataset{Name: d.Name, Type: "filesystem", Mountpoint: d.Mountpoint}
	}
	classifyTree(tree, skipDest)
	for i := range list {
		list[i].Skip = tree[i].Skip
		list[i].Preset = ClassifyACLPreset(list[i].Props)
	}
	return list
}

func parseACLSource(value, src string) ACLProp {
	p := ACLProp{Value: value, Source: src}
	switch {
	case strings.HasPrefix(src, "inherited from "):
		p.Source, p.From = "inherited", strings.TrimPrefix(src, "inherited from ")
	case src == "local", src == "default", src == "received":
	default:
		p.Source = "default"
	}
	return p
}

// ACLChange is the plan for switching a dataset to a preset.
type ACLChange struct {
	Set     map[string]string            `json:"set"`               // props written on the dataset ("inherit" = zfs inherit)
	Follow  []string                     `json:"follow"`            // children reset to inherit, so they take the new mode
	Pin     map[string]map[string]string `json:"pin"`               // children whose inherited values are written locally first, so they keep them
	Skipped map[string]string            `json:"skipped,omitempty"` // children left as they are, with why
}

// PlanACLChange works out what switching tree[0] to preset touches.
//
// ZFS properties inherit, so changing a dataset also changes every child that
// inherits from it. Children the change must not reach (protected: unmounted
// Incus/backup storage, replication destinations, or a share that needs the
// other mode; and all children when recursive is off) get their current
// values written locally first, so they stay exactly as they are. With
// recursive on, the other children drop their local values and follow.
// protect returns why a child must keep its mode under preset ("" = it may follow).
func PlanACLChange(tree []DatasetACL, preset string, recursive bool, protect func(DatasetACL) string) (ACLChange, error) {
	set, ok := presetProps(preset)
	if !ok {
		return ACLChange{}, fmt.Errorf("unknown preset %q", preset)
	}
	if len(tree) == 0 {
		return ACLChange{}, fmt.Errorf("dataset not found")
	}
	root := tree[0].Name
	ch := ACLChange{Set: set, Pin: map[string]map[string]string{}, Skipped: map[string]string{}}
	// cut[prop] holds children already pinned, local or following, so a
	// deeper child inheriting through them needs nothing of its own.
	cut := map[string]map[string]bool{}
	for _, p := range ACLProps {
		cut[p] = map[string]bool{}
	}
	insideCut := func(prop, name string) bool {
		for n := range cut[prop] {
			if strings.HasPrefix(name, n+"/") {
				return true
			}
		}
		return false
	}
	// A child below one that keeps its mode keeps it too: following would
	// make it inherit from that (pinned) parent, not take the new mode.
	keptAbove := func(name string) string {
		for n := range ch.Skipped {
			if strings.HasPrefix(name, n+"/") {
				return n
			}
		}
		return ""
	}
	for _, d := range tree[1:] {
		reason := d.Skip
		if reason == "" {
			if k := keptAbove(d.Name); k != "" {
				reason = "inside " + k
			}
		}
		if reason == "" && protect != nil {
			reason = protect(d)
		}
		if reason == "" && !recursive {
			reason = "only this dataset is changed"
		}
		follow := reason == ""
		if follow {
			ch.Follow = append(ch.Follow, d.Name)
		} else {
			ch.Skipped[d.Name] = reason
		}
		for _, prop := range ACLProps {
			if insideCut(prop, d.Name) {
				continue
			}
			v := d.Props[prop]
			reaches := v.Source == "default" ||
				(v.Source == "inherited" && (v.From == root || !strings.HasPrefix(v.From, root+"/")))
			if follow {
				// Takes the new value either way when it inherits; a local
				// value is dropped (in Apply) so it follows from now on.
				cut[prop][d.Name] = true
				continue
			}
			if v.Source == "local" || v.Source == "received" {
				cut[prop][d.Name] = true
				continue
			}
			if reaches {
				if ch.Pin[d.Name] == nil {
					ch.Pin[d.Name] = map[string]string{}
				}
				ch.Pin[d.Name][prop] = v.Value
				cut[prop][d.Name] = true
			}
		}
	}
	sort.Strings(ch.Follow)
	return ch, nil
}

// ApplyACLChange carries out a plan on root: pins first (so nothing the
// change must not reach ever sees the new value), then the dataset, then the
// followers.
func ApplyACLChange(root string, ch ACLChange) error {
	names := make([]string, 0, len(ch.Pin))
	for n := range ch.Pin {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := SetDatasetProps(n, ch.Pin[n]); err != nil {
			return fmt.Errorf("keeping %s as it is: %w (nothing else was changed)", n, err)
		}
	}
	if err := SetDatasetProps(root, ch.Set); err != nil {
		return err
	}
	for _, n := range ch.Follow {
		for _, p := range ACLProps {
			if out, err := exec.Command("sudo", "zfs", "inherit", p, n).CombinedOutput(); err != nil {
				return fmt.Errorf("%s changed, but %s could not follow: %s", root, n, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

// ReviewSignature is a stable hash of a set of findings, stored in
// ReviewProp when the admin dismisses them.
func ReviewSignature(keys []string) string {
	k := append([]string(nil), keys...)
	sort.Strings(k)
	h := sha256.Sum256([]byte(strings.Join(k, "\n")))
	return hex.EncodeToString(h[:8])
}

// GetReviewDismissed returns the signature stored on the pool ("" if none).
func GetReviewDismissed(pool string) string {
	out, err := exec.Command("sudo", "zfs", "get", "-H", "-o", "value", ReviewProp, pool).Output()
	if err != nil {
		return ""
	}
	v := strings.TrimSpace(string(out))
	if v == "-" {
		return ""
	}
	return v
}

// SetReviewDismissed stores sig on the pool's root dataset.
func SetReviewDismissed(pool, sig string) error {
	return SetDatasetProps(pool, map[string]string{ReviewProp: sig})
}
