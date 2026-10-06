// Configuration backup & migration: the system-level halves of export and
// import (Linux accounts, SMB password hashes, ZFS pools by GUID, Incus
// networks/profiles/datastores/instances and recovery). The archive format
// itself lives in internal/backup; orchestration in handlers/backup.go.
package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// LinuxAccount is a portal-managed Linux account as carried in a backup.
type LinuxAccount struct {
	Name     string   `json:"name"`
	UID      int      `json:"uid"`
	GID      int      `json:"gid"`
	Group    string   `json:"group"`  // primary group name
	Groups   []string `json:"groups"` // supplementary groups (sambashare, sudo, …)
	Shell    string   `json:"shell"`
	Home     string   `json:"home"`
	GECOS    string   `json:"gecos"`
	Hash     string   `json:"hash,omitempty"` // shadow hash; "" when it could not be read
	HasLogin bool     `json:"has_login"`
}

var groupPath = "/etc/group"

// ExportLinuxAccounts returns the Linux accounts of the given portal users
// that the portal manages (accountManaged); others are skipped silently —
// a reused account belongs to the server owner, not to the backup.
func ExportLinuxAccounts(usernames []string) (accts []LinuxAccount, warnings []string) {
	groups := readGroups(groupPath)
	for _, u := range usernames {
		e, ok := lookupPasswdFull(passwdPath, u)
		if !ok {
			continue
		}
		if managed, _ := accountManaged(u); !managed {
			continue
		}
		a := LinuxAccount{Name: u, UID: e.UID, GID: e.GID, Shell: e.Shell, Home: e.Home, GECOS: e.GECOS,
			HasLogin: !noLoginShell(e.Shell)}
		for name, g := range groups {
			if g.gid == e.GID {
				a.Group = name
			}
			for _, m := range g.members {
				if m == u {
					a.Groups = append(a.Groups, name)
				}
			}
		}
		sort.Strings(a.Groups)
		if a.HasLogin {
			if h, err := shadowHash(u); err == nil {
				a.Hash = h
			} else {
				warnings = append(warnings, fmt.Sprintf("the SSH password of %q could not be read (%v); set it again after the import", u, err))
			}
		}
		accts = append(accts, a)
	}
	return accts, warnings
}

type passwdFull struct {
	UID, GID           int
	GECOS, Home, Shell string
}

func lookupPasswdFull(path, name string) (passwdFull, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return passwdFull{}, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 || f[0] != name {
			continue
		}
		uid, _ := strconv.Atoi(f[2])
		gid, _ := strconv.Atoi(f[3])
		return passwdFull{UID: uid, GID: gid, GECOS: f[4], Home: f[5], Shell: strings.TrimSpace(f[6])}, true
	}
	return passwdFull{}, false
}

type groupEntry struct {
	gid     int
	members []string
}

func readGroups(path string) map[string]groupEntry {
	out := map[string]groupEntry{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 {
			continue
		}
		gid, _ := strconv.Atoi(f[2])
		var members []string
		for _, m := range strings.Split(f[3], ",") {
			if m = strings.TrimSpace(m); m != "" {
				members = append(members, m)
			}
		}
		out[f[0]] = groupEntry{gid: gid, members: members}
	}
	return out
}

// shadowHash reads one account's password hash (root-only file → sudo getent).
func shadowHash(user string) (string, error) {
	var out []byte
	var err error
	if os.Geteuid() == 0 {
		out, err = exec.Command("getent", "shadow", user).Output()
	} else {
		out, err = exec.Command("sudo", "-n", "getent", "shadow", user).Output()
	}
	if err != nil {
		return "", errors.New("not allowed to read it")
	}
	f := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(f) < 2 {
		return "", errors.New("unexpected getent output")
	}
	return f[1], nil
}

// RestoreLinuxAccount recreates an account with its original uid/gid, so the
// files it owns on the imported pools keep the right owner. An existing
// account is accepted only when it already has the same uid (then it is just
// brought up to date); anything else is a conflict and is not touched.
func RestoreLinuxAccount(a LinuxAccount) error {
	if !validUnixName.MatchString(a.Name) || a.UID < 1000 || a.GID < 1000 && a.GID != 100 {
		return fmt.Errorf("refusing account %q (uid %d, gid %d)", a.Name, a.UID, a.GID)
	}
	if e, ok := lookupPasswdFull(passwdPath, a.Name); ok {
		if e.UID != a.UID {
			return fmt.Errorf("a different account named %q already exists here (uid %d, backup has %d)", a.Name, e.UID, a.UID)
		}
	} else {
		if owner := uidOwner(passwdPath, a.UID); owner != "" {
			return fmt.Errorf("uid %d of %q is already used by %q on this server", a.UID, a.Name, owner)
		}
		groups := readGroups(groupPath)
		grp := a.Group
		if grp == "" {
			grp = a.Name
		}
		if g, ok := groups[grp]; !ok {
			if out, err := runRoot("groupadd", "-g", strconv.Itoa(a.GID), grp); err != nil {
				return fmt.Errorf("groupadd %s: %s", grp, out)
			}
		} else if g.gid != a.GID {
			return fmt.Errorf("group %q exists here with gid %d (backup has %d)", grp, g.gid, a.GID)
		}
		shell := a.Shell
		if shell == "" {
			shell = "/usr/sbin/nologin"
		}
		args := []string{"-u", strconv.Itoa(a.UID), "-g", strconv.Itoa(a.GID), "-s", shell, "-c", portalAccountComment}
		if a.HasLogin {
			args = append(args, "-m")
		} else {
			args = append(args, "-M")
		}
		if a.Hash != "" {
			args = append(args, "-p", a.Hash)
		}
		args = append(args, a.Name)
		if out, err := runRoot("useradd", args...); err != nil {
			return fmt.Errorf("useradd %s: %s", a.Name, out)
		}
	}
	for _, g := range a.Groups {
		switch g {
		case "sambashare":
			_, _ = runRoot("usermod", "-aG", "sambashare", a.Name)
		case sudoGroup:
			if a.HasLogin {
				_, _ = runRoot("gpasswd", "-a", a.Name, sudoGroup)
			}
		}
	}
	return SyncAuthToPersistStore()
}

// AccountConflict describes why RestoreLinuxAccount would refuse an account,
// without changing anything ("" = it can be restored).
func AccountConflict(a LinuxAccount) string {
	if e, ok := lookupPasswdFull(passwdPath, a.Name); ok {
		if e.UID != a.UID {
			return fmt.Sprintf("a different account %q exists here (uid %d)", a.Name, e.UID)
		}
		return ""
	}
	if owner := uidOwner(passwdPath, a.UID); owner != "" {
		return fmt.Sprintf("uid %d is used here by %q", a.UID, owner)
	}
	if g, ok := readGroups(groupPath)[a.Group]; ok && a.Group != "" && g.gid != a.GID {
		return fmt.Sprintf("group %q exists here with gid %d", a.Group, g.gid)
	}
	return ""
}

func uidOwner(path string, uid int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && f[2] == strconv.Itoa(uid) {
			return f[0]
		}
	}
	return ""
}

// runRoot runs a command as root: directly on the appliance (the portal is
// root there), through sudo elsewhere.
func runRoot(name string, args ...string) (string, error) {
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command(name, args...)
	} else {
		cmd = exec.Command("sudo", append([]string{name}, args...)...)
	}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// ExportSMBHashes returns the smbpasswd-format lines (`pdbedit -L -w`) of the
// given users — the NT hashes Samba authenticates with.
func ExportSMBHashes(usernames []string) (string, error) {
	pdb, err := exec.LookPath("pdbedit")
	if err != nil {
		return "", errors.New("pdbedit not found")
	}
	var out []byte
	if os.Geteuid() == 0 {
		out, err = exec.Command(pdb, "-L", "-w").Output()
	} else {
		out, err = exec.Command("sudo", "-n", pdb, "-L", "-w").Output()
	}
	if err != nil {
		return "", errors.New("not allowed to read the Samba password database")
	}
	want := map[string]bool{}
	for _, u := range usernames {
		want[u] = true
	}
	var b strings.Builder
	for _, line := range strings.Split(string(out), "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && want[name] {
			b.WriteString(line + "\n")
		}
	}
	return b.String(), nil
}

// ImportSMBHashes loads smbpasswd-format lines into Samba's tdbsam backend
// and returns the users that are in the database afterwards.
//
// pdbedit's smbpasswd backend locks the file it reads, which silently yields
// nothing on a pipe, so stdin must be a regular file: a private temp file,
// unlinked as soon as it is open so the hashes never sit at a path. pdbedit
// also exits 0 when it rejects an entry, so the result is checked by reading
// the database back.
func ImportSMBHashes(lines string) ([]string, error) {
	var names []string
	for _, line := range strings.Split(lines, "\n") {
		if name, _, ok := strings.Cut(line, ":"); ok && name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	pdb, err := exec.LookPath("pdbedit")
	if err != nil {
		return nil, errors.New("pdbedit not found")
	}
	f, err := os.CreateTemp("", "znas-smbimport-*")
	if err != nil {
		return nil, err
	}
	os.Remove(f.Name())
	defer f.Close()
	if _, err := f.WriteString(lines); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	var cmd *exec.Cmd
	if os.Geteuid() == 0 {
		cmd = exec.Command(pdb, "-i", "smbpasswd:/dev/stdin", "-e", "tdbsam")
	} else {
		cmd = exec.Command("sudo", "-n", pdb, "-i", "smbpasswd:/dev/stdin", "-e", "tdbsam")
	}
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("pdbedit import: %s", strings.TrimSpace(string(out)))
	}
	back, err := ExportSMBHashes(names)
	if err != nil {
		return nil, err
	}
	var done, missing []string
	for _, n := range names {
		if strings.Contains("\n"+back, "\n"+n+":") {
			done = append(done, n)
		} else {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return done, fmt.Errorf("not restored for %s: %s", strings.Join(missing, ", "), strings.TrimSpace(string(out)))
	}
	return done, nil
}

// PoolGUIDs maps imported pool names to their GUIDs.
func PoolGUIDs() map[string]string {
	out := map[string]string{}
	b, err := exec.Command("sudo", "zpool", "list", "-H", "-o", "name,guid").Output()
	if err != nil {
		b, err = exec.Command("zpool", "list", "-H", "-o", "name,guid").Output()
		if err != nil {
			return out
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if f := strings.Fields(line); len(f) == 2 {
			out[f[0]] = f[1]
		}
	}
	return out
}

// ImportPoolByGUID imports a pool identified by its GUID (names can clash on
// the target). force adds -f for a pool last used by another system — the
// normal case when disks were moved without exporting the pool first.
func ImportPoolByGUID(guid string, force bool) error {
	args := []string{"zpool", "import", "-o", "cachefile=/etc/zfs/zpool.cache"}
	if force {
		args = append(args, "-f")
	}
	args = append(args, guid)
	out, err := exec.Command("sudo", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if !force && (strings.Contains(msg, "another system") || strings.Contains(msg, "-f")) {
			return fmt.Errorf("pool was last used by another system; enable \"force import\" (%s)", msg)
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// ── Incus ────────────────────────────────────────────────────────────────

// IncusNamedConfig is a network or profile as stored in a backup.
type IncusNamedConfig struct {
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config"` // the /1.0 object as returned by the API
}

// IncusInventory is what a backup carries about virtualization.
type IncusInventory struct {
	Storage   []IncusStorageRef  `json:"storage"`
	Instances []IncusInstanceRef `json:"instances"`
	Networks  []IncusNamedConfig `json:"networks"` // managed networks used by instances
	Profiles  []IncusNamedConfig `json:"profiles"` // profiles used by instances
}

// IncusStorageRef is a datastore.
type IncusStorageRef struct {
	Name   string `json:"name"`
	Driver string `json:"driver"`
	Source string `json:"source"`
}

// IncusInstanceRef is one instance with what it depends on.
type IncusInstanceRef struct {
	Name     string            `json:"name"`
	Type     string            `json:"type"`
	Pool     string            `json:"pool"`
	Profiles []string          `json:"profiles"`
	NICs     map[string]NICRef `json:"nics"` // device name → network/parent
}

// NICRef is a NIC's attachment.
type NICRef struct {
	Network string `json:"network,omitempty"` // managed network
	Parent  string `json:"parent,omitempty"`  // host bridge (nictype bridged)
}

// ExportIncusInventory collects datastores, instances and the networks and
// profiles those instances need. Returns an empty inventory when Incus is
// not available.
func ExportIncusInventory() (IncusInventory, error) {
	var inv IncusInventory
	if _, err := exec.LookPath("incus"); err != nil {
		return inv, nil
	}
	var pools []struct {
		Name   string            `json:"name"`
		Driver string            `json:"driver"`
		Config map[string]string `json:"config"`
	}
	if err := incusQuery("/1.0/storage-pools?recursion=1", &pools); err != nil {
		return inv, err
	}
	for _, p := range pools {
		inv.Storage = append(inv.Storage, IncusStorageRef{Name: p.Name, Driver: p.Driver, Source: p.Config["source"]})
	}
	var insts []struct {
		Name            string                       `json:"name"`
		Type            string                       `json:"type"`
		Profiles        []string                     `json:"profiles"`
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if err := incusQuery("/1.0/instances?recursion=1", &insts); err != nil {
		return inv, err
	}
	needNet, needProf := map[string]bool{}, map[string]bool{}
	for _, in := range insts {
		ref := IncusInstanceRef{Name: in.Name, Type: in.Type, Profiles: in.Profiles, NICs: map[string]NICRef{}}
		for dev, d := range in.ExpandedDevices {
			switch d["type"] {
			case "disk":
				if d["path"] == "/" {
					ref.Pool = d["pool"]
				}
			case "nic":
				ref.NICs[dev] = NICRef{Network: d["network"], Parent: d["parent"]}
				if d["network"] != "" {
					needNet[d["network"]] = true
				}
			}
		}
		for _, p := range in.Profiles {
			needProf[p] = true
		}
		inv.Instances = append(inv.Instances, ref)
	}
	for name := range needProf {
		var raw json.RawMessage
		if err := incusQuery("/1.0/profiles/"+name, &raw); err == nil {
			inv.Profiles = append(inv.Profiles, IncusNamedConfig{Name: name, Config: raw})
			// A profile NIC overridden by every instance is still validated
			// when the profile is recreated, so its network must travel too.
			var p struct {
				Devices map[string]map[string]string `json:"devices"`
			}
			if json.Unmarshal(raw, &p) == nil {
				for _, d := range p.Devices {
					if d["type"] == "nic" && d["network"] != "" {
						needNet[d["network"]] = true
					}
				}
			}
		}
	}
	for name := range needNet {
		var raw json.RawMessage
		if err := incusQuery("/1.0/networks/"+name, &raw); err == nil {
			inv.Networks = append(inv.Networks, IncusNamedConfig{Name: name, Config: raw})
		}
	}
	return inv, nil
}

func incusQuery(path string, v any) error {
	out, err := exec.Command("incus", "query", path).Output()
	if err != nil {
		return fmt.Errorf("incus query %s: %w", path, err)
	}
	return json.Unmarshal(out, v)
}

// IncusNetworkExists / IncusProfileExists check the target.
func IncusNetworkExists(name string) bool {
	return exec.Command("incus", "query", "/1.0/networks/"+name).Run() == nil
}
func IncusProfileExists(name string) bool {
	return exec.Command("incus", "query", "/1.0/profiles/"+name).Run() == nil
}

// CreateIncusNetworkFromBackup recreates a managed network (bridge type
// only — other types depend on host hardware) from its backed-up object.
func CreateIncusNetworkFromBackup(n IncusNamedConfig) error {
	var obj struct {
		Type        string            `json:"type"`
		Managed     bool              `json:"managed"`
		Description string            `json:"description"`
		Config      map[string]string `json:"config"`
	}
	if err := json.Unmarshal(n.Config, &obj); err != nil {
		return err
	}
	if !obj.Managed || obj.Type != "bridge" {
		return fmt.Errorf("network %q is not a managed bridge; map it to a network on this server instead", n.Name)
	}
	body, _ := json.Marshal(map[string]any{"name": n.Name, "type": "bridge",
		"description": obj.Description, "config": obj.Config})
	if out, err := exec.Command("incus", "query", "-X", "POST", "/1.0/networks", "--data", string(body)).CombinedOutput(); err != nil {
		return fmt.Errorf("create network %s: %s", n.Name, strings.TrimSpace(string(out)))
	}
	return nil
}

// CreateIncusProfileFromBackup recreates a missing profile.
func CreateIncusProfileFromBackup(p IncusNamedConfig) error {
	var obj struct {
		Description string                       `json:"description"`
		Config      map[string]string            `json:"config"`
		Devices     map[string]map[string]string `json:"devices"`
	}
	if err := json.Unmarshal(p.Config, &obj); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"name": p.Name, "description": obj.Description,
		"config": obj.Config, "devices": obj.Devices})
	if out, err := exec.Command("incus", "query", "-X", "POST", "/1.0/profiles", "--data", string(body)).CombinedOutput(); err != nil {
		return fmt.Errorf("create profile %s: %s", p.Name, strings.TrimSpace(string(out)))
	}
	return nil
}

// RecoverResult is what Incus' recovery reports.
type RecoverResult struct {
	UnknownVolumes   []map[string]any `json:"UnknownVolumes"`
	DependencyErrors []string         `json:"DependencyErrors"`
}

// IncusRecover runs Incus' disaster-recovery against the given datastores:
// validate (what would be found / what is missing), then import when
// doImport is set and validation reported no dependency errors.
func IncusRecover(stores []IncusStorageRef, doImport bool) (RecoverResult, error) {
	var res RecoverResult
	type poolReq struct {
		Name   string            `json:"name"`
		Driver string            `json:"driver"`
		Config map[string]string `json:"config"`
	}
	req := struct {
		Pools []poolReq `json:"pools"`
	}{}
	for _, s := range stores {
		if IncusStoragePoolExists(s.Name) {
			req.Pools = append(req.Pools, poolReq{Name: s.Name}) // known pool: just scan it
			continue
		}
		req.Pools = append(req.Pools, poolReq{Name: s.Name, Driver: s.Driver,
			Config: map[string]string{"source": s.Source}})
	}
	body, _ := json.Marshal(req)
	out, err := exec.Command("incus", "query", "-X", "POST", "/internal/recover/validate", "--data", string(body)).CombinedOutput()
	if err != nil {
		return res, fmt.Errorf("incus recover (validate): %s", strings.TrimSpace(string(out)))
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &res); err != nil {
		return res, fmt.Errorf("incus recover (validate): %w", err)
	}
	if !doImport || len(res.DependencyErrors) > 0 {
		return res, nil
	}
	if out, err := exec.Command("incus", "query", "-X", "POST", "/internal/recover/import", "--data", string(body)).CombinedOutput(); err != nil {
		return res, fmt.Errorf("incus recover (import): %s", strings.TrimSpace(string(out)))
	}
	return res, nil
}

// IncusStoragePoolExists reports whether a datastore is already registered.
func IncusStoragePoolExists(name string) bool {
	return exec.Command("incus", "query", "/1.0/storage-pools/"+name).Run() == nil
}

// RemapInstanceNIC points an instance NIC at another host bridge/network.
func RemapInstanceNIC(instance, device string, nic NICRef) error {
	var args []string
	if nic.Network != "" {
		args = []string{"config", "device", "set", instance, device, "network=" + nic.Network}
	} else {
		args = []string{"config", "device", "set", instance, device, "parent=" + nic.Parent}
	}
	if out, err := exec.Command("incus", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s: %s", instance, strings.TrimSpace(string(out)))
	}
	return nil
}

// HostBridgeNames lists bridges this host can attach instances to (Incus
// managed bridges and host-managed bridges).
func HostBridgeNames() []string {
	ents, err := os.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if _, err := os.Stat("/sys/class/net/" + e.Name() + "/bridge"); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// UnavailableIncusStoragePools lists storage pools Incus cannot reach right
// now (disks missing, pool not imported). Empty when Incus is absent.
//
// A newer Incus upgrades its database on first start, and some of those
// upgrade steps need EVERY storage pool: with one unavailable, incusd refuses
// to start at all (seen going 6.0.5 -> 7.5.1: "Failed applying patch …:
// Unavailable storage pools"), taking every VM and container down with it.
func UnavailableIncusStoragePools() []string {
	if _, err := exec.LookPath("incus"); err != nil {
		return nil
	}
	var pools []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	if err := incusQuery("/1.0/storage-pools?recursion=1", &pools); err != nil {
		return nil
	}
	var out []string
	for _, p := range pools {
		if p.Status != "" && p.Status != "Created" {
			out = append(out, p.Name)
		}
	}
	return out
}
