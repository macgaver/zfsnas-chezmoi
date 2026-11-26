package system

// Datastore default + "Move contents" (6.11.26).
//
// The default datastore is the pool the `default` profile's root disk names.
// New VMs/containers created without an explicit datastore get their root
// disk there; it holds no instance configuration (Incus keeps that in its
// database, and each instance's backup.yaml / NVRAM live next to its own root
// disk). Incus refuses to delete a pool any profile still names, which is why
// a datastore with zero instances could still not be deleted.
//
// Evacuation empties a datastore onto another one, as ordered steps:
//
//  1. profiles   — repoint profile root disks (no source) at the target, so
//                  nothing new lands on the pool while we work;
//  2. instances  — every instance whose root disk is on the pool: stop the
//                  ones that run, `incus move --storage`, move the custom
//                  volumes on the pool that only it uses, start again;
//  3. volumes    — remaining custom volumes (extra disks, ISOs): stop the
//                  instances using them, `incus storage volume move`, start
//                  again (Incus rebinds the devices that reference them);
//  4. images     — cached image volumes are deleted (re-downloaded on use).
//
// A failed step puts its instances back the way they were (started again if
// they ran) and the job stops there: everything before it stays moved and
// consistent, nothing after it was touched.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
)

// EvacStep is one row of the evacuation plan / job.
type EvacStep struct {
	Kind   string   `json:"kind"`           // profile | instance | volume | image
	Name   string   `json:"name"`           // profile/instance/volume name, image fingerprint
	Type   string   `json:"type,omitempty"` // virtual-machine | container (instance); block | filesystem | iso (volume)
	Vols   []string `json:"vols,omitempty"` // instance step: custom volumes on the pool moved with it
	Stop   []string `json:"stop,omitempty"` // running instances stopped (and started again) for this step
	Status string   `json:"status"`         // pending | running | done | error | skipped
	Error  string   `json:"error,omitempty"`
}

// EvacPlan is what GET …/evacuate-plan returns and the job executes.
type EvacPlan struct {
	Pool      string     `json:"pool"`
	Steps     []EvacStep `json:"steps"`
	UsedBytes int64      `json:"used_bytes"`        // on the source pool
	Blocked   string     `json:"blocked,omitempty"` // non-empty: the plan cannot run (reason)
	IsDefault bool       `json:"is_default"`
}

// PoolUsage summarises what still uses a pool — the Delete item's reasons.
type PoolUsage struct {
	Profiles      []string `json:"profiles"`
	Instances     []string `json:"instances"`
	CustomVolumes []string `json:"custom_volumes"`
	ISOVolumes    []string `json:"iso_volumes"`
	Images        int      `json:"images"`
}

// ---- inputs (parsed from `incus query`) ----

type evacInst struct {
	Name    string                       `json:"name"`
	Type    string                       `json:"type"`
	Status  string                       `json:"status"`
	Project string                       `json:"project"`
	Devices map[string]map[string]string `json:"expanded_devices"`
}

type evacVol struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // custom | image | container | virtual-machine
	ContentType string `json:"content_type"`
	Project     string `json:"project"`
}

type evacProfile struct {
	Name    string                       `json:"name"`
	Devices map[string]map[string]string `json:"devices"`
}

func inDefaultProject(p string) bool { return p == "" || p == "default" }

// rootPool returns the pool of the instance's root disk (path=/).
func (i evacInst) rootPool() string {
	for _, d := range i.Devices {
		if d["type"] == "disk" && d["path"] == "/" {
			return d["pool"]
		}
	}
	return ""
}

// volsOn lists the custom volumes on pool the instance has attached.
func (i evacInst) volsOn(pool string) []string {
	var out []string
	for _, d := range i.Devices {
		if d["type"] == "disk" && d["pool"] == pool && d["source"] != "" && d["path"] != "/" {
			out = append(out, d["source"])
		}
	}
	sort.Strings(out)
	return out
}

func isRunning(status string) bool {
	return strings.EqualFold(status, "Running") || strings.EqualFold(status, "Frozen")
}

// buildEvacPlan orders the steps that empty pool. Pure, for tests.
func buildEvacPlan(pool string, insts []evacInst, vols []evacVol, profiles []evacProfile) ([]EvacStep, string) {
	var steps []EvacStep
	var blocked []string

	// Who attaches which custom volume on the pool (default project only).
	attachers := map[string][]evacInst{}
	for _, in := range insts {
		if !inDefaultProject(in.Project) {
			continue
		}
		for _, v := range in.volsOn(pool) {
			attachers[v] = append(attachers[v], in)
		}
	}
	runningOf := func(list []evacInst) []string {
		seen := map[string]bool{}
		var out []string
		for _, in := range list {
			if isRunning(in.Status) && !seen[in.Name] {
				seen[in.Name] = true
				out = append(out, in.Name)
			}
		}
		sort.Strings(out)
		return out
	}

	// 1. profiles
	for _, p := range profiles {
		for _, d := range p.Devices {
			if d["type"] == "disk" && d["pool"] == pool && d["source"] == "" {
				steps = append(steps, EvacStep{Kind: "profile", Name: p.Name})
				break
			}
		}
	}

	// 2. instances whose root is on the pool
	covered := map[string]bool{}
	sorted := append([]evacInst(nil), insts...)
	sort.Slice(sorted, func(a, b int) bool { return sorted[a].Name < sorted[b].Name })
	for _, in := range sorted {
		if in.rootPool() != pool {
			continue
		}
		if !inDefaultProject(in.Project) {
			blocked = append(blocked, fmt.Sprintf("%s (project %s)", in.Name, in.Project))
			continue
		}
		stopSet := []evacInst{in}
		var own []string
		for _, v := range in.volsOn(pool) {
			// Move a volume with this instance only when every instance
			// using it is stopped for this step anyway (it is the only
			// user, or the others get stopped too).
			own = append(own, v)
			covered[v] = true
			stopSet = append(stopSet, attachers[v]...)
		}
		steps = append(steps, EvacStep{Kind: "instance", Name: in.Name, Type: in.Type, Vols: own, Stop: runningOf(stopSet)})
	}

	// 3. remaining custom volumes; 4. cached images
	var images []EvacStep
	sortedVols := append([]evacVol(nil), vols...)
	sort.Slice(sortedVols, func(a, b int) bool { return sortedVols[a].Name < sortedVols[b].Name })
	for _, v := range sortedVols {
		if strings.Contains(v.Name, "/") { // snapshot entry — travels with its volume
			continue
		}
		if !inDefaultProject(v.Project) {
			blocked = append(blocked, fmt.Sprintf("volume %s (project %s)", v.Name, v.Project))
			continue
		}
		switch v.Type {
		case "custom":
			if covered[v.Name] {
				continue
			}
			steps = append(steps, EvacStep{Kind: "volume", Name: v.Name, Type: v.ContentType, Stop: runningOf(attachers[v.Name])})
		case "image":
			images = append(images, EvacStep{Kind: "image", Name: v.Name})
		}
	}
	steps = append(steps, images...)
	for i := range steps {
		steps[i].Status = "pending"
	}
	reason := ""
	if len(blocked) > 0 {
		reason = "Items in other Incus projects cannot be moved from here: " + strings.Join(blocked, ", ")
	}
	return steps, reason
}

// ---- live reads ----

func incusQueryJSON(path string, v interface{}) error {
	out, err := exec.Command("incus", "query", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return json.Unmarshal(out, v)
}

func evacInputs(pool string) ([]evacInst, []evacVol, []evacProfile, error) {
	var insts []evacInst
	if err := incusQueryJSON("/1.0/instances?recursion=1&all-projects=true", &insts); err != nil {
		if err2 := incusQueryJSON("/1.0/instances?recursion=1", &insts); err2 != nil {
			return nil, nil, nil, fmt.Errorf("list instances: %v", err2)
		}
	}
	var vols []evacVol
	if err := incusQueryJSON("/1.0/storage-pools/"+pool+"/volumes?recursion=1&all-projects=true", &vols); err != nil {
		if err2 := incusQueryJSON("/1.0/storage-pools/"+pool+"/volumes?recursion=1", &vols); err2 != nil {
			return nil, nil, nil, fmt.Errorf("list volumes: %v", err2)
		}
	}
	var profiles []evacProfile
	if err := incusQueryJSON("/1.0/profiles?recursion=1", &profiles); err != nil {
		return nil, nil, nil, fmt.Errorf("list profiles: %v", err)
	}
	return insts, vols, profiles, nil
}

// LXDPoolSpace returns used and total bytes of a pool.
func LXDPoolSpace(pool string) (used, total int64, err error) {
	var r struct {
		Space struct {
			Used  int64 `json:"used"`
			Total int64 `json:"total"`
		} `json:"space"`
	}
	if err := incusQueryJSON("/1.0/storage-pools/"+pool+"/resources", &r); err != nil {
		return 0, 0, err
	}
	return r.Space.Used, r.Space.Total, nil
}

// LXDPoolUsage lists what still uses pool (the Delete item's reasons).
func LXDPoolUsage(pool string) (*PoolUsage, error) {
	m, err := LXDPoolUsages([]string{pool})
	if err != nil {
		return nil, err
	}
	return m[pool], nil
}

// LXDPoolUsages computes PoolUsage for several pools with one instance and
// one profile listing (plus one volume listing per pool).
func LXDPoolUsages(pools []string) (map[string]*PoolUsage, error) {
	var insts []evacInst
	if err := incusQueryJSON("/1.0/instances?recursion=1&all-projects=true", &insts); err != nil {
		if err2 := incusQueryJSON("/1.0/instances?recursion=1", &insts); err2 != nil {
			return nil, fmt.Errorf("list instances: %v", err2)
		}
	}
	var profiles []evacProfile
	if err := incusQueryJSON("/1.0/profiles?recursion=1", &profiles); err != nil {
		return nil, fmt.Errorf("list profiles: %v", err)
	}
	out := map[string]*PoolUsage{}
	for _, pool := range pools {
		var vols []evacVol
		if err := incusQueryJSON("/1.0/storage-pools/"+pool+"/volumes?recursion=1&all-projects=true", &vols); err != nil {
			_ = incusQueryJSON("/1.0/storage-pools/"+pool+"/volumes?recursion=1", &vols)
		}
		out[pool] = poolUsageFrom(pool, insts, vols, profiles)
	}
	return out, nil
}

func poolUsageFrom(pool string, insts []evacInst, vols []evacVol, profiles []evacProfile) *PoolUsage {
	u := &PoolUsage{Profiles: []string{}, Instances: []string{}, CustomVolumes: []string{}, ISOVolumes: []string{}}
	for _, p := range profiles {
		for _, d := range p.Devices {
			if d["type"] == "disk" && d["pool"] == pool {
				u.Profiles = append(u.Profiles, p.Name)
				break
			}
		}
	}
	for _, in := range insts {
		if in.rootPool() == pool {
			u.Instances = append(u.Instances, in.Name)
		}
	}
	for _, v := range vols {
		if strings.Contains(v.Name, "/") {
			continue
		}
		switch v.Type {
		case "custom":
			if v.ContentType == "iso" {
				u.ISOVolumes = append(u.ISOVolumes, v.Name)
			} else {
				u.CustomVolumes = append(u.CustomVolumes, v.Name)
			}
		case "image":
			u.Images++
		}
	}
	sort.Strings(u.Profiles)
	sort.Strings(u.Instances)
	sort.Strings(u.CustomVolumes)
	sort.Strings(u.ISOVolumes)
	return u
}

// LXDPoolEvacuationPlan builds the plan for emptying pool.
func LXDPoolEvacuationPlan(pool, target string) (*EvacPlan, error) {
	if !validPoolName(pool) {
		return nil, fmt.Errorf("invalid datastore name")
	}
	insts, vols, profiles, err := evacInputs(pool)
	if err != nil {
		return nil, err
	}
	steps, blocked := buildEvacPlan(pool, insts, vols, profiles)
	if blocked == "" && target != "" && validPoolName(target) {
		var tvols []evacVol
		if incusQueryJSON("/1.0/storage-pools/"+target+"/volumes?recursion=1", &tvols) == nil {
			blocked = evacNameClashes(steps, target, tvols)
		}
	}
	used, _, _ := LXDPoolSpace(pool)
	return &EvacPlan{Pool: pool, Steps: steps, UsedBytes: used, Blocked: blocked,
		IsDefault: LXDDefaultProfileRootPool() == pool}, nil
}

// evacNameClashes reports custom volumes the plan would move onto target
// where a volume with the same name already exists — caught up front so a
// step never fails half-way (instance root moved, its extra disk not).
func evacNameClashes(steps []EvacStep, target string, targetVols []evacVol) string {
	have := map[string]bool{}
	for _, v := range targetVols {
		if v.Type == "custom" {
			have[v.Name] = true
		}
	}
	var clash []string
	for _, s := range steps {
		names := s.Vols
		if s.Kind == "volume" {
			names = []string{s.Name}
		}
		for _, n := range names {
			if have[n] {
				clash = append(clash, n)
			}
		}
	}
	if len(clash) == 0 {
		return ""
	}
	sort.Strings(clash)
	return fmt.Sprintf("%s already has a volume named %s. Rename or remove it there first.", target, strings.Join(clash, ", "))
}

// validPoolName accepts Incus pool names (letters, digits, - _ .).
func validPoolName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	return s[0] != '.' && s[0] != '-'
}

// LXDSetDefaultStoragePool points the `default` profile's root disk at pool
// (adding the root disk when the profile has none). Existing instances keep
// their disks where they are.
func LXDSetDefaultStoragePool(pool string) error {
	if !validPoolName(pool) {
		return fmt.Errorf("invalid datastore name")
	}
	return setProfileRootPool("default", pool)
}

func setProfileRootPool(profile, pool string) error {
	var p evacProfile
	if err := incusQueryJSON("/1.0/profiles/"+profile, &p); err != nil {
		return err
	}
	dev := ""
	for name, d := range p.Devices {
		if d["type"] == "disk" && d["path"] == "/" {
			dev = name
			break
		}
	}
	var out []byte
	var err error
	if dev == "" {
		out, err = exec.Command("incus", "profile", "device", "add", profile, "root", "disk", "path=/", "pool="+pool).CombinedOutput()
	} else {
		out, err = exec.Command("incus", "profile", "device", "set", profile, dev, "pool="+pool).CombinedOutput()
	}
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ---- execution ----

func runIncus(ctx context.Context, logFn func(string), args ...string) error {
	if logFn != nil {
		logFn("$ incus " + strings.Join(args, " "))
	}
	out, err := exec.CommandContext(ctx, "incus", args...).CombinedOutput()
	if s := strings.TrimSpace(string(out)); s != "" && logFn != nil {
		for _, l := range strings.Split(s, "\n") {
			// incus redraws progress with \r — keep only the last state.
			if i := strings.LastIndex(strings.TrimRight(l, "\r "), "\r"); i >= 0 {
				l = l[i+1:]
			}
			if l = strings.TrimSpace(l); l != "" {
				logFn("  " + l)
			}
		}
	}
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("canceled")
		}
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// evacStopTimeout is the graceful shutdown wait per instance before the step
// fails (nothing is ever force-killed by an evacuation).
const evacStopTimeout = "120"

func volumeOnPool(pool, vol string) bool {
	return exec.Command("incus", "storage", "volume", "show", pool, "custom/"+vol).Run() == nil
}

// LXDPoolEvacuateStep runs one plan step. stopped instances are started
// again afterwards when restart is true — also when the step fails, so a
// failed step leaves its instances as they were.
func LXDPoolEvacuateStep(ctx context.Context, pool, target string, st *EvacStep, restart bool, logFn func(string)) error {
	switch st.Kind {
	case "profile":
		if logFn != nil {
			logFn(fmt.Sprintf("Profile %s: root disk → %s", st.Name, target))
		}
		return setProfileRootPool(st.Name, target)

	case "image":
		return runIncus(ctx, logFn, "storage", "volume", "delete", pool, "image/"+st.Name)
	}

	// instance / volume: stop the running users first.
	var stopped []string
	startAgain := func() {
		if !restart {
			return
		}
		for _, n := range stopped {
			if err := runIncus(context.Background(), logFn, "start", n); err != nil && logFn != nil {
				logFn("  could not start " + n + " again: " + err.Error())
			}
		}
	}
	for _, n := range st.Stop {
		MarkUserInitiatedStop(n)
		if err := runIncus(ctx, logFn, "stop", n, "--timeout="+evacStopTimeout); err != nil {
			startAgain()
			return fmt.Errorf("%s did not shut down within %ss (%v) — shut it down yourself, then run Move contents again", n, evacStopTimeout, err)
		}
		stopped = append(stopped, n)
	}

	var err error
	switch st.Kind {
	case "instance":
		var in evacInst
		if e := incusQueryJSON("/1.0/instances/"+st.Name, &in); e != nil {
			err = e
		} else if in.rootPool() == pool {
			err = runIncus(ctx, logFn, "move", st.Name, "--storage", target)
		}
		for _, v := range st.Vols {
			if err != nil {
				break
			}
			if volumeOnPool(pool, v) {
				err = runIncus(ctx, logFn, "storage", "volume", "move", pool+"/"+v, target+"/"+v)
			}
		}
	case "volume":
		if volumeOnPool(pool, st.Name) {
			err = runIncus(ctx, logFn, "storage", "volume", "move", pool+"/"+st.Name, target+"/"+st.Name)
		}
	default:
		err = fmt.Errorf("unknown step kind %q", st.Kind)
	}
	startAgain()
	return err
}

// LXDRepointProfileVolumes fixes profile disk devices that still name pool
// for a volume now on target (Incus normally rebinds them on volume move;
// this is the safety net run at the end of an evacuation).
func LXDRepointProfileVolumes(pool, target string, logFn func(string)) {
	var profiles []evacProfile
	if incusQueryJSON("/1.0/profiles?recursion=1", &profiles) != nil {
		return
	}
	for _, p := range profiles {
		for dn, d := range p.Devices {
			if d["type"] != "disk" || d["pool"] != pool || d["source"] == "" {
				continue
			}
			if volumeOnPool(target, d["source"]) {
				_ = runIncus(context.Background(), logFn, "profile", "device", "set", p.Name, dn, "pool="+target)
			}
		}
	}
}

// ValidIncusPoolName reports whether s is a safe Incus storage pool name.
func ValidIncusPoolName(s string) bool { return validPoolName(s) }
