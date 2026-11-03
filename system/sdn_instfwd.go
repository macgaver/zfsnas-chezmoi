package system

// Instance port forwards while the Firewall is enabled (owner decision): the
// VM/CT editor's forwards become nft DNAT rules on the interfaces chosen in
// the editor, instead of Incus proxy devices (which listen everywhere). They
// are applied at once (firewall only, no countdown) and recorded in the
// change history. A forward with no interface stays paused.

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"zfsnas/internal/sdn"
)

// sdnRuntimeEnv is the compiler environment of the running portal (set at
// startup): instance forwards recompile the firewall from here.
var sdnRuntimeEnv sdn.Env

// SDNSetRuntimeEnv records the portal's compiler environment.
func SDNSetRuntimeEnv(env sdn.Env) { sdnRuntimeEnv = env }

// SDNInstanceForwardsActive: the Firewall owns instance port forwards.
func SDNInstanceForwardsActive() bool {
	if sdnConfigDir == "" {
		return false
	}
	st, err := (sdn.Store{Dir: sdnConfigDir}).LoadState()
	return err == nil && st.Enabled
}

// sdnInstanceAddr finds the IPv4 of an instance NIC: the Incus pin, else
// the address the guest holds now.
var sdnInstanceAddr = func(instance, nic string) string {
	out, err := exec.Command("incus", "query", "/1.0/instances/"+instance).Output()
	if err != nil {
		return ""
	}
	var raw struct {
		Config          map[string]string            `json:"config"`
		ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
	}
	if json.Unmarshal(out, &raw) != nil {
		return ""
	}
	dev := raw.ExpandedDevices[nic]
	if dev["ipv4.address"] != "" {
		return dev["ipv4.address"]
	}
	mac := raw.Config["volatile."+nic+".hwaddr"]
	so, err := exec.Command("incus", "query", "/1.0/instances/"+instance+"/state").Output()
	if err != nil {
		return ""
	}
	var state struct {
		Network map[string]lxdStateNetwork `json:"network"`
	}
	if json.Unmarshal(so, &state) != nil {
		return ""
	}
	for name, ifc := range state.Network {
		if name != nic && (mac == "" || ifc.HWAddr != mac) {
			continue
		}
		for _, a := range ifc.Addresses {
			if a.Family == "inet" && a.Scope == "global" {
				return a.Address
			}
		}
	}
	return ""
}

func nicForwardsToSDN(instance, nic string, fwds []NICPortForward) []sdn.PortForward {
	var out []sdn.PortForward
	auto := ""
	for _, f := range fwds {
		proto := f.Protocol
		if proto != "udp" {
			proto = "tcp"
		}
		pf := sdn.PortForward{ID: sdn.InstanceForwardID(instance, nic, proto, f.SourcePort), Enabled: true,
			Interfaces: append([]string{}, f.Interfaces...), Protocol: proto,
			PubPorts: strconv.Itoa(f.SourcePort), TargetPorts: strconv.Itoa(f.TargetPort),
			Source: sdn.Endpoint{Type: "any"}, Target: f.TargetAddr,
			Description: instance + " (" + nic + ")", Instance: instance, NIC: nic}
		if pf.Target == "" {
			if auto == "" {
				auto = sdnInstanceAddr(instance, nic)
			}
			pf.Target, pf.TargetAuto = auto, true
		}
		out = append(out, pf)
	}
	return out
}

// sdnInstanceChange applies edit to the confirmed config (and to an open
// draft, so applying the draft later keeps it), reloads the firewall and
// records a history entry.
func sdnInstanceChange(user, summary string, edit func(*sdn.Config) bool) error {
	if sdnConfigDir == "" {
		return errors.New("firewall not initialised")
	}
	st := sdn.Store{Dir: sdnConfigDir}
	unlock, err := st.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	if _, ok := SDNPendingRevert(st); ok {
		return errors.New("a firewall change is waiting for confirmation — confirm or revert it first (Firewall page)")
	}
	c, err := st.LoadConfirmed()
	if err != nil {
		return err
	}
	if !edit(c) {
		return nil
	}
	c.Normalize()
	if err := c.Validate(); err != nil {
		return fmt.Errorf("port forwards: %v", err)
	}
	script, err := sdn.Compile(c, sdnRuntimeEnv)
	if err != nil {
		return err
	}
	if SDNSafeModeReason() == "" {
		if _, err := sdnRun.Run([]byte(script), "nft", "-f", "-"); err != nil {
			return fmt.Errorf("loading the firewall: %v", err)
		}
	}
	if err := st.SaveConfirmed(c); err != nil {
		return err
	}
	_ = st.AddSnapshot(sdn.Snapshot{ID: sdn.NewID(), User: user, Summary: summary, Outcome: "confirmed", At: time.Now().UTC(), Config: c})
	if d, err := st.LoadDraft(); err == nil && d.Revision > 0 {
		edit(d.Config)
		_, _ = st.SaveDraft(d.Config, d.Revision, d.EditedBy)
	}
	return nil
}

// SDNSetInstanceForwards replaces the forwards of one instance NIC.
func SDNSetInstanceForwards(instance, nic string, fwds []NICPortForward, user string) error {
	next := nicForwardsToSDN(instance, nic, fwds)
	pub := 0
	for _, f := range next {
		if !f.Paused() {
			pub++
		}
	}
	summary := fmt.Sprintf("port forwards of %s (%s): %d published, %d paused", instance, nic, pub, len(next)-pub)
	return sdnInstanceChange(user, summary, func(c *sdn.Config) bool {
		var cur []sdn.PortForward
		known := map[string]string{}
		for _, f := range c.PortForwards {
			if f.Instance == instance && f.NIC == nic {
				cur = append(cur, f)
				known[f.ID] = f.Target
			}
		}
		want := append([]sdn.PortForward(nil), next...)
		for i := range want {
			// Address not found right now (instance stopped): keep the last.
			if want[i].TargetAuto && want[i].Target == "" {
				want[i].Target = known[want[i].ID]
			}
		}
		if sdnForwardsEqual(cur, want) {
			return false // the editor saves every NIC: nothing to do here
		}
		sdn.ReplaceInstanceForwards(c, instance, nic, want)
		return true
	})
}

// SDNInstanceForwards returns an instance's forwards per NIC (editor GET).
func SDNInstanceForwards(instance string) map[string][]NICPortForward {
	out := map[string][]NICPortForward{}
	if sdnConfigDir == "" {
		return out
	}
	c, err := (sdn.Store{Dir: sdnConfigDir}).LoadConfirmed()
	if err != nil {
		return out
	}
	for _, f := range c.PortForwards {
		if f.Instance != instance {
			continue
		}
		src, _ := strconv.Atoi(f.PubPorts)
		dst, _ := strconv.Atoi(f.TargetPorts)
		nf := NICPortForward{SourcePort: src, TargetPort: dst, Protocol: f.Protocol, Interfaces: append([]string{}, f.Interfaces...)}
		if !f.TargetAuto {
			nf.TargetAddr = f.Target
		}
		out[f.NIC] = append(out[f.NIC], nf)
	}
	return out
}

// SDNForgetInstance drops the forwards of a deleted instance.
func SDNForgetInstance(instance string) {
	if !SDNInstanceForwardsActive() {
		return
	}
	_ = sdnInstanceChange("system", "port forwards of deleted instance "+instance+" removed", func(c *sdn.Config) bool {
		return sdn.RemoveInstanceForwards(c, instance) > 0
	})
}

// SDNRefreshInstanceTargets follows instance addresses: forwards whose
// target was looked up (not typed) get the instance's current address — a
// new instance's first lease, or a changed one. An address that cannot be
// found right now (instance stopped) keeps the last one. Returns how many
// forwards changed.
func SDNRefreshInstanceTargets() int {
	if !SDNInstanceForwardsActive() {
		return 0
	}
	c, err := (sdn.Store{Dir: sdnConfigDir}).LoadConfirmed()
	if err != nil {
		return 0
	}
	type key struct{ instance, nic string }
	found := map[key]string{}
	for _, f := range c.PortForwards {
		k := key{f.Instance, f.NIC}
		if f.Instance == "" || !f.TargetAuto {
			continue
		}
		if _, done := found[k]; !done {
			found[k] = sdnInstanceAddr(f.Instance, f.NIC)
		}
	}
	changed, names := 0, map[string]bool{}
	for _, f := range c.PortForwards {
		if a := found[key{f.Instance, f.NIC}]; f.TargetAuto && a != "" && a != f.Target {
			names[f.Instance+" → "+a] = true
		}
	}
	if len(names) == 0 {
		return 0
	}
	var list []string
	for n := range names {
		list = append(list, n)
	}
	sort.Strings(list)
	first := true
	_ = sdnInstanceChange("system", "instance address followed: "+strings.Join(list, ", "), func(c *sdn.Config) bool {
		n := 0
		for i := range c.PortForwards {
			f := &c.PortForwards[i]
			if a := found[key{f.Instance, f.NIC}]; f.TargetAuto && a != "" && a != f.Target {
				f.Target = a
				n++
			}
		}
		if first { // the confirmed config; a second call edits the draft
			changed, first = n, false
		}
		return n > 0
	})
	return changed
}

// StartSDNInstanceTargetWatcher re-resolves instance forward addresses
// every 30 s while the Firewall owns them.
func StartSDNInstanceTargetWatcher() {
	go func() {
		for {
			time.Sleep(30 * time.Second)
			if IncusUsable() {
				SDNRefreshInstanceTargets()
			}
		}
	}()
}

// applyNewInstanceForwards attaches a new instance's forwards: Firewall
// rules (address looked up once the instance has one) or proxy devices.
func applyNewInstanceForwards(instance, nic string, fwds []NICPortForward) error {
	if SDNInstanceForwardsActive() {
		if _, _, err := validateNICPortForwards(nic, fwds); err != nil {
			return err
		}
		return SDNSetInstanceForwards(instance, nic, fwds, "VMs & Containers")
	}
	return applyNICPortForwards(instance, nic, fwds)
}

// Incus access for the enable/disable conversion (replaced in tests).
var (
	// sdnListInstanceDevices: instance → device → config (expanded).
	sdnListInstanceDevices = func() (map[string]map[string]map[string]string, error) {
		out, err := exec.Command("incus", "query", "/1.0/instances?recursion=1").Output()
		if err != nil {
			return nil, err
		}
		var list []struct {
			Name            string                       `json:"name"`
			ExpandedDevices map[string]map[string]string `json:"expanded_devices"`
		}
		if err := json.Unmarshal(out, &list); err != nil {
			return nil, err
		}
		m := map[string]map[string]map[string]string{}
		for _, i := range list {
			m[i.Name] = i.ExpandedDevices
		}
		return m, nil
	}
	sdnRemoveInstanceDevice = func(instance, dev string) error {
		return exec.Command("incus", "config", "device", "remove", instance, dev).Run()
	}
	sdnAddProxyForwards = applyNICPortForwards
	sdnIncusOK          = IncusUsable
)

// sdnProxyForwards lists ZNAS forward proxy devices: instance → nic → forwards
// (plus the device names).
func sdnProxyForwards() (map[string]map[string][]NICPortForward, map[string][]string) {
	fwds, names := map[string]map[string][]NICPortForward{}, map[string][]string{}
	if !sdnIncusOK() {
		return fwds, names
	}
	devs, err := sdnListInstanceDevices()
	if err != nil {
		return fwds, names
	}
	for inst, dd := range devs {
		for dev, cfg := range dd {
			parts := strings.SplitN(dev, "-", 4)
			if cfg["type"] != "proxy" || len(parts) != 4 || parts[0] != "fwd" {
				continue
			}
			src, dst, proto, addr := parseProxyListenConnect(cfg["listen"], cfg["connect"])
			if src <= 0 || dst <= 0 {
				continue
			}
			if fwds[inst] == nil {
				fwds[inst] = map[string][]NICPortForward{}
			}
			fwds[inst][parts[1]] = append(fwds[inst][parts[1]], NICPortForward{SourcePort: src, TargetPort: dst, Protocol: proto, TargetAddr: addr})
			names[inst] = append(names[inst], dev)
		}
	}
	return fwds, names
}

// SDNAdoptProxyForwards converts the instances' proxy-device forwards into
// Firewall forwards for the enable. New ones are paused (owner decision:
// they stay off until an interface is chosen); one that was published the
// last time the Firewall was on keeps its interfaces.
func SDNAdoptProxyForwards(last *sdn.Config) []sdn.PortForward {
	prev := map[string]sdn.PortForward{}
	if last != nil {
		for _, f := range last.PortForwards {
			if f.Instance != "" {
				prev[f.ID] = f
			}
		}
	}
	fwds, _ := sdnProxyForwards()
	var out []sdn.PortForward
	insts := make([]string, 0, len(fwds))
	for i := range fwds {
		insts = append(insts, i)
	}
	sort.Strings(insts)
	for _, inst := range insts {
		nics := make([]string, 0, len(fwds[inst]))
		for n := range fwds[inst] {
			nics = append(nics, n)
		}
		sort.Strings(nics)
		for _, nic := range nics {
			list := fwds[inst][nic]
			sort.Slice(list, func(i, j int) bool { return list[i].SourcePort < list[j].SourcePort })
			for _, pf := range nicForwardsToSDN(inst, nic, list) {
				if p, ok := prev[pf.ID]; ok {
					pf.Interfaces = append([]string{}, p.Interfaces...)
				}
				out = append(out, pf)
			}
		}
	}
	return out
}

// SDNDropProxyForwards removes the proxy devices of forwards the Firewall
// now owns — after the enable is confirmed (an auto-revert keeps them), and
// at portal start.
func SDNDropProxyForwards() {
	if !SDNInstanceForwardsActive() {
		return
	}
	st := sdn.Store{Dir: sdnConfigDir}
	if _, ok := SDNPendingRevert(st); ok {
		return
	}
	c, err := st.LoadConfirmed()
	if err != nil {
		return
	}
	owned := map[string]bool{}
	for _, f := range c.PortForwards {
		if f.Instance != "" {
			owned[f.Instance] = true
		}
	}
	_, names := sdnProxyForwards()
	insts := make([]string, 0, len(names))
	for i := range names {
		insts = append(insts, i)
	}
	sort.Strings(insts)
	for _, inst := range insts {
		if !owned[inst] {
			continue
		}
		sort.Strings(names[inst])
		for _, d := range names[inst] {
			if err := sdnRemoveInstanceDevice(inst, d); err != nil {
				log.Printf("[sdn] removing proxy %s/%s: %v", inst, d, err)
			}
		}
	}
}

// SDNRestoreProxyForwards recreates proxy devices for every instance
// forward (disable: without the Firewall, forwards are proxy devices again).
func SDNRestoreProxyForwards(c *sdn.Config) {
	if c == nil {
		return
	}
	type key struct{ inst, nic string }
	groups := map[key][]NICPortForward{}
	for _, f := range c.PortForwards {
		if f.Instance == "" {
			continue
		}
		src, _ := strconv.Atoi(f.PubPorts)
		dst, _ := strconv.Atoi(f.TargetPorts)
		nf := NICPortForward{SourcePort: src, TargetPort: dst, Protocol: f.Protocol}
		if !f.TargetAuto {
			nf.TargetAddr = f.Target
		}
		groups[key{f.Instance, f.NIC}] = append(groups[key{f.Instance, f.NIC}], nf)
	}
	keys := make([]key, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].inst+"\x00"+keys[i].nic < keys[j].inst+"\x00"+keys[j].nic
	})
	for _, k := range keys {
		if err := sdnAddProxyForwards(k.inst, k.nic, groups[k]); err != nil {
			log.Printf("[sdn] restoring port forwards of %s/%s: %v", k.inst, k.nic, err)
		}
	}
}

func sdnForwardsEqual(a, b []sdn.PortForward) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if len(x.Interfaces) == 0 && len(y.Interfaces) == 0 {
			x.Interfaces, y.Interfaces = nil, nil
		}
		xb, _ := json.Marshal(x)
		yb, _ := json.Marshal(y)
		if string(xb) != string(yb) {
			return false
		}
	}
	return true
}
