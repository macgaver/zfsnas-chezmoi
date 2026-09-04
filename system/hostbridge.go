package system

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
)

// HostBridgeConfig describes how a bridge defined in /etc/network/interfaces is
// addressed. These are the bridges the appliance generates on first boot
// (vmbr0, vmbr1, …) and any the admin added by hand — Incus does not manage
// them, so the portal has to read and write the ifupdown stanza itself.
type HostBridgeConfig struct {
	Name    string   `json:"name"`
	Exists  bool     `json:"exists"`  // false when the name is not in the file
	Mode    string   `json:"mode"`    // "dhcp" | "static" | "manual"
	Address string   `json:"address"` // static only, "1.2.3.4/24"
	Gateway string   `json:"gateway"`
	DNS     []string `json:"dns"`
	Ports   []string `json:"ports"` // enslaved interfaces (bridge_ports)
	// Pending is true when the stanza above has been saved but the live
	// interface is not running it yet — the only state in which "Apply now"
	// does anything, so the UI greys the action out unless this is set.
	Pending bool `json:"pending"`
}

// netPendingDir holds the "saved but not applied" markers. /run so a reboot
// clears them: booting applies the interfaces file, which is exactly what
// "apply" would have done. A var so tests can redirect it.
//
// Off the appliance the portal runs as its own unprivileged user and cannot
// write to /run, so it falls back to the temp dir — also per-boot, which is
// all these markers need.
var netPendingDir = defaultNetPendingDir()

func defaultNetPendingDir() string {
	if os.Getuid() == 0 {
		return "/run"
	}
	return os.TempDir()
}

func netPendingMarker(name string) string { return netPendingDir + "/zfsnas-netpending-" + name }

// hostInterfacesPath is a var so tests can point it at a fixture.
var hostInterfacesPath = "/etc/network/interfaces"

var ifaceStanzaRe = regexp.MustCompile(`^\s*iface\s+(\S+)\s+inet\s+(\S+)`)

// GetHostBridgeConfig parses one bridge's stanza out of the interfaces file.
func GetHostBridgeConfig(name string) (HostBridgeConfig, error) {
	cfg := HostBridgeConfig{Name: name, Mode: "manual"}
	data, err := os.ReadFile(hostInterfacesPath)
	if err != nil {
		return cfg, err
	}
	inStanza := false
	for _, line := range strings.Split(string(data), "\n") {
		if m := ifaceStanzaRe.FindStringSubmatch(line); m != nil {
			inStanza = m[1] == name
			if inStanza {
				cfg.Exists = true
				cfg.Mode = m[2]
			}
			continue
		}
		if !inStanza {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			// A blank line does NOT end a stanza in ifupdown, but a new
			// `auto`/`allow-hotplug` keyword does.
			if len(f) == 1 && (f[0] == "auto" || f[0] == "allow-hotplug") {
				inStanza = false
			}
			continue
		}
		switch f[0] {
		case "address":
			cfg.Address = f[1]
		case "netmask":
			// Legacy form: fold it into the CIDR the UI shows.
			if cfg.Address != "" && !strings.Contains(cfg.Address, "/") {
				cfg.Address += "/" + netmaskToPrefix(f[1])
			}
		case "gateway":
			cfg.Gateway = f[1]
		case "dns-nameservers":
			cfg.DNS = append(cfg.DNS, f[1:]...)
		case "bridge_ports", "bridge-ports":
			cfg.Ports = append(cfg.Ports, f[1:]...)
		case "auto", "allow-hotplug":
			inStanza = false
		}
	}
	if cfg.Exists {
		cfg.Pending = hostBridgePending(cfg)
	}
	return cfg, nil
}

// hostBridgePending reports whether the saved stanza differs from what the
// interface is actually running.
//
// The marker written on save is the primary signal — it is the only thing that
// can catch a DHCP↔DHCP-shaped change. For a static address we can also read
// the truth off the interface, which covers a marker lost to a reboot that then
// failed to bring the address up.
func hostBridgePending(cfg HostBridgeConfig) bool {
	if _, err := os.Stat(netPendingMarker(cfg.Name)); err == nil {
		return true
	}
	if cfg.Mode != "static" || cfg.Address == "" {
		return false
	}
	out, err := exec.Command("ip", "-4", "-o", "addr", "show", "dev", cfg.Name).Output()
	if err != nil {
		return false // can't tell — don't invite the user to apply blindly
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, f := range strings.Fields(line) {
			if f == cfg.Address {
				return false
			}
		}
	}
	return true
}

// netmaskToPrefix converts 255.255.255.0 → "24". Returns "24" when the mask
// cannot be parsed, which is the overwhelmingly common case on a LAN.
func netmaskToPrefix(mask string) string {
	parts := strings.Split(mask, ".")
	if len(parts) != 4 {
		return "24"
	}
	bits := 0
	for _, p := range parts {
		var v int
		if _, err := fmt.Sscanf(p, "%d", &v); err != nil {
			return "24"
		}
		for v > 0 {
			bits += v & 1
			v >>= 1
		}
	}
	return fmt.Sprintf("%d", bits)
}

// SetHostBridgeConfig rewrites one bridge's stanza in /etc/network/interfaces,
// switching it between DHCP and a static address. Everything else in the file —
// other interfaces, the bridge's own bridge_ports/stp/fd lines — is preserved:
// this edits addressing only, so it can never orphan a bridge from its NIC.
//
// The change is applied with `ifdown`/`ifup` on that interface alone rather
// than restarting networking, so the other bridges keep their leases.
func SetHostBridgeConfig(cfg HostBridgeConfig) error {
	if cfg.Name == "" {
		return fmt.Errorf("bridge name is required")
	}
	switch cfg.Mode {
	case "dhcp", "static", "manual":
	default:
		return fmt.Errorf("mode must be dhcp, static or manual")
	}
	if cfg.Mode == "static" {
		if cfg.Address == "" {
			return fmt.Errorf("a static address is required (e.g. 192.168.1.50/24)")
		}
		if !strings.Contains(cfg.Address, "/") {
			return fmt.Errorf("address must include the prefix length, e.g. %s/24", cfg.Address)
		}
	}

	// An interface that is a PORT of a bridge must not carry its own address:
	// the bridge and its member would both run DHCP / hold an IP, which is the
	// classic way to knock a host off the network. Configure the bridge itself.
	if cfg.Mode != "manual" {
		if master, err := os.Readlink("/sys/class/net/" + cfg.Name + "/master"); err == nil {
			m := master[strings.LastIndex(master, "/")+1:]
			return fmt.Errorf("%s is a port of bridge %s — set the address on %s instead, not on the member interface",
				cfg.Name, m, m)
		}
	}

	data, err := os.ReadFile(hostInterfacesPath)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")

	var out []string
	inStanza := false
	replaced := false
	// Lines that belong to the bridge itself (not addressing) are carried over
	// verbatim — losing bridge_ports would detach the bridge from its NIC.
	var keep []string
	for _, line := range lines {
		if m := ifaceStanzaRe.FindStringSubmatch(line); m != nil {
			if inStanza {
				out = append(out, renderBridgeStanza(cfg, keep)...)
				keep = nil
				inStanza = false
				replaced = true
			}
			if m[1] == cfg.Name {
				inStanza = true
				continue // the new stanza header is emitted by renderBridgeStanza
			}
			out = append(out, line)
			continue
		}
		if inStanza {
			f := strings.Fields(line)
			if len(f) > 0 && (f[0] == "auto" || f[0] == "allow-hotplug") {
				out = append(out, renderBridgeStanza(cfg, keep)...)
				keep = nil
				inStanza = false
				replaced = true
				out = append(out, line)
				continue
			}
			if len(f) > 0 {
				switch f[0] {
				case "address", "netmask", "gateway", "dns-nameservers", "dns-search":
					continue // addressing: replaced
				default:
					keep = append(keep, line) // bridge_ports, stp, fd, post-up …
				}
			}
			continue
		}
		out = append(out, line)
	}
	if inStanza {
		out = append(out, renderBridgeStanza(cfg, keep)...)
		replaced = true
	}
	if !replaced {
		return fmt.Errorf("%q is not defined in %s", cfg.Name, hostInterfacesPath)
	}

	body := strings.TrimRight(strings.Join(out, "\n"), "\n") + "\n"
	if err := writeInterfacesFile(hostInterfacesPath, []byte(body)); err != nil {
		return err
	}
	// Saved but not live: this is what makes "Apply now" available.
	_ = os.WriteFile(netPendingMarker(cfg.Name), []byte(cfg.Mode+"\n"), 0644)
	return nil
}

// renderBridgeStanza builds the replacement stanza, keeping the bridge's own
// (non-addressing) lines.
func renderBridgeStanza(cfg HostBridgeConfig, keep []string) []string {
	out := []string{fmt.Sprintf("iface %s inet %s", cfg.Name, cfg.Mode)}
	if cfg.Mode == "static" {
		out = append(out, "    address "+cfg.Address)
		if cfg.Gateway != "" {
			out = append(out, "    gateway "+cfg.Gateway)
		}
		if len(cfg.DNS) > 0 {
			out = append(out, "    dns-nameservers "+strings.Join(cfg.DNS, " "))
		}
	}
	out = append(out, keep...)
	return out
}

// ApplyHostBridge brings one interface down and back up so a saved change
// takes effect without a reboot.
//
// It runs DETACHED and after a short delay on purpose: when the interface being
// re-applied is the one carrying the portal session (the usual case — you edit
// the bridge you are connected through), the connection drops the moment it
// goes down. Running in the background lets the HTTP response reach the browser
// first, so the user gets "reconnect on the new address" instead of a dead tab
// and no idea whether the change applied.
func ApplyHostBridge(name string) error {
	cfg, err := GetHostBridgeConfig(name)
	if err != nil {
		return err
	}
	if !cfg.Exists {
		return fmt.Errorf("%q is not defined in %s", name, hostInterfacesPath)
	}
	if !cfg.Pending {
		return fmt.Errorf("%s already matches its saved settings — nothing to apply", name)
	}
	q := shellQuote(name)
	// The portal runs as root on the appliance and as an unprivileged service
	// user elsewhere; ifup/ifdown are in the sudoers allowlist for the latter.
	sudo := ""
	if os.Getuid() != 0 {
		sudo = "sudo -n "
	}
	// The settle delay between ifdown and ifup is required, not cosmetic:
	// tearing a bridge down removes its device, and systemd reacts to that by
	// stopping ifup@<iface>.service, whose ExecStop runs `ifdown` again. Bring
	// the interface back up in the same instant and that stray ifdown lands on
	// the half-built interface and leaves the box with no bridge at all (seen
	// on the appliance: vmbr1 vanished). Waiting lets the device-gone event be
	// processed first. `ifup` may then report "already configured" because
	// systemd's own ifup@ unit won the race — that outcome is fine, the
	// interface is up either way, which is why the second ifup is --force.
	script := fmt.Sprintf(
		"%sifdown --force %s; sleep 3; if %sifup %s || %sifup --force %s; then rm -f %s; fi",
		sudo, q, sudo, q, sudo, q, shellQuote(netPendingMarker(name)))
	logPath := netPendingDir + "/zfsnas-apply-" + name + ".log"
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("{ date; %s; } >%s 2>&1", script, shellQuote(logPath)))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() // reap; the portal must not accumulate zombies
	return nil
}

// GatewayIfaces lists the interfaces in the interfaces file that configure a
// default gateway. Two of them means two default routes, which is how a host
// ends up answering on an address that packets never come back from — the
// portal warns about it rather than silently letting it happen.
func GatewayIfaces() []string {
	data, err := os.ReadFile(hostInterfacesPath)
	if err != nil {
		return nil
	}
	var out []string
	cur := ""
	for _, line := range strings.Split(string(data), "\n") {
		if m := ifaceStanzaRe.FindStringSubmatch(line); m != nil {
			cur = m[1]
			continue
		}
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "gateway" && cur != "" {
			out = append(out, cur)
			cur = "" // one mention per interface
		}
	}
	return out
}
