package system

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// NIC identity for the "Network Interfaces" table: what hardware a port is
// (vendor + model), and which physical port(s) a VLAN or bond rides on.

// lowerIfaces returns the interfaces directly under iface: a VLAN's parent,
// a bond's slaves, a macvlan's base. The kernel exposes each as a
// "lower_<name>" link in the interface's sysfs directory.
func lowerIfaces(iface string) []string {
	if iface == "" || strings.ContainsAny(iface, "/\x00") {
		return nil
	}
	ents, err := os.ReadDir(sysClassNet + "/" + iface)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if n, ok := strings.CutPrefix(e.Name(), "lower_"); ok {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// hasHardware reports whether iface is backed by a device (PCI, USB…), i.e.
// it is a real port rather than a software interface.
func hasHardware(iface string) bool {
	if iface == "" || strings.ContainsAny(iface, "/\x00") {
		return false
	}
	_, err := os.Stat(sysClassNet + "/" + iface + "/device")
	return err == nil
}

// PhysicalPortsUnder walks down from iface (VLAN → parent, bond → slaves,
// bridge → its ports) to the real NICs at the bottom. A port is returned as
// itself; a purely virtual interface yields nothing.
func PhysicalPortsUnder(iface string) []string {
	seen := map[string]bool{}
	var out []string
	var walk func(string, int)
	walk = func(n string, depth int) {
		if depth > 6 || seen[n] {
			return
		}
		seen[n] = true
		if hasHardware(n) {
			out = append(out, n)
			return
		}
		next := lowerIfaces(n)
		if isBridgeIface(n) {
			for _, p := range bridgePortsAt(n) {
				if !isVirtualBridgePort(p) {
					next = append(next, p)
				}
			}
		}
		for _, l := range next {
			walk(l, depth+1)
		}
	}
	walk(iface, 0)
	sort.Strings(out)
	return out
}

// bridgePortsAt lists a bridge's ports under the (test-overridable) sysfs root.
func bridgePortsAt(name string) []string {
	ents, err := os.ReadDir(sysClassNet + "/" + name + "/brif")
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// VLANInfo returns a VLAN interface's parent and tag from `ip -d -j link`
// (/proc/net/vlan is root-only; the portal does not always run as root).
// ok is false when iface is not a VLAN.
func VLANInfo(iface string) (parent string, id int, ok bool) {
	out, err := exec.Command("ip", "-d", "-j", "link", "show", "dev", iface).Output()
	if err != nil {
		return "", 0, false
	}
	return parseVLANLink(out)
}

func parseVLANLink(js []byte) (parent string, id int, ok bool) {
	var links []struct {
		Link     string `json:"link"`
		LinkInfo struct {
			Kind string `json:"info_kind"`
			Data struct {
				ID int `json:"id"`
			} `json:"info_data"`
		} `json:"linkinfo"`
	}
	if json.Unmarshal(js, &links) != nil || len(links) == 0 || links[0].LinkInfo.Kind != "vlan" {
		return "", 0, false
	}
	return links[0].Link, links[0].LinkInfo.Data.ID, true
}

var virtioRe = regexp.MustCompile(`^virtio[0-9]+$`)

// pciSlotRe matches the PCI address a NIC's "device" link resolves to.
var pciSlotRe = regexp.MustCompile(`^[0-9a-f]{4}:([0-9a-f]{2}:[0-9a-f]{2}\.[0-7])$`)

// NICModels describes the hardware behind each named port, e.g.
// "Realtek RTL8111/8168/8211/8411 PCI Express Gigabit Ethernet Controller".
// PCI NICs are named from lspci (one call for all of them); USB adapters from
// the USB device's own manufacturer/product strings. Ports with no hardware
// (or that cannot be identified) are absent from the map.
func NICModels(ports []string) map[string]string {
	out := map[string]string{}
	var pci map[string]PCIDevice
	for _, p := range ports {
		if !hasHardware(p) {
			continue
		}
		dev, err := filepath.EvalSymlinks(sysClassNet + "/" + p + "/device")
		if err != nil {
			continue
		}
		// A virtio NIC (VMs) links to its virtio bus node; the PCI function
		// carrying it is the parent.
		if virtioRe.MatchString(filepath.Base(dev)) {
			dev = filepath.Dir(dev)
		}
		if m := pciSlotRe.FindStringSubmatch(filepath.Base(dev)); m != nil {
			if pci == nil {
				pci = map[string]PCIDevice{}
				if list, err := ListPCIDevices(); err == nil {
					for _, d := range list {
						pci[strings.TrimPrefix(d.Slot, "0000:")] = d
					}
				}
			}
			if d, ok := pci[m[1]]; ok {
				out[p] = joinVendorModel(d.Vendor, d.Device)
			} else {
				// No lspci (pciutils not installed): name the vendor from the
				// kernel driver bound to the port, and keep the IDs, which
				// still identify the exact chip.
				ids := strings.TrimPrefix(readFileTrim(dev+"/vendor"), "0x") + ":" +
					strings.TrimPrefix(readFileTrim(dev+"/device"), "0x")
				out[p] = driverNICLabel(nicDriver(p)) + " (PCI " + ids + ")"
			}
			continue
		}
		// USB: the net device hangs off a USB interface (e.g. 2-1:1.0) whose
		// parent is the device carrying the manufacturer/product strings.
		usb := filepath.Dir(dev)
		if prod := readFileTrim(usb + "/product"); prod != "" {
			out[p] = joinVendorModel(readFileTrim(usb+"/manufacturer"), prod) + " (USB)"
		}
	}
	return out
}

func readFileTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// vendorSuffixRe strips company-form words lspci carries along
// ("Realtek Semiconductor Co., Ltd." → "Realtek Semiconductor").
var vendorSuffixRe = regexp.MustCompile(`(?i)[,.]?\s+(co\.?|corp\.?|corporation|inc\.?|ltd\.?|limited|gmbh|ag|llc)\b\.?`)

func joinVendorModel(vendor, model string) string {
	vendor = strings.TrimSpace(vendorSuffixRe.ReplaceAllString(vendor, ""))
	vendor = strings.TrimRight(vendor, ", .")
	model = strings.TrimSpace(model)
	switch {
	case vendor == "":
		return model
	case model == "":
		return vendor
	case strings.HasPrefix(strings.ToLower(model), strings.ToLower(strings.Fields(vendor)[0])):
		return model // "Intel" + "Intel Ethernet I210" → no repetition
	}
	return vendor + " " + model
}

// nicDriver is the kernel driver bound to a port (r8169, igb, virtio_net…).
func nicDriver(iface string) string {
	d, err := filepath.EvalSymlinks(sysClassNet + "/" + iface + "/device/driver")
	if err != nil {
		return ""
	}
	return filepath.Base(d)
}

// driverVendors names the maker behind common NIC drivers, for hosts without
// lspci.
var driverVendors = map[string]string{
	"r8169": "Realtek", "r8168": "Realtek", "r8125": "Realtek", "8139too": "Realtek", "8139cp": "Realtek",
	"e1000": "Intel", "e1000e": "Intel", "igb": "Intel", "igc": "Intel", "ixgbe": "Intel", "i40e": "Intel", "ice": "Intel",
	"tg3": "Broadcom", "bnx2": "Broadcom", "bnx2x": "Broadcom", "bnxt_en": "Broadcom",
	"mlx4_core": "Mellanox", "mlx5_core": "Mellanox", "atlantic": "Aquantia", "alx": "Qualcomm Atheros",
	"atl1c": "Qualcomm Atheros", "sky2": "Marvell", "skge": "Marvell", "virtio_net": "Virtio (virtual)",
	"virtio-pci": "Virtio (virtual)", "vmxnet3": "VMware (virtual)",
}

func driverNICLabel(driver string) string {
	if v := driverVendors[driver]; v != "" {
		return v + " NIC, " + driver + " driver"
	}
	if driver != "" {
		return driver + " driver"
	}
	return "NIC"
}
