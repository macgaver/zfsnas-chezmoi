package system

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ── Public types returned by GetDetailedSystemInfo ────────────────────────────

// DetailedSystemInfo is the full hardware snapshot rendered by the SysInfo popup.
// Every field is best-effort; missing values come back as empty strings or zero
// so the frontend can simply hide rows it doesn't have data for.
type DetailedSystemInfo struct {
	CPU          DetailedCPUInfo          `json:"cpu"`
	Memory       DetailedMemoryInfo       `json:"memory"`
	Motherboard  DetailedMotherboardInfo  `json:"motherboard"`
	BIOS         DetailedBIOSInfo         `json:"bios"`
	Controllers  []DetailedDiskController `json:"controllers"`
	GPUs         []DetailedGPU            `json:"gpus"`
	USBDevices   []DetailedUSBDevice      `json:"usb_devices"`
	System       DetailedSystemSummary    `json:"system"`
	// UptimeSeconds is the host uptime from /proc/uptime; 0 when unreadable
	// (or when the response comes from a peer running an older build).
	UptimeSeconds int64 `json:"uptime_seconds"`
}

// DetailedGPU is a display/3D adapter from lspci, with best-effort VRAM.
type DetailedGPU struct {
	Slot        string `json:"slot"`         // PCI BDF, e.g. "01:00.0"
	Class       string `json:"class"`        // "VGA compatible controller" / "3D controller" / "Display controller"
	Vendor      string `json:"vendor"`
	Model       string `json:"model"`
	Driver      string `json:"driver,omitempty"`       // kernel driver in use (amdgpu, nvidia, i915, …)
	MemoryBytes uint64 `json:"memory_bytes"`           // VRAM; 0 = unknown (e.g. shared-memory iGPU)
}

// DetailedUSBDevice is one connected USB device (root hubs excluded), read from
// /sys/bus/usb/devices so it needs no usbutils package.
type DetailedUSBDevice struct {
	Bus          string `json:"bus,omitempty"`
	Device       string `json:"device,omitempty"`
	VendorID     string `json:"vendor_id"`
	ProductID    string `json:"product_id"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Product      string `json:"product"`
	Class        string `json:"class,omitempty"` // friendly USB class (HID, Mass Storage, Hub, …)
}

type DetailedCPUInfo struct {
	Vendor     string  `json:"vendor"`      // e.g. "GenuineIntel" → friendly "Intel"
	Model      string  `json:"model"`       // /proc/cpuinfo "model name"
	Cores      int     `json:"cores"`       // physical cores (best-effort)
	Threads    int     `json:"threads"`     // logical CPUs (always reliable)
	Sockets    int     `json:"sockets"`     // populated when distinct in /proc/cpuinfo
	BaseGHz    float64 `json:"base_ghz"`    // base frequency (cpu MHz divided by 1000) — current value
	MaxGHz     float64 `json:"max_ghz"`     // max boost frequency from cpufreq if present
	Arch       string  `json:"arch"`        // uname -m equivalent

	// Hybrid-CPU breakdown (Intel Alder Lake+ / hybrid ARM big.LITTLE). All four
	// fields are zero when the host is a single-class CPU; the frontend uses
	// `hybrid` as the gate.
	Hybrid     bool    `json:"hybrid"`
	PCores     int     `json:"p_cores"`     // distinct P (performance) physical cores
	PThreads   int     `json:"p_threads"`   // logical CPUs riding on P cores
	ECores     int     `json:"e_cores"`     // distinct E (efficient) physical cores
	EThreads   int     `json:"e_threads"`   // logical CPUs riding on E cores
}

type DetailedMemoryInfo struct {
	TotalBytes uint64               `json:"total_bytes"` // /proc/meminfo MemTotal — kernel-usable RAM
	// InstalledBytes is the sum of the populated DIMM sizes reported by
	// dmidecode — the physically installed RAM. It is slightly larger than
	// TotalBytes, which the kernel/firmware trims by a few hundred MB of
	// reserved regions. 0 when dmidecode is unavailable.
	InstalledBytes uint64        `json:"installed_bytes"`
	DIMMs          []DetailedDIMM `json:"dimms"` // populated by dmidecode -t memory
}

// DetailedDIMM represents one populated DIMM slot. Empty slots are skipped.
type DetailedDIMM struct {
	Locator      string `json:"locator"`        // bank/slot label (e.g. "DIMM_A1")
	SizeBytes    uint64 `json:"size_bytes"`     // 0 = empty slot (filtered out)
	SpeedMTs     int    `json:"speed_mts"`      // configured speed in MT/s
	Type         string `json:"type"`           // e.g. "DDR4", "DDR5"
	Manufacturer string `json:"manufacturer"`
	PartNumber   string `json:"part_number"`
	FormFactor   string `json:"form_factor"`    // e.g. "DIMM", "SODIMM"
}

type DetailedMotherboardInfo struct {
	Manufacturer string `json:"manufacturer"`
	Product      string `json:"product"`
	Version      string `json:"version"`
	Serial       string `json:"serial"`
}

type DetailedBIOSInfo struct {
	Vendor      string `json:"vendor"`
	Version     string `json:"version"`
	ReleaseDate string `json:"release_date"`
}

// DetailedDiskController groups storage controllers (SATA/SAS/NVMe/RAID/USB)
// with the block devices that ride on them.
type DetailedDiskController struct {
	Slot   string                  `json:"slot"`    // PCI BDF, e.g. "00:1f.2"
	Class  string                  `json:"class"`   // e.g. "SATA controller", "Non-Volatile memory controller"
	Vendor string                  `json:"vendor"`
	Model  string                  `json:"model"`
	Disks  []DetailedAttachedDisk  `json:"disks"`
}

type DetailedAttachedDisk struct {
	Device    string `json:"device"`     // e.g. "sda", "nvme0n1"
	Model     string `json:"model"`
	SizeBytes uint64 `json:"size_bytes"`
	Rotation  string `json:"rotation"`   // "ssd", "hdd", or "" if unknown
}

type DetailedSystemSummary struct {
	Hostname     string `json:"hostname"`
	Manufacturer string `json:"manufacturer"`
	ProductName  string `json:"product_name"`
	Serial       string `json:"serial"`
}

// GetDetailedSystemInfo gathers the entire hardware snapshot. Every step is
// independent: a failed dmidecode call leaves the rest of the response intact.
func GetDetailedSystemInfo() DetailedSystemInfo {
	info := DetailedSystemInfo{}
	info.CPU = collectCPUInfo()
	info.Memory = collectMemoryInfo()
	info.Motherboard, info.BIOS, info.System = collectDMIInfo()
	info.Controllers = collectStorageControllers()
	info.GPUs = collectGPUs()
	info.USBDevices = collectUSBDevices()
	if info.System.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			info.System.Hostname = h
		}
	}
	info.UptimeSeconds = hostUptimeSeconds()
	return info
}

// hostUptimeSeconds reads /proc/uptime and returns the host uptime in whole
// seconds, or 0 if it can't be read.
func hostUptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	up, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	return int64(up)
}

// ── CPU ───────────────────────────────────────────────────────────────────────

func collectCPUInfo() DetailedCPUInfo {
	cpu := DetailedCPUInfo{}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return cpu
	}
	defer f.Close()

	physIDs := map[string]struct{}{}
	coreIDs := map[string]struct{}{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	var lastPhys, lastCore string
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "processor":
			cpu.Threads++
		case "vendor_id":
			if cpu.Vendor == "" {
				cpu.Vendor = friendlyCPUVendor(val)
			}
		case "model name":
			if cpu.Model == "" {
				cpu.Model = val
			}
		case "cpu MHz":
			if cpu.BaseGHz == 0 {
				if v, err := strconv.ParseFloat(val, 64); err == nil {
					cpu.BaseGHz = v / 1000
				}
			}
		case "physical id":
			lastPhys = val
			physIDs[val] = struct{}{}
		case "core id":
			lastCore = val
			if lastPhys != "" {
				coreIDs[lastPhys+"|"+lastCore] = struct{}{}
			}
		}
	}
	cpu.Sockets = len(physIDs)
	if cpu.Sockets == 0 {
		cpu.Sockets = 1
	}
	cpu.Cores = len(coreIDs)
	if cpu.Cores == 0 {
		cpu.Cores = cpu.Threads
	}

	// Max boost frequency comes from cpufreq when available; the kernel
	// exposes it in kHz at /sys/devices/system/cpu/cpu*/cpufreq/cpuinfo_max_freq.
	maxKHz := 0
	if entries, _ := filepath.Glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/cpuinfo_max_freq"); len(entries) > 0 {
		for _, p := range entries {
			b, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			v, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err == nil && v > maxKHz {
				maxKHz = v
			}
		}
	}
	if maxKHz > 0 {
		cpu.MaxGHz = float64(maxKHz) / 1_000_000
	}
	if cpu.MaxGHz == 0 {
		cpu.MaxGHz = cpu.BaseGHz
	}

	// Architecture: uname -m
	if out, err := exec.Command("uname", "-m").Output(); err == nil {
		cpu.Arch = strings.TrimSpace(string(out))
	}

	// Hybrid-CPU breakdown (Intel P+E from Alder Lake on, ARM big.LITTLE).
	// GetCPUTopology already separates the logical CPU IDs into PCores and
	// ECores; we then dedupe by physical core_id to derive the distinct
	// physical-core counts.
	if topo, err := GetCPUTopology(); err == nil && topo != nil && topo.Hybrid {
		cpu.Hybrid = true
		cpu.PThreads = len(topo.PCores)
		cpu.EThreads = len(topo.ECores)
		cpu.PCores = countDistinctPhysicalCores(topo.PCores)
		cpu.ECores = countDistinctPhysicalCores(topo.ECores)
	}
	return cpu
}

// countDistinctPhysicalCores reads /sys/devices/system/cpu/cpuN/topology/core_id
// for each logical CPU and counts unique values. Returns len(ids) when
// topology files are missing — common inside VMs and on minimal kernels —
// which matches "1 thread per core" behaviour for E cores anyway.
func countDistinctPhysicalCores(ids []int) int {
	seen := map[string]struct{}{}
	for _, id := range ids {
		path := "/sys/devices/system/cpu/cpu" + strconv.Itoa(id) + "/topology/core_id"
		b, err := os.ReadFile(path)
		if err != nil {
			seen[strconv.Itoa(id)] = struct{}{}
			continue
		}
		seen[strings.TrimSpace(string(b))] = struct{}{}
	}
	return len(seen)
}

func friendlyCPUVendor(raw string) string {
	switch strings.ToLower(raw) {
	case "genuineintel":
		return "Intel"
	case "authenticamd":
		return "AMD"
	case "centaurhauls", "vortex86":
		return raw
	}
	return raw
}

// ── Memory ────────────────────────────────────────────────────────────────────

func collectMemoryInfo() DetailedMemoryInfo {
	mem := DetailedMemoryInfo{}

	// Total from /proc/meminfo
	if f, err := os.Open("/proc/meminfo"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 2 && fields[0] == "MemTotal:" {
				if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
					mem.TotalBytes = v * 1024
				}
				break
			}
		}
		f.Close()
	}

	// Per-DIMM details from `dmidecode -t memory`. Requires root or sudo;
	// falls back silently if we don't have permission.
	out, err := runDMIDecode("memory")
	if err != nil {
		return mem
	}
	mem.DIMMs = parseDMIDecodeMemory(out)
	for _, d := range mem.DIMMs {
		mem.InstalledBytes += d.SizeBytes
	}
	return mem
}

func parseDMIDecodeMemory(out string) []DetailedDIMM {
	var dimms []DetailedDIMM
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	var cur DetailedDIMM
	inDevice := false
	flush := func() {
		if inDevice && cur.SizeBytes > 0 {
			dimms = append(dimms, cur)
		}
		cur = DetailedDIMM{}
		inDevice = false
	}
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "Handle ") {
			flush()
			continue
		}
		if trimmed == "Memory Device" {
			flush()
			inDevice = true
			continue
		}
		if !inDevice {
			continue
		}
		idx := strings.IndexByte(trimmed, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:idx])
		val := strings.TrimSpace(trimmed[idx+1:])
		switch key {
		case "Size":
			cur.SizeBytes = parseMemSize(val)
		case "Locator":
			cur.Locator = val
		case "Type":
			if val != "Unknown" {
				cur.Type = val
			}
		case "Speed":
			cur.SpeedMTs = parseMemSpeed(val)
		case "Configured Memory Speed", "Configured Clock Speed":
			if v := parseMemSpeed(val); v > 0 {
				cur.SpeedMTs = v
			}
		case "Manufacturer":
			if val != "Unknown" && val != "" && val != "Not Specified" {
				cur.Manufacturer = val
			}
		case "Part Number":
			if val != "Unknown" && val != "" && val != "Not Specified" {
				cur.PartNumber = val
			}
		case "Form Factor":
			if val != "Unknown" {
				cur.FormFactor = val
			}
		}
	}
	flush()

	sort.Slice(dimms, func(i, j int) bool { return dimms[i].Locator < dimms[j].Locator })
	return dimms
}

// parseMemSize handles "8 GB", "16384 MB", "No Module Installed", etc.
func parseMemSize(s string) uint64 {
	if s == "" || strings.HasPrefix(s, "No Module") || s == "Unknown" {
		return 0
	}
	parts := strings.Fields(s)
	if len(parts) < 2 {
		return 0
	}
	v, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0
	}
	switch strings.ToUpper(parts[1]) {
	case "GB":
		return v * 1024 * 1024 * 1024
	case "MB":
		return v * 1024 * 1024
	case "TB":
		return v * 1024 * 1024 * 1024 * 1024
	}
	return 0
}

// parseMemSpeed handles "3200 MT/s", "2400 MHz", "Unknown".
func parseMemSpeed(s string) int {
	if s == "" || s == "Unknown" {
		return 0
	}
	parts := strings.Fields(s)
	if len(parts) < 1 {
		return 0
	}
	v, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0
	}
	return v
}

// ── Motherboard / BIOS / system summary (one dmidecode call covers all) ──────

func collectDMIInfo() (DetailedMotherboardInfo, DetailedBIOSInfo, DetailedSystemSummary) {
	mb := DetailedMotherboardInfo{}
	bios := DetailedBIOSInfo{}
	sys := DetailedSystemSummary{}

	if out, err := runDMIDecode("baseboard"); err == nil {
		mb = parseDMIBaseboard(out)
	}
	if out, err := runDMIDecode("bios"); err == nil {
		bios = parseDMIBIOS(out)
	}
	if out, err := runDMIDecode("system"); err == nil {
		sys = parseDMISystem(out)
	}
	return mb, bios, sys
}

func parseDMIBaseboard(out string) DetailedMotherboardInfo {
	mb := DetailedMotherboardInfo{}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		idx := strings.IndexByte(trimmed, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:idx])
		val := strings.TrimSpace(trimmed[idx+1:])
		switch key {
		case "Manufacturer":
			mb.Manufacturer = val
		case "Product Name":
			mb.Product = val
		case "Version":
			if val != "Not Specified" {
				mb.Version = val
			}
		case "Serial Number":
			if val != "Not Specified" && val != "Default string" {
				mb.Serial = val
			}
		}
	}
	return mb
}

func parseDMIBIOS(out string) DetailedBIOSInfo {
	bios := DetailedBIOSInfo{}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		idx := strings.IndexByte(trimmed, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:idx])
		val := strings.TrimSpace(trimmed[idx+1:])
		switch key {
		case "Vendor":
			bios.Vendor = val
		case "Version":
			bios.Version = val
		case "Release Date":
			bios.ReleaseDate = val
		}
	}
	return bios
}

func parseDMISystem(out string) DetailedSystemSummary {
	sys := DetailedSystemSummary{}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		idx := strings.IndexByte(trimmed, ':')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(trimmed[:idx])
		val := strings.TrimSpace(trimmed[idx+1:])
		switch key {
		case "Manufacturer":
			sys.Manufacturer = val
		case "Product Name":
			sys.ProductName = val
		case "Serial Number":
			if val != "Not Specified" && val != "Default string" {
				sys.Serial = val
			}
		}
	}
	return sys
}

// runDMIDecode runs `dmidecode -t <typ>`, retrying through sudo when the direct
// call fails (the binary normally requires root). Returns ("", err) when both
// paths fail; the caller treats that as "data unavailable" and moves on.
func runDMIDecode(typ string) (string, error) {
	if out, err := exec.Command("dmidecode", "-t", typ).Output(); err == nil {
		return string(out), nil
	}
	out, err := exec.Command("sudo", "-n", "/usr/sbin/dmidecode", "-t", typ).Output()
	if err != nil {
		return "", fmt.Errorf("dmidecode -t %s: %w", typ, err)
	}
	return string(out), nil
}

// ── Storage controllers + attached disks ─────────────────────────────────────

func collectStorageControllers() []DetailedDiskController {
	devices, err := ListPCIDevices()
	if err != nil {
		return nil
	}

	// Filter to storage-class controllers only.
	var ctrls []DetailedDiskController
	for _, d := range devices {
		if !isStorageClass(d.Class) {
			continue
		}
		ctrls = append(ctrls, DetailedDiskController{
			Slot:   d.Slot,
			Class:  d.Class,
			Vendor: d.Vendor,
			Model:  d.Device,
		})
	}

	// Map disks to controllers by walking /sys/block/<dev>/device upwards
	// until a PCI BDF appears in the path. The BDF that surfaces is the
	// disk's parent controller's PCI address — exactly what we want.
	disks := enumerateBlockDevices()
	for _, disk := range disks {
		bdf := findControllerBDF(disk.Device)
		if bdf == "" {
			continue
		}
		for i := range ctrls {
			if ctrls[i].Slot == bdf {
				ctrls[i].Disks = append(ctrls[i].Disks, disk)
				break
			}
		}
	}

	// Sort controllers by slot for stable rendering.
	sort.Slice(ctrls, func(i, j int) bool { return ctrls[i].Slot < ctrls[j].Slot })
	for i := range ctrls {
		sort.Slice(ctrls[i].Disks, func(a, b int) bool {
			return ctrls[i].Disks[a].Device < ctrls[i].Disks[b].Device
		})
	}
	return ctrls
}

func isStorageClass(class string) bool {
	c := strings.ToLower(class)
	keywords := []string{"sata", "sas", "raid", "non-volatile memory", "nvme", "ide interface", "scsi storage", "mass storage"}
	for _, k := range keywords {
		if strings.Contains(c, k) {
			return true
		}
	}
	return false
}

// ── GPUs ──────────────────────────────────────────────────────────────────────

// collectGPUs lists display/3D adapters from lspci and attaches a best-effort
// VRAM figure + kernel driver. VRAM is read from the amdgpu DRM sysfs node or
// nvidia-smi when available; integrated GPUs (shared system memory) report 0.
func collectGPUs() []DetailedGPU {
	devices, err := ListPCIDevices()
	if err != nil {
		return nil
	}
	var gpus []DetailedGPU
	for _, d := range devices {
		if !isDisplayClass(d.Class) {
			continue
		}
		bdf := pciFullBDF(d.Slot)
		g := DetailedGPU{
			Slot:   d.Slot,
			Class:  d.Class,
			Vendor: d.Vendor,
			Model:  d.Device,
			Driver: pciDriver(bdf),
		}
		g.MemoryBytes = gpuVRAMBytes(bdf)
		gpus = append(gpus, g)
	}
	sort.Slice(gpus, func(i, j int) bool { return gpus[i].Slot < gpus[j].Slot })
	return gpus
}

func isDisplayClass(class string) bool {
	c := strings.ToLower(class)
	return strings.Contains(c, "vga") ||
		strings.Contains(c, "3d controller") ||
		strings.Contains(c, "display controller")
}

// pciFullBDF normalises an lspci slot ("01:00.0") to a sysfs BDF with the PCI
// domain ("0000:01:00.0"). Slots that already carry a domain are returned as-is.
func pciFullBDF(slot string) string {
	if strings.Count(slot, ":") >= 2 {
		return slot
	}
	return "0000:" + slot
}

// pciDriver returns the kernel driver bound to a PCI device, or "".
func pciDriver(bdf string) string {
	link, err := os.Readlink("/sys/bus/pci/devices/" + bdf + "/driver")
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

// gpuVRAMBytes returns total VRAM for a GPU at the given PCI BDF, 0 if unknown.
func gpuVRAMBytes(bdf string) uint64 {
	if v := amdgpuVRAMForBDF(bdf); v > 0 {
		return v
	}
	if v := nvidiaVRAMForBDF(bdf); v > 0 {
		return v
	}
	return 0
}

// amdgpuVRAMForBDF reads mem_info_vram_total from the DRM card whose PCI device
// matches bdf (amdgpu exposes this; Intel/iGPU do not).
func amdgpuVRAMForBDF(bdf string) uint64 {
	cards, _ := filepath.Glob("/sys/class/drm/card*/device")
	for _, dev := range cards {
		target, err := os.Readlink(dev)
		if err != nil || !strings.HasSuffix(target, bdf) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dev, "mem_info_vram_total"))
		if err != nil {
			continue
		}
		if v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
			return v
		}
	}
	return 0
}

// nvidiaVRAMForBDF queries nvidia-smi (if installed) for the card's total memory.
func nvidiaVRAMForBDF(bdf string) uint64 {
	out, err := exec.Command("nvidia-smi",
		"--query-gpu=pci.bus_id,memory.total", "--format=csv,noheader,nounits").Output()
	if err != nil {
		return 0
	}
	want := strings.ToLower(bdf)
	for _, line := range strings.Split(string(out), "\n") {
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			continue
		}
		// nvidia-smi prints a zero-padded bus id like "00000000:01:00.0".
		if strings.HasSuffix(strings.ToLower(strings.TrimSpace(parts[0])), want) {
			if mib, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 64); err == nil {
				return mib * 1024 * 1024
			}
		}
	}
	return 0
}

// ── USB devices ───────────────────────────────────────────────────────────────

// collectUSBDevices enumerates connected USB devices from /sys/bus/usb/devices
// (no usbutils dependency). Root hubs and interface nodes are excluded.
func collectUSBDevices() []DetailedUSBDevice {
	entries, _ := filepath.Glob("/sys/bus/usb/devices/*")
	var devs []DetailedUSBDevice
	for _, e := range entries {
		base := filepath.Base(e)
		// Interface nodes look like "1-1:1.0" (contain ':'); root hubs are
		// named "usbN". Skip both — we want real downstream devices.
		if strings.Contains(base, ":") || strings.HasPrefix(base, "usb") {
			continue
		}
		vid := readSysStr(filepath.Join(e, "idVendor"))
		pid := readSysStr(filepath.Join(e, "idProduct"))
		if vid == "" || pid == "" {
			continue
		}
		d := DetailedUSBDevice{
			Bus:          readSysStr(filepath.Join(e, "busnum")),
			Device:       readSysStr(filepath.Join(e, "devnum")),
			VendorID:     vid,
			ProductID:    pid,
			Manufacturer: readSysStr(filepath.Join(e, "manufacturer")),
			Product:      readSysStr(filepath.Join(e, "product")),
			Class:        usbClassName(e),
		}
		if d.Product == "" {
			d.Product = vid + ":" + pid
		}
		devs = append(devs, d)
	}
	sort.Slice(devs, func(i, j int) bool {
		if devs[i].Bus != devs[j].Bus {
			return devs[i].Bus < devs[j].Bus
		}
		return devs[i].Device < devs[j].Device
	})
	return devs
}

// usbClassName maps a device's USB class to a friendly label. The device-level
// bDeviceClass is often 00 ("use per-interface"), in which case we fall back to
// the first interface's bInterfaceClass.
func usbClassName(devDir string) string {
	code := readSysStr(filepath.Join(devDir, "bDeviceClass"))
	if code == "00" || code == "" {
		if ifaces, _ := filepath.Glob(filepath.Join(devDir, filepath.Base(devDir)+":*")); len(ifaces) > 0 {
			if ic := readSysStr(filepath.Join(ifaces[0], "bInterfaceClass")); ic != "" {
				code = ic
			}
		}
	}
	switch strings.ToLower(code) {
	case "01":
		return "Audio"
	case "02":
		return "Communications"
	case "03":
		return "HID"
	case "05":
		return "Physical"
	case "06":
		return "Image"
	case "07":
		return "Printer"
	case "08":
		return "Mass Storage"
	case "09":
		return "Hub"
	case "0a":
		return "CDC-Data"
	case "0b":
		return "Smart Card"
	case "0e":
		return "Video"
	case "e0":
		return "Wireless"
	case "ef":
		return "Miscellaneous"
	case "ff":
		return "Vendor Specific"
	}
	return ""
}

// readSysStr reads and trims a sysfs/text file, returning "" on any error.
func readSysStr(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func enumerateBlockDevices() []DetailedAttachedDisk {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil
	}
	var out []DetailedAttachedDisk
	for _, e := range entries {
		name := e.Name()
		// Skip loop, ram, dm-, zd, zram, sr (cdrom): they aren't physical
		// disks even if they show up under /sys/block.
		if strings.HasPrefix(name, "loop") || strings.HasPrefix(name, "ram") ||
			strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "zd") ||
			strings.HasPrefix(name, "zram") || strings.HasPrefix(name, "sr") {
			continue
		}
		// Must have a /sys/block/<name>/device link (= real hardware).
		if _, err := os.Stat("/sys/block/" + name + "/device"); err != nil {
			continue
		}
		disk := DetailedAttachedDisk{Device: name}
		if b, err := os.ReadFile("/sys/block/" + name + "/size"); err == nil {
			if sectors, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
				disk.SizeBytes = sectors * 512
			}
		}
		// Model lives at /sys/block/<name>/device/model on SATA/SAS, and at
		// /sys/block/<name>/device/{model_name,model} on NVMe (varies). Try
		// the conventional path first.
		for _, p := range []string{"/sys/block/" + name + "/device/model", "/sys/block/" + name + "/device/model_name"} {
			if b, err := os.ReadFile(p); err == nil {
				m := strings.TrimSpace(string(b))
				if m != "" {
					disk.Model = m
					break
				}
			}
		}
		// Rotational flag tells us SSD vs HDD.
		if b, err := os.ReadFile("/sys/block/" + name + "/queue/rotational"); err == nil {
			switch strings.TrimSpace(string(b)) {
			case "0":
				disk.Rotation = "ssd"
			case "1":
				disk.Rotation = "hdd"
			}
		}
		out = append(out, disk)
	}
	return out
}

// findControllerBDF resolves /sys/block/<dev>/device to its absolute path and
// scans the components for the *deepest* (closest to the disk) PCI
// bus-device-function token. The token matches the PCI slot reported by
// `lspci`, letting us join disks to their controllers without parsing extra
// metadata.
//
// The path looks like:
//   /sys/devices/pci0000:00/0000:00:1e.0/0000:05:04.0/0000:09:01.0/virtioN/...
// Each PCI BDF segment is a hop down a PCI bridge tree. The leaf one
// (here 0000:09:01.0) is the storage controller; everything above is just a
// bridge chain. lspci omits bridges from `Slot:` for non-bridge classes, so we
// must return the deepest BDF — the earlier code returned the first/shallowest
// BDF, which never matched any storage controller and caused the SysInfo
// popup to show zero attached disks.
//
// pciBDFRe matches DDDD:BB:DD.F (domain optional in the canonical sysfs form,
// always present in /sys/devices, so we accept either).
var pciBDFRe = regexp.MustCompile(`^(?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$`)

func findControllerBDF(dev string) string {
	target, err := filepath.EvalSymlinks("/sys/block/" + dev + "/device")
	if err != nil {
		return ""
	}
	parts := strings.Split(target, "/")
	// Walk from the end so we hit the controller (deepest BDF) first.
	for i := len(parts) - 1; i >= 0; i-- {
		p := parts[i]
		if !pciBDFRe.MatchString(p) {
			continue
		}
		// `lspci -vmm` emits the short BB:DD.F form; strip the optional
		// domain prefix so the join matches.
		if idx := strings.IndexByte(p, ':'); idx == 4 {
			return p[idx+1:]
		}
		return p
	}
	return ""
}
