package system

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// DiskInfo describes a physical disk detected on the system.
type DiskInfo struct {
	Name       string    `json:"name"`
	Device     string    `json:"device"`
	Size       string    `json:"size"`
	SizeBytes  uint64    `json:"size_bytes"`
	Vendor     string    `json:"vendor"`
	Model      string    `json:"model"`
	Serial     string    `json:"serial"`
	Transport  string    `json:"transport"`
	DiskType   string    `json:"disk_type"` // HDD, SSD, NVMe
	Rotational bool      `json:"rotational"`
	WearoutPct *int      `json:"wearout_pct"` // nil = N/A
	TempC      *int      `json:"temp_c"`      // nil = not available
	SmartOK    bool      `json:"smart_ok"`
	SmartMsg   string    `json:"smart_msg"`
	InUse      bool      `json:"in_use"`
	UpdatedAt  time.Time `json:"updated_at"`
}

const smartCacheFile = "smart_cache.json"

type lsblkOutput struct {
	Blockdevices []lsblkDev `json:"blockdevices"`
}

type lsblkDev struct {
	Name        string     `json:"name"`
	Size        uint64     `json:"size"`
	Rota        any        `json:"rota"`
	Tran        string     `json:"tran"`
	Type        string     `json:"type"`
	// Support both old lsblk (mountpoint, string) and new lsblk ≥2.37 (mountpoints, array).
	Mountpoint  string     `json:"mountpoint"`
	Mountpoints []string   `json:"mountpoints"`
	Children    []lsblkDev `json:"children"`
}

// allMountpoints returns all mountpoint strings for a device, covering both formats.
func (d *lsblkDev) allMountpoints() []string {
	var mps []string
	if d.Mountpoint != "" {
		mps = append(mps, d.Mountpoint)
	}
	for _, mp := range d.Mountpoints {
		if mp != "" {
			mps = append(mps, mp)
		}
	}
	return mps
}

// ListDisks returns physical disks detected by lsblk, annotated with SMART cache data.
func ListDisks(configDir string) ([]DiskInfo, error) {
	cached, _ := loadSmartCache(configDir)

	// Use a minimal column set; get vendor/model from sysfs to avoid null issues on VMs.
	out, err := exec.Command("lsblk", "-J", "-b",
		"-o", "NAME,SIZE,TYPE,ROTA,TRAN,MOUNTPOINT,MOUNTPOINTS").Output()
	if err != nil {
		// Fallback: try without specifying MOUNTPOINTS in case of older lsblk.
		out, err = exec.Command("lsblk", "-J", "-b",
			"-o", "NAME,SIZE,TYPE,ROTA,TRAN,MOUNTPOINT").Output()
		if err != nil {
			return []DiskInfo{}, fmt.Errorf("lsblk failed: %w", err)
		}
	}

	debugLog("lsblk output: %d bytes", len(out))

	var blkInfo lsblkOutput
	if err := json.Unmarshal(out, &blkInfo); err != nil {
		return []DiskInfo{}, fmt.Errorf("lsblk parse failed: %w", err)
	}

	debugLog("parsed %d top-level blockdevices", len(blkInfo.Blockdevices))
	for _, d := range blkInfo.Blockdevices {
		debugLog("  name=%s type=%q tran=%q size=%d mounts=%v/%v",
			d.Name, d.Type, d.Tran, d.Size, d.Mountpoint, d.Mountpoints)
	}

	systemMounts := gatherSystemMounts(blkInfo.Blockdevices)
	debugLog("system-mounted disks: %v", systemMounts)

	disks := []DiskInfo{} // non-nil empty slice so JSON encodes as [] not null
	for _, dev := range blkInfo.Blockdevices {
		if !strings.EqualFold(dev.Type, "disk") {
			continue
		}
		if strings.HasPrefix(dev.Name, "loop") || strings.HasPrefix(dev.Name, "ram") {
			continue
		}

		vendor, model := sysfsVendorModel(dev.Name)

		info := DiskInfo{
			Name:      dev.Name,
			Device:    "/dev/" + dev.Name,
			Size:      formatBytes(dev.Size),
			SizeBytes: dev.Size,
			Vendor:    vendor,
			Model:     model,
			Transport: dev.Tran,
			InUse:     systemMounts[dev.Name],
		}
		info.Rotational = isRotational(dev.Rota)
		info.DiskType = diskType(dev.Tran, info.Rotational)

		if c, ok := cached[dev.Name]; ok {
			info.WearoutPct = c.WearoutPct
			info.TempC      = c.TempC
			info.SmartOK    = c.SmartOK
			info.SmartMsg   = c.SmartMsg
			info.Serial     = c.Serial
			info.UpdatedAt  = c.UpdatedAt
		}

		debugLog("  → adding disk %s (type=%s in_use=%v)", info.Device, info.DiskType, info.InUse)
		disks = append(disks, info)
	}

	debugLog("returning %d disks total", len(disks))
	return disks, nil
}

// RefreshSMART queries smartctl/nvme for all physical disks and writes the cache.
func RefreshSMART(configDir string) error {
	out, err := exec.Command("lsblk", "-J", "-b",
		"-o", "NAME,SIZE,TYPE,ROTA,TRAN,MOUNTPOINT,MOUNTPOINTS").Output()
	if err != nil {
		out, err = exec.Command("lsblk", "-J", "-b",
			"-o", "NAME,SIZE,TYPE,ROTA,TRAN,MOUNTPOINT").Output()
		if err != nil {
			return err
		}
	}

	var blkInfo lsblkOutput
	if err := json.Unmarshal(out, &blkInfo); err != nil {
		return err
	}

	cache := make(map[string]DiskInfo)
	for _, dev := range blkInfo.Blockdevices {
		if !strings.EqualFold(dev.Type, "disk") {
			continue
		}
		if strings.HasPrefix(dev.Name, "loop") || strings.HasPrefix(dev.Name, "ram") {
			continue
		}

		info := DiskInfo{
			Name:      dev.Name,
			Device:    "/dev/" + dev.Name,
			UpdatedAt: time.Now(),
		}

		if dev.Tran == "nvme" {
			querySMARTNVMe(&info)
		} else {
			querySMARTATA(&info)
		}

		cache[dev.Name] = info
	}

	return saveSmartCache(configDir, cache)
}

// querySMARTATA populates wearout/health for SATA/SAS/USB drives via smartctl.
func querySMARTATA(info *DiskInfo) {
	out, err := exec.Command("sudo", "smartctl", "-j", "-a", info.Device).Output()
	if err != nil && len(out) == 0 {
		info.SmartOK = false
		info.SmartMsg = "smartctl unavailable"
		return
	}

	var s smartctlOutput
	if err := json.Unmarshal(out, &s); err != nil {
		info.SmartOK = false
		info.SmartMsg = "parse error"
		return
	}

	info.Serial = s.SerialNumber

	// If SMART is not supported by the device (common on VMs), report N/A.
	if !s.SmartSupport.Available {
		info.SmartOK = true // not failed — just unsupported
		info.SmartMsg = "Not supported"
		return
	}

	info.SmartOK = s.SmartStatus.Passed
	if !info.SmartOK {
		info.SmartMsg = "SMART FAILED"
	} else {
		info.SmartMsg = "Healthy"
	}

	// Temperature — prefer top-level field (smartctl 7+), fall back to attr table.
	if s.Temperature.Current > 0 {
		t := s.Temperature.Current
		info.TempC = &t
	}

	for _, attr := range s.AtaSmartAttributes.Table {
		// Temperature from attribute table (ID 194 or 190) if not already set.
		if info.TempC == nil {
			id := attr.ID
			if id == 194 || id == 190 {
				t := attr.Raw.Value
				if t > 0 && t < 100 {
					info.TempC = &t
				}
			}
		}
		name := strings.ToLower(attr.Name)
		// Skip non-wear attributes that can match our ID checks (e.g. Life_Curve_Status, Temperature).
		if strings.Contains(name, "life_curve") || strings.Contains(name, "curve_status") ||
			strings.Contains(name, "temp") {
			continue
		}
		matched := strings.Contains(name, "wear_leveling_count") ||
			strings.Contains(name, "wear_leveling") ||
			strings.Contains(name, "ssd_life") ||
			strings.Contains(name, "life_left") ||
			strings.Contains(name, "percent_lifetime_remain") ||
			strings.Contains(name, "media_wearout") ||
			attr.ID == 177 || // Wear_Leveling_Count (Samsung, etc.)
			(attr.ID == 231 && (strings.Contains(name, "life") || strings.Contains(name, "wear")))
		if !matched {
			continue
		}
		worn := 100 - attr.Value
		if worn < 0 {
			worn = 0
		}
		if worn > 100 {
			worn = 100
		}
		info.WearoutPct = &worn
		break
	}
}

// querySMARTNVMe populates wearout/health for NVMe drives via nvme-cli.
func querySMARTNVMe(info *DiskInfo) {
	out, err := exec.Command("sudo", "nvme", "smart-log", "-o", "json", info.Device).Output()
	if err != nil && len(out) == 0 {
		querySMARTATA(info) // fallback
		return
	}

	var nlog nvmeSmartLog
	if err := json.Unmarshal(out, &nlog); err != nil {
		info.SmartOK = false
		info.SmartMsg = "parse error"
		return
	}

	info.SmartOK = nlog.CriticalWarning == 0
	if !info.SmartOK {
		info.SmartMsg = fmt.Sprintf("Critical warning: 0x%x", nlog.CriticalWarning)
	} else {
		info.SmartMsg = "Healthy"
	}

	// Temperature: nvme smart-log reports Kelvin; convert to Celsius.
	if nlog.Temperature > 273 {
		t := nlog.Temperature - 273
		info.TempC = &t
	}

	// Use whichever field is non-zero (nvme-cli versions differ in field name).
	worn := nlog.PercentageUsed
	if nlog.PercentUsed > worn {
		worn = nlog.PercentUsed
	}
	if worn < 0 {
		worn = 0
	}
	if worn > 100 {
		worn = 100
	}
	info.WearoutPct = &worn

	if sout, err := exec.Command("sudo", "smartctl", "-j", "-i", info.Device).Output(); err == nil {
		var s smartctlOutput
		if json.Unmarshal(sout, &s) == nil {
			info.Serial = s.SerialNumber
		}
	}
}

// sysfsVendorModel reads vendor and model from /sys/block/<name>/device/.
// This is more reliable than lsblk VENDOR/MODEL, especially on VMs.
func sysfsVendorModel(name string) (vendor, model string) {
	vendor = strings.TrimSpace(readSysfs("/sys/block/" + name + "/device/vendor"))
	model = strings.TrimSpace(readSysfs("/sys/block/" + name + "/device/model"))
	// NVMe devices have a different sysfs path.
	if vendor == "" && model == "" {
		model = strings.TrimSpace(readSysfs("/sys/block/" + name + "/device/model"))
		// Try the nvme subsystem path.
		vendor = strings.TrimSpace(readSysfs("/sys/class/nvme/" + name + "/device/vendor"))
	}
	return
}

func readSysfs(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// ---- JSON structures ----

type smartctlOutput struct {
	SerialNumber string `json:"serial_number"`
	SmartSupport struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	Temperature struct {
		Current int `json:"current"` // smartctl 7+ top-level temperature
	} `json:"temperature"`
	AtaSmartAttributes struct {
		Table []struct {
			ID    int    `json:"id"`
			Name  string `json:"name"`
			Value int    `json:"value"`
			Raw   struct {
				Value int `json:"value"`
			} `json:"raw"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
}

type nvmeSmartLog struct {
	CriticalWarning int `json:"critical_warning"`
	PercentageUsed  int `json:"percentage_used"` // nvme-cli 1.x field name
	PercentUsed     int `json:"percent_used"`     // nvme-cli 2.x field name
	Temperature     int `json:"temperature"`      // Kelvin (nvme smart-log)
}

// ---- Cache helpers ----

func smartCachePath(configDir string) string {
	return filepath.Join(configDir, smartCacheFile)
}

func loadSmartCache(configDir string) (map[string]DiskInfo, error) {
	data, err := os.ReadFile(smartCachePath(configDir))
	if err != nil {
		return nil, err
	}
	var cache map[string]DiskInfo
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	return cache, nil
}

func saveSmartCache(configDir string, cache map[string]DiskInfo) error {
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(smartCachePath(configDir), data, 0640)
}

// ---- Helpers ----

func gatherSystemMounts(devs []lsblkDev) map[string]bool {
	result := make(map[string]bool)
	systemPrefixes := []string{"/", "/boot", "/home", "/usr", "/var", "/opt", "[SWAP]"}

	var walk func(diskName string, dev lsblkDev)
	walk = func(diskName string, dev lsblkDev) {
		for _, mp := range dev.allMountpoints() {
			mp = strings.TrimSpace(mp)
			for _, pfx := range systemPrefixes {
				if mp == pfx || strings.HasPrefix(mp, pfx+"/") {
					result[diskName] = true
				}
			}
		}
		for _, child := range dev.Children {
			walk(diskName, child)
		}
	}

	for _, dev := range devs {
		if strings.EqualFold(dev.Type, "disk") {
			walk(dev.Name, dev)
		}
	}
	return result
}

func isRotational(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "1"
	case float64:
		return val == 1
	}
	return false
}

func diskType(tran string, rotational bool) string {
	if tran == "nvme" {
		return "NVMe"
	}
	if rotational {
		return "HDD"
	}
	return "SSD"
}

// formatBytes formats a byte count using 1024-based units (matching lsblk/OS conventions).
// Labels use common convention (GB, TB) rather than IEC (GiB, TiB).
func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	val := float64(b) / float64(div)
	// Show whole number when it's exact (e.g. "8 GB" not "8.0 GB").
	if val == float64(int(val)) {
		return fmt.Sprintf("%d %cB", int(val), "KMGTPE"[exp])
	}
	return fmt.Sprintf("%.1f %cB", val, "KMGTPE"[exp])
}

// RescanDisks asks the kernel to probe for newly connected physical disks by
// writing "- - -" to every SCSI host scan file, then waits for udev to settle.
func RescanDisks() error {
	hosts, err := filepath.Glob("/sys/class/scsi_host/host*/scan")
	if err != nil {
		return fmt.Errorf("glob scsi hosts: %w", err)
	}
	for _, scanFile := range hosts {
		// Errors on individual hosts are non-fatal (some may be read-only).
		_ = os.WriteFile(scanFile, []byte("- - -"), 0200)
	}
	// Give udev time to create device nodes for any newly detected disks.
	exec.Command("udevadm", "settle", "--timeout=5").Run() //nolint
	return nil
}
