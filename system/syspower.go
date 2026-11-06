package system

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"zfsnas/internal/config"
)

// SystemPowerAvailability contains current settings and feature availability flags.
type SystemPowerAvailability struct {
	Current               config.SystemPowerConfig `json:"current"`
	CPUFreqAvailable      bool                     `json:"cpufreq_available"`
	PowerProfilesAvail    bool                     `json:"power_profiles_available"`
	AvailableGovernors    []string                 `json:"available_governors"`
	PCIeASPMAvailable     bool                     `json:"pcie_aspm_available"`
	AvailableASPMPolicies []string                 `json:"available_aspm_policies"`
}

// GetSystemPowerAvailability reads current active settings + detects feature support.
func GetSystemPowerAvailability() SystemPowerAvailability {
	var avail SystemPowerAvailability

	// CPU governor
	govPath := "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
	if data, err := os.ReadFile(govPath); err == nil {
		avail.CPUFreqAvailable = true
		avail.Current.CPUGovernor = strings.TrimSpace(string(data))
	}
	// Available governors
	availGovPath := "/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_governors"
	if data, err := os.ReadFile(availGovPath); err == nil {
		for _, g := range strings.Fields(string(data)) {
			avail.AvailableGovernors = append(avail.AvailableGovernors, g)
		}
	}

	// Power profile
	if _, err := exec.LookPath("powerprofilesctl"); err == nil {
		avail.PowerProfilesAvail = true
		out, err := exec.Command("powerprofilesctl", "get").Output()
		if err == nil {
			avail.Current.PowerProfile = strings.TrimSpace(string(out))
		}
	}

	// USB autosuspend
	usbPath := "/sys/module/usbcore/parameters/autosuspend"
	if data, err := os.ReadFile(usbPath); err == nil {
		val := strings.TrimSpace(string(data))
		enabled := val != "-1" && val != "0"
		avail.Current.USBAutosuspend = &enabled
	}

	// PCIe ASPM. Format is like `[default] performance powersave powersupersave`
	// — bracketed token is the CURRENT policy, the rest are also valid choices.
	// The set of policies the kernel will accept is exactly the tokens
	// present on this line; on hosts where ASPM is disabled at compile time
	// or via the boot cmdline, fewer tokens appear and writes to other
	// values are rejected. Surface the parsed list so the UI can filter the
	// dropdown to only show what's actually accepted, same pattern as the
	// CPU-governor handling above.
	aspmPath := "/sys/module/pcie_aspm/parameters/policy"
	if data, err := os.ReadFile(aspmPath); err == nil {
		avail.PCIeASPMAvailable = true
		raw := strings.TrimSpace(string(data))
		for _, token := range strings.Fields(raw) {
			policy := token
			isCurrent := strings.HasPrefix(token, "[") && strings.HasSuffix(token, "]")
			if isCurrent {
				policy = strings.Trim(token, "[]")
				avail.Current.PCIeASPM = policy
			}
			avail.AvailableASPMPolicies = append(avail.AvailableASPMPolicies, policy)
		}
	}

	return avail
}

// ApplySystemPowerConfig applies settings and writes persistence config.
func ApplySystemPowerConfig(cfg config.SystemPowerConfig) error {
	// CPU Governor — apply immediately; rc.local handles persistence (see applyRcLocal)
	if cfg.CPUGovernor != "" {
		cpuDirs, _ := filepath.Glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_governor")
		for _, path := range cpuDirs {
			cmd := exec.Command("sudo", "tee", path)
			cmd.Stdin = strings.NewReader(cfg.CPUGovernor + "\n")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("[syspower] set governor %s: %v — %s", path, err, strings.TrimSpace(string(out)))
			}
		}
	}

	// Power profile (daemon persists state)
	if cfg.PowerProfile != "" {
		if _, err := exec.LookPath("powerprofilesctl"); err == nil {
			out, err := exec.Command("powerprofilesctl", "set", cfg.PowerProfile).CombinedOutput()
			if err != nil {
				log.Printf("[syspower] powerprofilesctl set %s: %v — %s", cfg.PowerProfile, err, strings.TrimSpace(string(out)))
			}
		}
	}

	// USB autosuspend + PCIe ASPM — manage block in /etc/rc.local
	if err := applyRcLocal(cfg); err != nil {
		return err
	}

	// Apply USB autosuspend immediately
	if cfg.USBAutosuspend != nil {
		if *cfg.USBAutosuspend {
			// Enable: set autosuspend_delay_ms to 2000
			usbDirs, _ := filepath.Glob("/sys/bus/usb/devices/*/power/autosuspend_delay_ms")
			for _, path := range usbDirs {
				cmd := exec.Command("sudo", "tee", path)
				cmd.Stdin = strings.NewReader("2000\n")
				cmd.CombinedOutput()
			}
			ctrlDirs, _ := filepath.Glob("/sys/bus/usb/devices/*/power/control")
			for _, path := range ctrlDirs {
				cmd := exec.Command("sudo", "tee", path)
				cmd.Stdin = strings.NewReader("auto\n")
				cmd.CombinedOutput()
			}
		} else {
			// Disable: set autosuspend_delay_ms to -1
			usbDirs, _ := filepath.Glob("/sys/bus/usb/devices/*/power/autosuspend_delay_ms")
			for _, path := range usbDirs {
				cmd := exec.Command("sudo", "tee", path)
				cmd.Stdin = strings.NewReader("-1\n")
				cmd.CombinedOutput()
			}
			ctrlDirs, _ := filepath.Glob("/sys/bus/usb/devices/*/power/control")
			for _, path := range ctrlDirs {
				cmd := exec.Command("sudo", "tee", path)
				cmd.Stdin = strings.NewReader("on\n")
				cmd.CombinedOutput()
			}
		}
	}

	// Apply PCIe ASPM immediately
	if cfg.PCIeASPM != "" {
		aspmPath := "/sys/module/pcie_aspm/parameters/policy"
		if _, err := os.Stat(aspmPath); err == nil {
			cmd := exec.Command("sudo", "tee", aspmPath)
			cmd.Stdin = strings.NewReader(cfg.PCIeASPM + "\n")
			if out, err := cmd.CombinedOutput(); err != nil {
				log.Printf("[syspower] set PCIe ASPM: %v — %s", err, strings.TrimSpace(string(out)))
			}
		}
	}

	return nil
}

const (
	rcLocalBegin = "# ===== ZNAS SYSPOWER BEGIN ====="
	rcLocalEnd   = "# ===== ZNAS SYSPOWER END ====="
)

func applyRcLocal(cfg config.SystemPowerConfig) error {
	rcPath := "/etc/rc.local"

	// Read existing content (may not exist)
	existing := ""
	isNew := false
	if data, err := os.ReadFile(rcPath); err == nil {
		existing = string(data)
	} else {
		existing = "#!/bin/sh -e\n\nexit 0\n"
		isNew = true
	}

	// Build the new managed block
	var block strings.Builder
	block.WriteString(rcLocalBegin + "\n")
	if cfg.CPUGovernor != "" {
		block.WriteString("# CPU governor\n")
		block.WriteString(fmt.Sprintf("for f in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo %s > \"$f\" 2>/dev/null; done\n", cfg.CPUGovernor))
	}
	if cfg.USBAutosuspend != nil {
		if *cfg.USBAutosuspend {
			block.WriteString("# USB autosuspend: enabled\n")
			block.WriteString("for f in /sys/bus/usb/devices/*/power/autosuspend_delay_ms; do echo 2000 > \"$f\" 2>/dev/null; done\n")
			block.WriteString("for f in /sys/bus/usb/devices/*/power/control; do echo auto > \"$f\" 2>/dev/null; done\n")
		} else {
			block.WriteString("# USB autosuspend: disabled\n")
			block.WriteString("for f in /sys/bus/usb/devices/*/power/autosuspend_delay_ms; do echo -1 > \"$f\" 2>/dev/null; done\n")
			block.WriteString("for f in /sys/bus/usb/devices/*/power/control; do echo on > \"$f\" 2>/dev/null; done\n")
		}
	}
	if cfg.PCIeASPM != "" {
		block.WriteString("# PCIe ASPM policy\n")
		block.WriteString(fmt.Sprintf("echo %s > /sys/module/pcie_aspm/parameters/policy 2>/dev/null || true\n", cfg.PCIeASPM))
	}
	block.WriteString(rcLocalEnd + "\n")

	// Strip existing managed block
	newContent := stripRcLocalBlock(existing)
	// Insert before exit 0, or append
	if strings.Contains(newContent, "exit 0") {
		newContent = strings.Replace(newContent, "exit 0", block.String()+"\nexit 0", 1)
	} else {
		newContent = strings.TrimRight(newContent, "\n") + "\n\n" + block.String()
	}

	if err := writeFileViaSudo(rcPath, newContent, 0755); err != nil {
		return fmt.Errorf("write rc.local: %w", err)
	}
	// Make executable
	if out, err := exec.Command("sudo", "chmod", "+x", rcPath).CombinedOutput(); err != nil {
		log.Printf("[syspower] chmod +x rc.local: %v — %s", err, strings.TrimSpace(string(out)))
	}
	// If rc.local was newly created, enable and start the rc-local systemd service
	// so the script runs at every boot (the unit exists on modern Debian/Ubuntu but
	// is only activated when /etc/rc.local is present and executable).
	if isNew {
		if out, err := exec.Command("sudo", "systemctl", "enable", "rc-local").CombinedOutput(); err != nil {
			log.Printf("[syspower] systemctl enable rc-local: %v — %s", err, strings.TrimSpace(string(out)))
		}
		if out, err := exec.Command("sudo", "systemctl", "start", "rc-local").CombinedOutput(); err != nil {
			log.Printf("[syspower] systemctl start rc-local: %v — %s", err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func stripRcLocalBlock(content string) string {
	lines := strings.Split(content, "\n")
	var out []string
	inBlock := false
	for _, line := range lines {
		if strings.TrimSpace(line) == rcLocalBegin {
			inBlock = true
			continue
		}
		if strings.TrimSpace(line) == rcLocalEnd {
			inBlock = false
			continue
		}
		if !inBlock {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
