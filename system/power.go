package system

import (
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Reboot schedules an immediate system reboot.
func Reboot() error {
	out, err := exec.Command("sudo", "shutdown", "-r", "now").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// Shutdown schedules an immediate system power-off.
func Shutdown() error {
	out, err := exec.Command("sudo", "shutdown", "-h", "now").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// RestartPortal restarts the zfsnas systemd service.
// It schedules the restart in a goroutine so the HTTP response can be sent first.
func RestartPortal() {
	go func() {
		time.Sleep(300 * time.Millisecond)
		exec.Command("sudo", "systemctl", "restart", "zfsnas").Run()
	}()
}
