package system

import (
	"fmt"
	"os/exec"
	"strings"
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
