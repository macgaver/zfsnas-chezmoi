package handlers

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/updater"
	"zfsnas/internal/version"
	"zfsnas/system"
)

// firstBootUpdateMarker records that the one-shot first-boot update check has
// run. It lives in the persist store, so it survives the reboot but not a
// fresh stick — a newly flashed appliance checks once, then leaves updates to
// the normal scheduler.
const firstBootUpdateMarker = "firstboot-update.done"

// firstBootUpdateAttempts is how long we give the network to come up before
// giving up: DHCP, DNS and the default route are still settling while the
// portal is already serving, so an immediate check would report "no internet"
// on a box that has it.
var (
	firstBootUpdateAttempts = 12
	firstBootUpdateDelay    = 15 * time.Second
)

// RunApplianceFirstBootUpdate replaces the baked binary with the latest signed
// release from GitHub, once, on the first boot of a freshly flashed stick.
//
// The image ships whatever was current when it was built, which may be months
// old by the time someone boots it. Everything here is best-effort: no network,
// no release, a bad signature or a failed write all leave the baked binary
// running. It is deliberately the same download → verify → replace → restart
// path the UI upgrade uses, so a release that installs from the portal installs
// here too, and one that fails verification is refused in both places.
func RunApplianceFirstBootUpdate(appCfg *config.AppConfig) {
	if !system.ApplianceMode() {
		return
	}
	marker := filepath.Join(system.AppliancePersistStore(), firstBootUpdateMarker)
	if _, err := os.Stat(marker); err == nil {
		return
	}

	info, ok := firstBootWaitForRelease()
	if !ok {
		// No internet this boot. Leave the marker alone so a box that gets
		// plugged into the network later still gets its one check.
		log.Printf("[firstboot-update] no internet — keeping the image binary, will retry next boot")
		return
	}
	// The check itself is what we record, not its outcome: once we have talked
	// to GitHub, the daily scheduler owns updates from here on.
	if err := os.WriteFile(marker, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0644); err != nil {
		log.Printf("[firstboot-update] could not write %s: %v", marker, err)
	}

	latest := strings.TrimPrefix(info.Tag, "v")
	if !semverGreater(latest, version.Version) {
		log.Printf("[firstboot-update] image is current (v%s)", version.Version)
		return
	}

	destPath := system.AppliancePersistBin()
	log.Printf("[firstboot-update] v%s available (image has v%s) — downloading", latest, version.Version)
	if err := installFirstBootRelease(info, destPath, defaultFirstBootDeps()); err != nil {
		log.Printf("[firstboot-update] %v — keeping the image binary", err)
		audit.Log(audit.Entry{User: "system", Role: "admin", Action: audit.ActionSoftwareUpdate,
			Result:  audit.ResultError,
			Details: "first-boot update to v" + latest + " refused: " + err.Error()})
		return
	}

	audit.Log(audit.Entry{User: "system", Role: "admin", Action: audit.ActionSoftwareUpdate,
		Result:  audit.ResultOK,
		Details: "first-boot update from v" + version.Version + " to v" + latest})
	appCfg.VersionCheckCache = nil
	config.SaveAppConfig(appCfg)

	// Restart through systemd so run-zfsnas.sh re-evaluates the override and
	// adopts the newer binary.
	log.Printf("[firstboot-update] installed v%s — restarting the portal", latest)
	_ = exec.Command("systemctl", "restart", "zfsnas.service").Start()
}

// firstBootDeps are the three steps that touch the network and the disk,
// injected so the refusal rules below can be tested without either.
type firstBootDeps struct {
	download func(url, destDir string) (string, error)
	verify   func(path, sigURL string) error
	replace  func(tmpPath, destPath string) error
}

func defaultFirstBootDeps() firstBootDeps {
	return firstBootDeps{
		download: updater.Download,
		verify:   updater.VerifyDownloadedBinary,
		replace:  updater.Replace,
	}
}

// installFirstBootRelease downloads, verifies and installs one release.
//
// Every failure path deletes the download and leaves destPath alone: the
// binary baked into the image is the fallback, and an unverified binary must
// never reach the persist store, where the launcher would adopt it on the next
// boot purely because its version string is higher.
func installFirstBootRelease(info updater.ReleaseInfo, destPath string, d firstBootDeps) error {
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("persist store not writable: %w", err)
	}
	// An unsigned release is not an upgrade path: the point of shipping a key
	// in the binary is that nothing installs without one.
	if info.SigURL == "" {
		return fmt.Errorf("release %s has no signature asset", info.Tag)
	}
	tmpPath, err := d.download(info.DownloadURL, destDir)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	if err := d.verify(tmpPath, info.SigURL); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("signature check failed: %w", err)
	}
	if err := d.replace(tmpPath, destPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("install failed: %w", err)
	}
	return nil
}

// firstBootWaitForRelease polls GitHub until the network is up, returning
// false when it never came up.
func firstBootWaitForRelease() (updater.ReleaseInfo, bool) {
	for i := 0; i < firstBootUpdateAttempts; i++ {
		if i > 0 {
			time.Sleep(firstBootUpdateDelay)
		}
		info, err := updater.CheckLatest()
		if err == nil && info.DownloadURL != "" {
			return info, true
		}
	}
	return updater.ReleaseInfo{}, false
}
