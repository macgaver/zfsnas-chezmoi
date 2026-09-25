// Appliance mode: detection and helpers for the USB-stick image (v6.8.28).
// See PLANS/spec-6.8.28-usb-appliance.md.
package system

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Paths are vars so tests can point them into a temp dir.
var (
	applianceMarkerPath  = "/etc/zfsnas-appliance"
	applianceReleasePath = "/etc/zfsnas-release"
	osReleasePath        = "/etc/os-release"
	procCmdlinePath      = "/proc/cmdline"
	casperNoPromptPath   = "/run/casper-no-prompt"
	persistStatusPath    = "/var/lib/zfsnas/persist-status"
	persistBinPath       = "/persist/.zfsnas-persist/bin/zfsnas"
	persistStoreDir      = "/persist/.zfsnas-persist"
	authSyncSrcDir       = "/etc"
)

// authSyncFiles are copied /etc/<name> -> <persistStoreDir>/system/etc-auth/<name>,
// matching usbimage/persist-manifest.txt's copy-type entries. These files
// can't be bind mounted: shadow-utils (chpasswd, useradd, ...) update them
// via write-new + rename, which EBUSYs when the target is a mountpoint.
var authSyncFiles = []string{"passwd", "shadow", "group", "gshadow", "subuid", "subgid"}

var (
	applianceOnce   sync.Once
	applianceCached bool
)

// ApplianceMode reports whether we run from the USB appliance image (marker
// file baked into the squashfs). Sticky: the answer cannot change at runtime.
func ApplianceMode() bool {
	applianceOnce.Do(func() { applianceCached = applianceModeUncached() })
	return applianceCached
}

func applianceModeUncached() bool {
	_, err := os.Stat(applianceMarkerPath)
	return err == nil
}

// ApplianceRelease returns the image version and build date from
// /etc/zfsnas-release ("version=6.8.28\nbuild_date=2026-08-28").
func ApplianceRelease() (version, buildDate string) {
	b, err := os.ReadFile(applianceReleasePath)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "version":
			version = v
		case "build_date":
			buildDate = v
		}
	}
	return
}

// ApplianceImage describes the OS image the appliance booted from. The image
// is versioned after the Ubuntu point release it was built on plus our own
// build counter: "26.04.1-2" is the second image built on Ubuntu 26.04.1.
type ApplianceImage struct {
	Version string // "26.04.1-1" — compared against GitHub releases
	Display string // "26.04.1 LTS" — what the Platform page shows
}

// ApplianceImageInfo reads the image version from /etc/zfsnas-release
// (appliance_version=, written by usbimage/build.sh) and the display string
// from /etc/os-release. Images built before appliance_version existed get
// build 0, so the first published image of the same Ubuntu release still
// counts as newer. Zero value off-appliance.
func ApplianceImageInfo() ApplianceImage {
	if !ApplianceMode() {
		return ApplianceImage{}
	}
	return applianceImageInfo(applianceReleasePath, osReleasePath)
}

func applianceImageInfo(releasePath, osRelease string) ApplianceImage {
	fields := readKV(osRelease)
	point, display := ubuntuPointVersion(fields["VERSION"], fields["VERSION_ID"])
	img := ApplianceImage{Display: display}
	if v := readKV(releasePath)["appliance_version"]; v != "" {
		img.Version = v
	} else if point != "" {
		img.Version = point + "-0"
	}
	return img
}

// ubuntuPointVersion turns os-release's VERSION ("26.04.1 LTS (Resolute
// Raccoon)") into the three-part point release ("26.04.1") and the display
// form without the codename ("26.04.1 LTS"). The .0 release carries no point
// digit ("26.04 LTS"), so it is padded to "26.04.0".
func ubuntuPointVersion(version, versionID string) (point, display string) {
	display = strings.TrimSpace(version)
	if i := strings.IndexByte(display, '('); i >= 0 {
		display = strings.TrimSpace(display[:i])
	}
	if display == "" {
		display = versionID
	}
	point = display
	if i := strings.IndexByte(point, ' '); i >= 0 {
		point = point[:i]
	}
	if point == "" {
		return "", display
	}
	if strings.Count(point, ".") == 1 {
		point += ".0"
	}
	return point, display
}

// readKV parses a KEY=value file (os-release / zfsnas-release style);
// surrounding double quotes are stripped. Missing file -> empty map.
func readKV(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		out[k] = strings.Trim(v, `"`)
	}
	return out
}

// ApplianceBootedToRAM reports whether this boot used the "load OS to RAM"
// (toram) GRUB entry — the only mode in which the image on the stick is not
// in use and can be rewritten in place (zfsnas-upgrade-image enforces it too).
func ApplianceBootedToRAM() bool {
	b, err := os.ReadFile(procCmdlinePath)
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(b)) {
		if f == "toram" {
			return true
		}
	}
	return false
}

// DisableCasperShutdownPrompt stops casper-stop from ending every shutdown
// and reboot with "Please remove the installation medium, then press ENTER"
// — without a keypress on the console the appliance never actually reboots.
// Images from 26.04.1-3 on pass `noprompt` on the kernel command line; this
// flag file (checked by casper-stop too) fixes the ones already flashed.
// /run is tmpfs, so it is written on every portal start. No-op off-appliance.
func DisableCasperShutdownPrompt() error {
	if !ApplianceMode() {
		return nil
	}
	return os.WriteFile(casperNoPromptPath, nil, 0644)
}

// PersistStatus returns the persist-store status the initramfs hook wrote
// this boot: "ok", "fresh", "adopted", "overlap-lost", "degraded" — or ""
// off-appliance.
func PersistStatus() string {
	b, err := os.ReadFile(persistStatusPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// AppliancePersistBin is where the self-updater writes new binaries on the
// appliance; run-zfsnas.sh picks it up at service start.
func AppliancePersistBin() string { return persistBinPath }

// AppliancePersistStore is the root of the persist store — the one place on
// the stick that takes writes and survives a reflash.
func AppliancePersistStore() string { return persistStoreDir }

// SyncAuthToPersistStore copies the live auth files (passwd, shadow, group,
// gshadow, subuid, subgid) back into the persist store so changes made at
// runtime (e.g. SetRootSSHAccess's chpasswd) survive a reboot. These files
// are copy-type manifest entries, not bind mounts — see the comment in
// usbimage/persist-manifest.txt for why. No-op off-appliance.
func SyncAuthToPersistStore() error {
	if !ApplianceMode() {
		return nil
	}
	return syncAuthFiles(authSyncSrcDir, persistStoreDir)
}

// syncAuthFiles does the actual copy; split out from SyncAuthToPersistStore
// so it's testable without the ApplianceMode gate (sync.Once-cached
// process-wide, so tests can't flip it back and forth).
func syncAuthFiles(srcDir, storeDir string) error {
	destDir := filepath.Join(storeDir, "system", "etc-auth")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}
	var firstErr error
	for _, name := range authSyncFiles {
		srcPath := filepath.Join(srcDir, name)
		fi, err := os.Stat(srcPath)
		if err != nil {
			continue // missing source file (e.g. subuid absent) -> skip, not an error
		}
		b, err := os.ReadFile(srcPath)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		destPath := filepath.Join(destDir, name)
		mode := fi.Mode().Perm()
		if err := os.WriteFile(destPath, b, mode); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		// os.WriteFile only applies mode on create; force it in case
		// destPath already existed with a different mode.
		if err := os.Chmod(destPath, mode); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
