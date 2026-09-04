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
