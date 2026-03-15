package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

var (
	diskCache      []system.DiskInfo
	diskCacheStale = true
)

// HandleListDisks returns the cached disk list, refreshing SMART data if stale.
func HandleListDisks(w http.ResponseWriter, r *http.Request) {
	if diskCacheStale || diskCache == nil {
		disks, err := system.ListDisks(config.Dir())
		if err != nil {
			log.Printf("[disks] ListDisks error: %v", err)
			jsonErr(w, http.StatusInternalServerError, "failed to list disks: "+err.Error())
			return
		}
		if disks == nil {
			disks = []system.DiskInfo{}
		}
		diskCache = disks
		diskCacheStale = false
	}
	jsonOK(w, diskCache)
}

// HandleScanDisks triggers an OS-level SCSI bus rescan for newly connected disks,
// then returns the updated disk list (without a slow SMART probe).
func HandleScanDisks(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	log.Printf("[disks] bus rescan requested by %s", sess.Username)

	if err := system.RescanDisks(); err != nil {
		log.Printf("[disks] rescan error: %v", err)
		// Non-fatal — lsblk may still see new disks after a partial rescan.
	}

	diskCacheStale = true
	disks, err := system.ListDisks(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "disk reload failed: "+err.Error())
		return
	}
	diskCache = disks
	diskCacheStale = false
	jsonOK(w, diskCache)
}

// HandleRefreshDisks forces a full SMART refresh (can take several seconds).
func HandleRefreshDisks(w http.ResponseWriter, r *http.Request) {
	sess := MustSession(r)
	log.Printf("[disks] SMART refresh requested by %s", sess.Username)

	if err := system.RefreshSMART(config.Dir()); err != nil {
		jsonErr(w, http.StatusInternalServerError, "SMART refresh failed: "+err.Error())
		return
	}
	diskCacheStale = true

	// Re-load fresh data into cache.
	disks, err := system.ListDisks(config.Dir())
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "disk reload failed: "+err.Error())
		return
	}
	diskCache = disks
	diskCacheStale = false

	jsonOK(w, diskCache)
}

// HandleWipeDisk destroys all partition tables and filesystem signatures on a disk.
// The disk must not be in use by any ZFS pool or mounted.
// Body: {"device": "/dev/sdb"}
func HandleWipeDisk(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Device string `json:"device"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.Device = strings.TrimSpace(req.Device)
	if req.Device == "" {
		jsonErr(w, http.StatusBadRequest, "device is required")
		return
	}
	// Safety check: block wiping a disk that is part of any ZFS pool.
	pools, _ := system.GetAllPools()
	for _, p := range pools {
		for _, m := range append(p.Members, p.MemberDevices...) {
			if strings.HasPrefix(m, req.Device) || strings.HasPrefix(req.Device, m) {
				jsonErr(w, http.StatusConflict, "disk is part of ZFS pool "+p.Name+" — remove it from the pool first")
				return
			}
		}
	}

	if err := system.WipeDisk(req.Device); err != nil {
		jsonErr(w, http.StatusInternalServerError, "wipe failed: "+err.Error())
		return
	}

	diskCacheStale = true

	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  "wipe_disk",
		Target:  req.Device,
		Result:  audit.ResultOK,
		Details: "partition table and filesystem signatures destroyed",
	})

	jsonOK(w, map[string]string{"message": "disk wiped"})
}

// StartDailySmartRefresh launches a background goroutine that refreshes SMART
// data once every 24 hours (and immediately on first start if cache is absent/old).
func StartDailySmartRefresh() {
	go func() {
		// Check if cached data is missing or older than 24h.
		disks, err := system.ListDisks(config.Dir())
		needsRefresh := true
		if err == nil && len(disks) > 0 {
			// All disks share the same refresh timestamp — use the first one.
			for _, d := range disks {
				if !d.UpdatedAt.IsZero() && time.Since(d.UpdatedAt) < 24*time.Hour {
					needsRefresh = false
				}
				break
			}
		}

		if needsRefresh {
			log.Println("[disks] Starting initial SMART refresh…")
			if err := system.RefreshSMART(config.Dir()); err != nil {
				log.Printf("[disks] SMART refresh error: %v", err)
			} else {
				log.Println("[disks] SMART refresh complete.")
				diskCacheStale = true
			}
		} else {
			log.Println("[disks] SMART cache is fresh — skipping initial refresh.")
		}

		// Refresh every 24h thereafter.
		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			log.Println("[disks] Running daily SMART refresh…")
			if err := system.RefreshSMART(config.Dir()); err != nil {
				log.Printf("[disks] Daily SMART refresh error: %v", err)
			} else {
				log.Println("[disks] Daily SMART refresh complete.")
				diskCacheStale = true
			}
		}
	}()
}
