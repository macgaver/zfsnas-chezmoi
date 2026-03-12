package handlers

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"zfsnas/internal/config"
	"zfsnas/internal/scheduler"
	"zfsnas/internal/version"
	"zfsnas/system"
)

// TrueNAS-compatible read-only REST API (v2.0).
// All routes require session cookie or Authorization: Bearer <api_key>.
//
// Implemented endpoints:
//   GET /api/v2.0/alert/list
//   GET /api/v2.0/system/info
//   GET /api/v2.0/system/version
//   GET /api/v2.0/pool
//   GET /api/v2.0/pool/dataset
//   GET /api/v2.0/pool/snapshottask
//   GET /api/v2.0/snapshot
//   GET /api/v2.0/disk
//   GET /api/v2.0/sharing/smb
//   GET /api/v2.0/sharing/nfs
//   GET /api/v2.0/service

// ── Alerts ────────────────────────────────────────────────────────────────────

// HandleHomepageAlertList returns an empty alert array.
// The homepage widget counts items where dismissed == false.
func HandleHomepageAlertList(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, []interface{}{})
}

// ── System ────────────────────────────────────────────────────────────────────

// HandleHomepageSystemInfo returns load average and uptime (TrueNAS-compatible).
func HandleHomepageSystemInfo(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, map[string]interface{}{
		"loadavg":        readLoadAvg(),
		"uptime_seconds": readUptimeSeconds(),
	})
}

// HandleHomepageSystemVersion returns the application version string.
func HandleHomepageSystemVersion(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, "ZFS-NAS-"+version.Version)
}

// ── Pool ──────────────────────────────────────────────────────────────────────

// HandleHomepagePools returns the ZFS pool list with health status (TrueNAS-compatible).
func HandleHomepagePools(w http.ResponseWriter, r *http.Request) {
	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonOK(w, []interface{}{})
		return
	}
	jsonOK(w, []map[string]interface{}{
		{
			"name":    pool.Name,
			"healthy": pool.Health == "ONLINE",
			"status":  pool.Health,
			"size":    pool.Size,
			"allocated": pool.Alloc,
			"free":    pool.Free,
		},
	})
}

// HandleHomepageDatasets returns datasets with used/available (TrueNAS-compatible).
// The homepage widget matches: d.pool === pool.name && d.name === pool.name.
func HandleHomepageDatasets(w http.ResponseWriter, r *http.Request) {
	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonOK(w, []interface{}{})
		return
	}
	datasets, err := system.ListDatasets(pool.Name)
	if err != nil {
		jsonOK(w, []interface{}{})
		return
	}
	out := make([]map[string]interface{}, 0, len(datasets))
	for _, d := range datasets {
		out = append(out, map[string]interface{}{
			"id":   d.Name,
			"pool": pool.Name,
			"name": d.Name,
			"used": map[string]interface{}{
				"value":  byteStr(d.Used),
				"parsed": d.Used,
			},
			"available": map[string]interface{}{
				"value":  byteStr(d.Avail),
				"parsed": d.Avail,
			},
			"quota": map[string]interface{}{
				"value":  byteStr(d.Quota),
				"parsed": d.Quota,
			},
			"compression": d.Compression,
			"mountpoint":  d.Mountpoint,
		})
	}
	jsonOK(w, out)
}

// ── Snapshots ─────────────────────────────────────────────────────────────────

// HandleHomepageSnapshots returns all snapshots (TrueNAS-compatible).
func HandleHomepageSnapshots(w http.ResponseWriter, r *http.Request) {
	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonOK(w, []interface{}{})
		return
	}
	snaps, err := system.ListSnapshots(pool.Name)
	if err != nil {
		jsonOK(w, []interface{}{})
		return
	}
	out := make([]map[string]interface{}, 0, len(snaps))
	for _, s := range snaps {
		out = append(out, map[string]interface{}{
			"id":            s.Name,
			"name":          s.Name,
			"dataset":       s.Dataset,
			"snapshot_name": s.SnapName,
			"properties": map[string]interface{}{
				"creation": map[string]interface{}{
					"value":   s.Creation.Format("Mon Jan  2 15:04 2006"),
					"rawvalue": strconv.FormatInt(s.Creation.Unix(), 10),
				},
				"used": map[string]interface{}{
					"value":   s.UsedStr,
					"rawvalue": strconv.FormatUint(s.Used, 10),
					"parsed":  s.Used,
				},
				"refer": map[string]interface{}{
					"value":   s.ReferStr,
					"rawvalue": strconv.FormatUint(s.Refer, 10),
					"parsed":  s.Refer,
				},
			},
		})
	}
	jsonOK(w, out)
}

// HandleHomepageSnapshotTasks returns snapshot policies (TrueNAS pool.snapshottask-compatible).
func HandleHomepageSnapshotTasks(w http.ResponseWriter, r *http.Request) {
	policies, err := scheduler.LoadPolicies()
	if err != nil {
		jsonOK(w, []interface{}{})
		return
	}
	out := make([]map[string]interface{}, 0, len(policies))
	for _, p := range policies {
		out = append(out, map[string]interface{}{
			"id":          p.ID,
			"dataset":     p.Dataset,
			"recursive":   false,
			"lifetime_value": p.Retention,
			"lifetime_unit":  "COUNT",
			"enabled":     p.Enabled,
			"naming_schema": p.Label + "-%Y%m%d-%H%M",
			"schedule": map[string]interface{}{
				"minute":  strconv.Itoa(p.Minute),
				"hour":    strconv.Itoa(p.Hour),
				"dom":     strconv.Itoa(p.DayOfMonth),
				"month":   "*",
				"dow":     strconv.Itoa(p.Weekday),
			},
			"state": map[string]interface{}{
				"state":     p.LastStatus,
				"last_run":  p.LastRun,
			},
		})
	}
	jsonOK(w, out)
}

// ── Disks ─────────────────────────────────────────────────────────────────────

// HandleHomepageDisks returns physical disk list (TrueNAS-compatible).
func HandleHomepageDisks(w http.ResponseWriter, r *http.Request) {
	disks, err := system.ListDisks(config.Dir())
	if err != nil {
		jsonOK(w, []interface{}{})
		return
	}
	out := make([]map[string]interface{}, 0, len(disks))
	for _, d := range disks {
		entry := map[string]interface{}{
			"identifier":  "{serial}" + d.Serial,
			"name":        d.Name,
			"serial":      d.Serial,
			"model":       d.Model,
			"description": d.Vendor + " " + d.Model,
			"size":        d.SizeBytes,
			"type":        d.DiskType,
			"rotational":  d.Rotational,
			"in_use":      d.InUse,
		}
		if d.TempC != nil {
			entry["temperature"] = *d.TempC
		}
		out = append(out, entry)
	}
	jsonOK(w, out)
}

// ── Shares ────────────────────────────────────────────────────────────────────

// HandleHomepageSMBShares returns SMB shares (TrueNAS sharing/smb-compatible).
func HandleHomepageSMBShares(w http.ResponseWriter, r *http.Request) {
	shares, err := system.ListSMBShares(config.Dir())
	if err != nil {
		jsonOK(w, []interface{}{})
		return
	}
	out := make([]map[string]interface{}, 0, len(shares))
	for i, s := range shares {
		out = append(out, map[string]interface{}{
			"id":       i + 1,
			"name":     s.Name,
			"path":     s.Path,
			"comment":  s.Comment,
			"ro":       s.ReadOnly,
			"browsable": s.Browseable,
			"guestok":  s.GuestOK,
			"timemachine": s.TimeMachine,
		})
	}
	jsonOK(w, out)
}

// HandleHomepageNFSShares returns NFS shares (TrueNAS sharing/nfs-compatible).
func HandleHomepageNFSShares(w http.ResponseWriter, r *http.Request) {
	shares, err := system.ListNFSShares(config.Dir())
	if err != nil {
		jsonOK(w, []interface{}{})
		return
	}
	out := make([]map[string]interface{}, 0, len(shares))
	for _, s := range shares {
		out = append(out, map[string]interface{}{
			"id":      s.ID,
			"paths":   []string{s.Path},
			"comment": s.Comment,
			"ro":      s.ReadOnly,
			"hosts":   []string{s.Client},
			"maproot_squash": !s.NoRootSquash,
		})
	}
	jsonOK(w, out)
}

// ── Services ──────────────────────────────────────────────────────────────────

// HandleHomepageServices returns running state of SMB and NFS services (TrueNAS-compatible).
func HandleHomepageServices(w http.ResponseWriter, r *http.Request) {
	smbState := serviceState(system.SambaStatus())
	nfsState := serviceState(system.NFSStatus())
	jsonOK(w, []map[string]interface{}{
		{"id": 1, "service": "cifs", "state": smbState, "enable": smbState == "RUNNING"},
		{"id": 2, "service": "nfs",  "state": nfsState, "enable": nfsState == "RUNNING"},
	})
}

// serviceState maps our status strings to TrueNAS-style state strings.
func serviceState(s string) string {
	if s == "active" {
		return "RUNNING"
	}
	return "STOPPED"
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// readLoadAvg reads /proc/loadavg and returns [1min, 5min, 15min] averages.
func readLoadAvg() [3]float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return [3]float64{}
	}
	fields := strings.Fields(string(data))
	var result [3]float64
	for i := 0; i < 3 && i < len(fields); i++ {
		result[i], _ = strconv.ParseFloat(fields[i], 64)
	}
	return result
}

// readUptimeSeconds reads /proc/uptime and returns uptime in whole seconds.
func readUptimeSeconds() int64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	f, _ := strconv.ParseFloat(fields[0], 64)
	return int64(f)
}

// byteStr formats a byte count as a human-readable string (e.g. "1.5 GiB").
func byteStr(b uint64) string {
	const (
		kib = 1024
		mib = 1024 * kib
		gib = 1024 * mib
		tib = 1024 * gib
	)
	switch {
	case b >= tib:
		return strconv.FormatFloat(float64(b)/tib, 'f', 2, 64) + " TiB"
	case b >= gib:
		return strconv.FormatFloat(float64(b)/gib, 'f', 2, 64) + " GiB"
	case b >= mib:
		return strconv.FormatFloat(float64(b)/mib, 'f', 2, 64) + " MiB"
	case b >= kib:
		return strconv.FormatFloat(float64(b)/kib, 'f', 2, 64) + " KiB"
	default:
		return strconv.FormatUint(b, 10) + " B"
	}
}
