package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// scrubResolvePool picks the pool the request targets. Priority:
//  1. `pool` from query (GET) or JSON body (POST) — required on
//     multi-pool hosts so the UI's selection is honoured.
//  2. Legacy fallback to system.GetPool() — keeps single-pool
//     installs working without a frontend change.
//
// Returns the resolved pool name and an error suitable to surface
// (the caller already mapped it to JSON; this function never writes
// to the response itself).
func scrubResolvePool(r *http.Request) (string, error) {
	// GET → query string. POST → JSON body. We try both regardless of
	// method so a curl user can do whichever feels natural.
	if q := r.URL.Query().Get("pool"); q != "" {
		if p, err := system.GetPoolByName(q); err == nil && p != nil {
			return p.Name, nil
		}
		return "", fmt.Errorf("pool %q not found", q)
	}
	if r.Body != nil && r.ContentLength != 0 {
		var body struct {
			Pool string `json:"pool"`
		}
		// Best-effort decode — an empty body is fine; we fall through
		// to the single-pool default below.
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Pool != "" {
			if p, err := system.GetPoolByName(body.Pool); err == nil && p != nil {
				return p.Name, nil
			}
			return "", fmt.Errorf("pool %q not found", body.Pool)
		}
	}
	def, err := system.GetPool()
	if err != nil || def == nil {
		return "", fmt.Errorf("no pool available")
	}
	return def.Name, nil
}

// HandleScrubStatus returns the current scrub state for the target pool.
// GET /api/pool/scrub/status[?pool=<name>]
func HandleScrubStatus(w http.ResponseWriter, r *http.Request) {
	poolName, err := scrubResolvePool(r)
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	info, err := system.GetScrubStatus(poolName)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, info)
}

// HandleStartScrub starts a scrub on the target pool (admin only).
// POST /api/pool/scrub/start  body: {"pool":"<name>"}
func HandleStartScrub(w http.ResponseWriter, r *http.Request) {
	poolName, err := scrubResolvePool(r)
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err := system.StartScrub(poolName); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "scrub started", "pool": poolName})
}

// HandleStopScrub cancels a running scrub (admin only).
// POST /api/pool/scrub/stop  body: {"pool":"<name>"}
func HandleStopScrub(w http.ResponseWriter, r *http.Request) {
	poolName, err := scrubResolvePool(r)
	if err != nil {
		jsonErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err := system.StopScrub(poolName); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "scrub stopped", "pool": poolName})
}

// scrubPolicyFor returns the effective policy for `poolName`: the
// explicit per-pool entry if present, otherwise the legacy global
// schedule/hour synthesised into a policy. The bool reports whether an
// explicit entry exists (used by the UI to show "(this pool only)" vs
// "(inherited)" labels in future revisions; not surfaced today).
func scrubPolicyFor(appCfg *config.AppConfig, poolName string) (config.PoolScrubPolicy, bool) {
	for _, p := range appCfg.ScrubPolicies {
		if p.Pool == poolName {
			return p, true
		}
	}
	return config.PoolScrubPolicy{
		Pool:     poolName,
		Schedule: appCfg.ScrubSchedule,
		Hour:     appCfg.ScrubHour,
	}, false
}

// HandleGetScrubSchedule returns the scrub schedule for ?pool=<name>.
// Falls back to the legacy global setting when no per-pool entry exists
// (and the caller is on a single-pool install or didn't pass a pool).
// GET /api/pool/scrub/schedule[?pool=<name>]
func HandleGetScrubSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		poolName := r.URL.Query().Get("pool")
		if poolName == "" {
			if def, err := system.GetPool(); err == nil && def != nil {
				poolName = def.Name
			}
		}
		// All scopes get the same shape: schedule+hour+pool. Single-pool
		// hosts that never set anything get a useful default (the
		// legacy global, which may itself be "").
		policy, explicit := scrubPolicyFor(appCfg, poolName)
		jsonOK(w, map[string]interface{}{
			"pool":     policy.Pool,
			"schedule": policy.Schedule,
			"hour":     policy.Hour,
			"explicit": explicit, // false = inherited from legacy global
		})
	}
}

// HandleSetScrubSchedule writes a per-pool schedule (admin only).
// PUT /api/pool/scrub/schedule  body: {"pool":"<name>","schedule":"weekly","hour":2}
// When `pool` is empty the legacy global is updated instead (kept so
// older clients that still PUT without a pool field keep working).
func HandleSetScrubSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Pool     string `json:"pool"`
			Schedule string `json:"schedule"`
			Hour     int    `json:"hour"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		switch req.Schedule {
		case "", "weekly", "biweekly", "monthly", "2months", "4months":
		default:
			jsonErr(w, http.StatusBadRequest, "invalid schedule value")
			return
		}
		if req.Hour < 0 || req.Hour > 23 {
			jsonErr(w, http.StatusBadRequest, "hour must be 0-23")
			return
		}
		if req.Pool == "" {
			// Legacy path: write the global. Multi-pool clients always
			// send `pool` so they don't land here.
			appCfg.ScrubSchedule = req.Schedule
			appCfg.ScrubHour = req.Hour
		} else {
			// Validate that the pool actually exists on this host so a
			// typo doesn't silently persist a no-op entry.
			if p, err := system.GetPoolByName(req.Pool); err != nil || p == nil {
				jsonErr(w, http.StatusBadRequest, fmt.Sprintf("pool %q not found", req.Pool))
				return
			}
			// Upsert into ScrubPolicies.
			found := false
			for i := range appCfg.ScrubPolicies {
				if appCfg.ScrubPolicies[i].Pool == req.Pool {
					appCfg.ScrubPolicies[i].Schedule = req.Schedule
					appCfg.ScrubPolicies[i].Hour = req.Hour
					found = true
					break
				}
			}
			if !found {
				appCfg.ScrubPolicies = append(appCfg.ScrubPolicies, config.PoolScrubPolicy{
					Pool: req.Pool, Schedule: req.Schedule, Hour: req.Hour,
				})
			}
		}
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save config")
			return
		}
		// Echo back the effective policy for the targeted pool so the UI
		// can refresh its dropdowns from the response.
		effPool := req.Pool
		if effPool == "" {
			if def, derr := system.GetPool(); derr == nil && def != nil {
				effPool = def.Name
			}
		}
		policy, explicit := scrubPolicyFor(appCfg, effPool)
		jsonOK(w, map[string]interface{}{
			"pool":     policy.Pool,
			"schedule": policy.Schedule,
			"hour":     policy.Hour,
			"explicit": explicit,
		})
	}
}

// shouldRunScrub returns true when the current time matches the configured scrub schedule.
func shouldRunScrub(now time.Time, schedule string, hour int) bool {
	if schedule == "" {
		return false
	}
	if now.Hour() != hour || now.Minute() != 0 {
		return false
	}
	day := now.Day()
	weekday := now.Weekday()
	month := now.Month()
	switch schedule {
	case "weekly":
		return weekday == time.Sunday
	case "biweekly":
		// 1st and 3rd Sunday of the month
		return weekday == time.Sunday && (day <= 7 || (day >= 15 && day <= 21))
	case "monthly":
		return day == 1
	case "2months":
		// Jan, Mar, May, Jul, Sep, Nov
		return day == 1 && month%2 == 1
	case "4months":
		// Jan, May, Sep
		return day == 1 && (month == time.January || month == time.May || month == time.September)
	}
	return false
}

// StartScrubScheduler runs a goroutine that fires scrubs according to
// the per-pool ScrubPolicies. Each pool's policy is evaluated
// independently — different cadences and hours per pool are supported,
// so a user can scrub the NVMe pool weekly at 02:00 and the bulk HDD
// pool monthly at 04:00. Pools with no explicit entry inherit the
// legacy global ScrubSchedule/ScrubHour (so single-pool installs and
// pre-v6.5.26 configs keep their old behaviour).
func StartScrubScheduler(appCfg *config.AppConfig) {
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for now := range tick.C {
			pools, err := system.GetAllPools()
			if err != nil || len(pools) == 0 {
				continue
			}
			for _, pool := range pools {
				policy, _ := scrubPolicyFor(appCfg, pool.Name)
				if !shouldRunScrub(now, policy.Schedule, policy.Hour) {
					continue
				}
				log.Printf("[scrub] starting auto-scrub (%s at %02d:00) on pool %s",
					policy.Schedule, policy.Hour, pool.Name)
				if err := system.StartScrub(pool.Name); err != nil {
					log.Printf("[scrub] auto-scrub failed on %s: %v", pool.Name, err)
				}
			}
		}
	}()
}
