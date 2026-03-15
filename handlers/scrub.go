package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleScrubStatus returns the current scrub state for the active pool.
func HandleScrubStatus(w http.ResponseWriter, r *http.Request) {
	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonErr(w, http.StatusNotFound, "no pool available")
		return
	}
	info, err := system.GetScrubStatus(pool.Name)
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, info)
}

// HandleStartScrub starts a scrub on the active pool (admin only).
func HandleStartScrub(w http.ResponseWriter, r *http.Request) {
	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonErr(w, http.StatusNotFound, "no pool available")
		return
	}
	if err := system.StartScrub(pool.Name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "scrub started"})
}

// HandleStopScrub cancels a running scrub (admin only).
func HandleStopScrub(w http.ResponseWriter, r *http.Request) {
	pool, err := system.GetPool()
	if err != nil || pool == nil {
		jsonErr(w, http.StatusNotFound, "no pool available")
		return
	}
	if err := system.StopScrub(pool.Name); err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonOK(w, map[string]string{"message": "scrub stopped"})
}

// HandleGetScrubSchedule returns the current scrub schedule config.
func HandleGetScrubSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]interface{}{
			"schedule": appCfg.ScrubSchedule,
			"hour":     appCfg.ScrubHour,
		})
	}
}

// HandleSetScrubSchedule updates the scrub schedule (admin only).
func HandleSetScrubSchedule(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Schedule string `json:"schedule"`
			Hour     int    `json:"hour"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		switch req.Schedule {
		case "", "weekly", "biweekly", "monthly", "2months", "4months":
			// valid
		default:
			jsonErr(w, http.StatusBadRequest, "invalid schedule value")
			return
		}
		if req.Hour < 0 || req.Hour > 23 {
			jsonErr(w, http.StatusBadRequest, "hour must be 0-23")
			return
		}
		appCfg.ScrubSchedule = req.Schedule
		appCfg.ScrubHour = req.Hour
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save config")
			return
		}
		jsonOK(w, map[string]interface{}{
			"schedule": appCfg.ScrubSchedule,
			"hour":     appCfg.ScrubHour,
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

// StartScrubScheduler runs a goroutine that fires scrubs according to the configured schedule.
func StartScrubScheduler(appCfg *config.AppConfig) {
	go func() {
		tick := time.NewTicker(time.Minute)
		defer tick.Stop()
		for now := range tick.C {
			if !shouldRunScrub(now, appCfg.ScrubSchedule, appCfg.ScrubHour) {
				continue
			}
			pool, err := system.GetPool()
			if err != nil || pool == nil {
				continue
			}
			log.Printf("[scrub] starting auto-scrub (%s at %02d:00) on pool %s",
				appCfg.ScrubSchedule, appCfg.ScrubHour, pool.Name)
			if err := system.StartScrub(pool.Name); err != nil {
				log.Printf("[scrub] auto-scrub failed: %v", err)
			}
		}
	}()
}
