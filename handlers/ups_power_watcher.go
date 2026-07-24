package handlers

// Background UPS power watcher. Every 5 seconds the UPS is queried and its
// on-battery state is compared to the previous reading. The "ups_power_changed"
// notification fires ONCE each time AC power is lost (UPS goes on battery) and
// ONCE each time AC power is restored — edge-triggered and immediate, with no
// throttling: if power drops again shortly after recovering, a fresh "power
// lost" notification is sent (by design — no antispam).
//
// This is deliberately independent of StartUPSShutdownWatcher so notifications
// work even when no automatic-shutdown policy is configured; it only requires
// the UPS feature to be enabled. State is in-memory: the first reading after a
// service restart establishes a silent baseline (whatever state we boot into is
// not announced), and only later transitions notify.

import (
	"fmt"
	"log"
	"time"

	"zfsnas/internal/alerts"
	"zfsnas/internal/config"
	"zfsnas/system"
)

const upsPowerPollInterval = 5 * time.Second

// upsPowerState tracks the last observed on-battery state across polls.
type upsPowerState struct {
	initialized bool
	onBattery   bool
}

// observe records a new on-battery reading and reports whether a notification
// should be sent. The first observation only establishes the baseline and never
// notifies. Afterwards, every change of state notifies exactly once; lost is
// true when AC power was just lost (now on battery), false on recovery.
func (s *upsPowerState) observe(curOnBattery bool) (send bool, lost bool) {
	if !s.initialized {
		s.initialized = true
		s.onBattery = curOnBattery
		return false, false
	}
	if curOnBattery == s.onBattery {
		return false, false
	}
	s.onBattery = curOnBattery
	return true, curOnBattery
}

// StartUPSPowerWatcher launches the 5-second UPS power-transition poller.
func StartUPSPowerWatcher(appCfg *config.AppConfig) {
	go func() {
		var state upsPowerState
		ticker := time.NewTicker(upsPowerPollInterval)
		defer ticker.Stop()
		for range ticker.C {
			ups := appCfg.UPS
			if !ups.Enabled {
				// Feature off — drop any baseline so re-enabling re-baselines
				// silently instead of announcing the state at re-enable time.
				state = upsPowerState{}
				continue
			}

			status := queryUPSStatus(ups)
			if status == nil {
				// UPS not queryable or a transient failure — hold the previous
				// state so a momentary read error doesn't flip the notification.
				continue
			}

			// On battery only when actively on battery AND not on line, matching
			// the shutdown watcher's convention.
			curOnBattery := status.OnBattery && !status.OnLine
			send, lost := state.observe(curOnBattery)
			if !send {
				continue
			}

			name := ups.UPSName
			if name == "" {
				name = "UPS"
			}
			var title, subject, body string
			if lost {
				title = "UPS on battery — AC power lost: " + name
				subject = "UPS Power Lost"
				body = fmt.Sprintf("'%s' switched to battery power — AC input was lost. A follow-up notification is sent when AC power is restored.", name)
			} else {
				title = "UPS AC power restored: " + name
				subject = "UPS Power Restored"
				body = fmt.Sprintf("'%s' is back on AC power after running on battery.", name)
			}
			if err := alerts.Send(alerts.EventUPSPowerChanged, title, subject, body); err != nil {
				log.Printf("[alerts] ups-power send for %s: %v", name, err)
			}
		}
	}()
}

// queryUPSStatus fetches the current UPS status using the same source the
// shutdown watcher uses, honoring the configured mode and falling back to the
// sysfs battery when NUT is not installed. Returns nil on any failure.
func queryUPSStatus(ups config.UPSConfig) *system.UPSStatus {
	if !system.UPSPrereqsInstalled() {
		return system.QuerySysBattery()
	}
	mode := ups.Mode
	if mode == "" {
		mode = "standalone"
	}
	switch mode {
	case "network_client":
		if ups.NUTClient == nil || ups.NUTClient.Host == "" {
			return nil
		}
		status, err := system.QueryUPSClient(ups.NUTClient)
		if err != nil {
			return nil
		}
		return status
	default: // standalone or network_server both query localhost
		if ups.UPSName == "" {
			return nil
		}
		status, err := system.QueryUPS(ups.UPSName)
		if err != nil {
			return nil
		}
		return status
	}
}
