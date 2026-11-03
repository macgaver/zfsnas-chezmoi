package handlers

// Firewall alerts (event key firewall_events): gateway down/up/failover
// published by the gateway monitor daemon, and a boot that fell back to
// safe mode. Auto-reverts are alerted by the revert service itself.
// "Already sent" marks live in /run, so a portal restart does not replay
// events and a reboot starts clean.

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"zfsnas/internal/alerts"
	"zfsnas/internal/config"
	"zfsnas/system"
)

type sdnAlert struct{ title, subject, body string }

// sdnGatewayAlerts returns the alerts for monitor events newer than last.
func sdnGatewayAlerts(st system.GWStateFile, last time.Time) ([]sdnAlert, time.Time) {
	var out []sdnAlert
	for _, e := range st.Events {
		if !e.At.After(last) {
			continue
		}
		last = e.At
		switch e.Kind {
		case "down":
			out = append(out, sdnAlert{"Gateway down: " + e.Name, "Firewall Gateway Down",
				fmt.Sprintf("Gateway '%s' stopped answering at %s. Traffic using it fails over to the next working gateway.", e.Name, e.At.Format("15:04:05"))})
		case "up":
			out = append(out, sdnAlert{"Gateway back up: " + e.Name, "Firewall Gateway Up",
				fmt.Sprintf("Gateway '%s' has been healthy again since %s.", e.Name, e.At.Format("15:04:05"))})
		case "reconnect":
			out = append(out, sdnAlert{"PPPoE reconnecting: " + e.Name, "Firewall PPPoE Reconnect",
				fmt.Sprintf("Gateway '%s' failed its ping tests, so its PPPoE link was hung up and is redialling (%s).", e.Name, e.At.Format("15:04:05"))})
		case "failover":
			out = append(out, sdnAlert{"Internet traffic now through " + e.Name, "Firewall Gateway Failover",
				fmt.Sprintf("The default route moved to gateway '%s' at %s.", e.Name, e.At.Format("15:04:05"))})
		}
	}
	return out, last
}

// StartSDNEventWatcher polls the monitor state every 10 s.
func StartSDNEventWatcher(appCfg *config.AppConfig) {
	go func() {
		markFile := system.SDNRunFile("alerted-events")
		last := time.Now()
		sentSafe := false
		if b, err := os.ReadFile(markFile); err == nil {
			if t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b))); err == nil {
				last = t
			}
		}
		for {
			time.Sleep(10 * time.Second)
			if st, _ := sdnStoreFor(appCfg).LoadState(); !st.Enabled {
				continue
			}
			if r := system.SDNSafeModeReason(); r != "" {
				mark := system.SDNRunFile("alerted-safemode")
				if _, err := os.Stat(mark); err != nil && !sentSafe {
					sentSafe = true
					_ = os.WriteFile(mark, nil, 0644) // best effort: /run may be root-only
					if err := alerts.Send(alerts.EventFirewall, "Firewall started in SAFE MODE", "Firewall Safe Mode",
						"The firewall could not load its configuration at boot and fell back to safe mode (management access only, no routing). Reason: "+r); err != nil {
						log.Printf("[alerts] firewall safe mode: %v", err)
					}
				}
			}
			list, newLast := sdnGatewayAlerts(system.SDNGatewayState(), last)
			for _, a := range list {
				if err := alerts.Send(alerts.EventFirewall, a.title, a.subject, a.body); err != nil {
					log.Printf("[alerts] firewall: %v", err)
				}
			}
			if newLast.After(last) {
				last = newLast
				_ = os.WriteFile(markFile, []byte(last.Format(time.RFC3339Nano)), 0644)
			}
		}
	}()
}
