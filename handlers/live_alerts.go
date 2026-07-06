package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/config"
	"zfsnas/internal/version"
	"zfsnas/system"
)

// live_alerts.go — server-side mirror of the browser's _liveAlertsRegistry.
//
// Two endpoints:
//   GET /api/live-alerts            — this server's current alerts.
//   GET /api/live-alerts/aggregate  — local + every interlink peer's, merged
//                                     with the source hostname stamped on each
//                                     entry. Used by the "All Servers" toggle
//                                     in the bottom-bar Live Alerts pane.
//
// Per-peer fetch failures are silently skipped; we still return the rest.

// LiveAlert is the wire shape consumed by the frontend renderer.
type LiveAlert struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // "warn" | "danger"
	Label    string `json:"label"`
	Message  string `json:"message,omitempty"`
	Page     string `json:"page,omitempty"`   // SPA page name to navigate to on click
	System   string `json:"system,omitempty"` // hostname of the originating server
}

// 10-second cache: the derivation runs `zpool status`, `systemctl is-active`,
// etc. per call and the browser polls every 10s, so a tiny TTL keeps cost low
// without making the UI feel laggy after a state change.
var (
	liveAlertsMu       sync.Mutex
	liveAlertsCache    []LiveAlert
	liveAlertsCacheAt  time.Time
	liveAlertsCacheTTL = 10 * time.Second
)

func deriveLiveAlerts(appCfg *config.AppConfig) []LiveAlert {
	liveAlertsMu.Lock()
	defer liveAlertsMu.Unlock()
	if liveAlertsCache != nil && time.Since(liveAlertsCacheAt) < liveAlertsCacheTTL {
		return liveAlertsCache
	}

	hostname, _ := os.Hostname()
	alerts := []LiveAlert{}

	// --- Pool health ---
	pools, _ := system.GetAllPools()
	var faulted, degraded, locked []string
	for _, p := range pools {
		switch p.Health {
		case "FAULTED", "SUSPENDED", "UNAVAIL", "REMOVED":
			faulted = append(faulted, p.Name)
		case "DEGRADED":
			degraded = append(degraded, p.Name)
		}
		if p.Encrypted && p.KeyLocked {
			locked = append(locked, p.Name)
		}
	}
	if len(faulted) > 0 {
		alerts = append(alerts, LiveAlert{
			ID: "pool-health", Severity: "danger",
			Label: "Pool fault detected", Message: strings.Join(faulted, ", "),
			Page: "pool", System: hostname,
		})
	} else if len(degraded) > 0 {
		alerts = append(alerts, LiveAlert{
			ID: "pool-health", Severity: "warn",
			Label: "Pool degraded", Message: strings.Join(degraded, ", "),
			Page: "pool", System: hostname,
		})
	}
	if len(locked) > 0 {
		alerts = append(alerts, LiveAlert{
			ID: "pool-key-locked", Severity: "warn",
			Label: "Encrypted pool key locked", Message: strings.Join(locked, ", "),
			Page: "pool", System: hostname,
		})
	}

	// --- SMB service down (only when shares exist) ---
	if shares, _ := system.ListSMBShares(appCfg.ConfigDir); len(shares) > 0 {
		if system.SambaStatus() == "inactive" {
			alerts = append(alerts, LiveAlert{
				ID: "smb-service", Severity: "danger",
				Label: "SMB service is down",
				Page: "shares", System: hostname,
			})
		}
	}

	// --- NFS service down (only when exports exist) ---
	if exports, _ := system.ListNFSShares(appCfg.ConfigDir); len(exports) > 0 {
		if system.NFSStatus() == "inactive" {
			alerts = append(alerts, LiveAlert{
				ID: "nfs-service", Severity: "danger",
				Label: "NFS service is down",
				Page: "nfs", System: hostname,
			})
		}
	}

	// --- iSCSI service down (only when enabled) ---
	if appCfg.ISCSI.Enabled {
		st := system.GetISCSIServiceStatus()
		if !st.Active {
			alerts = append(alerts, LiveAlert{
				ID: "iscsi-service", Severity: "danger",
				Label: "iSCSI service is down",
				Page: "iscsi", System: hostname,
			})
		}
	}

	// --- Sudoers hardening review pending ---
	// Mirrors the client-side `prereqs` live alert (updatePrereqDot): when
	// hardening is enabled and the installed sudoers file drifts from the
	// required template (unsilenced missing/extra lines), a review is pending.
	// Deriving it here means it survives the "All Servers" aggregate view and
	// is reported by interlink peers (both previously dropped it because it
	// only ever lived in the browser's _liveAlertsRegistry).
	if appCfg.SudoersHardeningEnabled {
		current, _ := sudoersCurrentContent(appCfg)
		diff := system.ComputeSudoersDiff(current, system.RequiredSudoersContent(), appCfg.SudoersSilencedLines)
		pending := 0
		for _, d := range diff.MissingLines {
			if !d.Silenced {
				pending++
			}
		}
		for _, d := range diff.ExtraLines {
			if !d.Silenced {
				pending++
			}
		}
		if pending > 0 {
			s := ""
			if pending != 1 {
				s = "s"
			}
			alerts = append(alerts, LiveAlert{
				ID: "sudoers-pending", Severity: "warn",
				Label:   "Sudoers review pending",
				Message: fmt.Sprintf("%d change%s awaiting approval", pending, s),
				Page:    "prereqs", System: hostname,
			})
		}
	}

	// --- Update available ---
	// Recompute against the *live* running version rather than trusting the
	// VersionCheckCache.UpdateAvailable bool, which is computed at check time
	// against the then-current version. After this server is updated the process
	// runs the new version but that stored flag stays true until the cache
	// refreshes — so a freshly-updated interlink peer would otherwise report a
	// phantom "update available" in the aggregated Live Alerts even though
	// latest == current. Mirrors the recompute in HandleCheckBinaryUpdate.
	if vc := appCfg.VersionCheckCache; vc != nil && semverGreater(vc.Latest, version.Version) {
		msg := ""
		if vc.Latest != "" {
			msg = "v" + vc.Latest
		}
		alerts = append(alerts, LiveAlert{
			ID: "update-available", Severity: "warn",
			Label: "ZNAS update available", Message: msg,
			Page: "updates", System: hostname,
		})
	}

	liveAlertsCache = alerts
	liveAlertsCacheAt = time.Now()
	return alerts
}

// HandleLiveAlerts returns this server's current live alerts.
func HandleLiveAlerts(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, deriveLiveAlerts(appCfg))
	}
}

// HandleLiveAlertsAggregate returns the local live alerts merged with every
// linked peer's. Each entry's System field identifies its origin.
func HandleLiveAlertsAggregate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all := append([]LiveAlert{}, deriveLiveAlerts(appCfg)...)

		var (
			mu sync.Mutex
			wg sync.WaitGroup
		)
		for i := range appCfg.InterLink {
			ls := appCfg.InterLink[i]
			if ls.URL == "" || ls.LinkedBy == "" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				remote, err := fetchPeerLiveAlerts(ls)
				if err != nil {
					return
				}
				// Belt-and-suspenders — backfill hostname from the link
				// record if the peer (older version) didn't stamp it.
				for j := range remote {
					if remote[j].System == "" {
						remote[j].System = ls.Hostname
					}
				}
				mu.Lock()
				all = append(all, remote...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		jsonOK(w, all)
	}
}

// fetchPeerLiveAlerts dials a peer's /api/live-alerts with the standard
// X-Interlink-Relay-* HMAC headers, mirroring the interlink-relay subscriber
// in internal/alerts/interlink_relay_sub.go. The peer's RelayAuthMiddleware
// validates the HMAC and injects a synthetic session for the LinkedBy user.
func fetchPeerLiveAlerts(ls config.LinkedServer) ([]LiveAlert, error) {
	ts := time.Now().Unix()
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, err
	}
	nonceHex := hex.EncodeToString(nonceBytes)
	sig := system.RelayForwardHMAC(ls.SharedSecret, ls.LinkedBy, ts, nonceHex)

	req, err := http.NewRequest("GET", strings.TrimRight(ls.URL, "/")+"/api/live-alerts", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Interlink-Relay-User", ls.LinkedBy)
	req.Header.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Interlink-Relay-Nonce", nonceHex)
	req.Header.Set("X-Interlink-Relay-HMAC", sig)

	client := system.InterlinkClientForRelay(ls.TLSFingerprint)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var out []LiveAlert
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}
