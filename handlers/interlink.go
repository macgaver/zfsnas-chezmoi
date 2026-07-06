package handlers

import (
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/alerts"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/interlink"
	"zfsnas/internal/session"
	"zfsnas/internal/totp"
	"zfsnas/internal/version"
	"zfsnas/system"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// ─── online-status cache ─────────────────────────────────────────────────────

type serverStatus struct {
	Online        bool
	RemoteVersion string
	LXDEnabled    bool
	FetchedAt     time.Time
	// Hostname (v6.5.43) — the peer's CURRENT system hostname returned
	// by the live ping. The stored config.LinkedServer.Hostname is
	// frozen at link time, so renaming a peer leaves the dropdown
	// showing the old name forever. Cached here for the 30s TTL window
	// and used by HandleInterlinkList to override the stale config
	// value. Empty when populated from accept-link / push-ssh-key
	// (which don't ping).
	Hostname string
}

var (
	statusCacheMu  sync.Mutex
	statusCache    = map[string]serverStatus{} // keyed by LinkedServer.ID
	statusCacheTTL = 30 * time.Second
)

// interlinkMu serialises read-check-append and dedupe/save cycles on
// appCfg.InterLink. Without it, cluster propagation (which fires several
// accept-link requests concurrently) can race two handlers past the
// "already linked?" check and append the same peer twice — the duplicate
// that shows up as a server "listed twice" and doubles the ping work.
var interlinkMu sync.Mutex

// interlinkListMaxWait bounds how long the "Manage InterLink" list waits for
// live peer pings. One unreachable peer used to make every goroutine block up
// to ~90s (PingServer + RemotePingHasLXD + GetRemoteZFSAccess, each 30s), and
// the endpoint waited for all of them — so the modal sat on "Loading…". Past
// this deadline we fill any missing peer from its cached status (or mark it
// offline) and return, so a dead peer can't hang the screen.
const interlinkListMaxWait = 8 * time.Second

func cachedStatus(id string) (serverStatus, bool) {
	statusCacheMu.Lock()
	defer statusCacheMu.Unlock()
	s, ok := statusCache[id]
	if !ok || time.Since(s.FetchedAt) > statusCacheTTL {
		return serverStatus{}, false
	}
	return s, true
}

func setStatus(id string, s serverStatus) {
	statusCacheMu.Lock()
	defer statusCacheMu.Unlock()
	statusCache[id] = s
}

// ─── inbound endpoints ───────────────────────────────────────────────────────

// HandleInterlinkPing handles GET /api/interlink/ping — no auth required.
func HandleInterlinkPing(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}
	jsonOK(w, map[string]interface{}{
		"hostname":    hostname,
		"version":     version.Version,
		"lxd_enabled": isLXDAvailable(),
		"ok":          true,
	})
}

// HandleInterlinkAcceptLink handles POST /api/interlink/accept-link — no session auth.
// Validates remote admin credentials, stores link, returns local ID + hostname.
func HandleInterlinkAcceptLink(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.AcceptLinkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.CallerURL == "" || req.SharedSecret == "" || req.AdminUsername == "" {
			jsonErr(w, http.StatusBadRequest, "missing required fields")
			return
		}

		users, err := config.LoadUsers()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load users")
			return
		}
		user := config.FindUserByUsername(users, req.AdminUsername)
		if user == nil || user.Role != config.RoleAdmin {
			jsonErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.AdminPassword)); err != nil {
			jsonErr(w, http.StatusUnauthorized, "invalid credentials")
			return
		}

		// If TOTP is enabled on the admin account, require the code.
		if user.TOTPEnabled {
			if req.AdminTOTP == "" {
				jsonOK(w, system.AcceptLinkResponse{TOTPNeeded: true})
				return
			}
			if !totp.Verify(user.TOTPSecret, req.AdminTOTP) {
				jsonErr(w, http.StatusUnauthorized, "invalid 2FA code")
				return
			}
		}

		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "localhost"
		}

		// Serialize the whole check-and-append under interlinkMu. Cluster
		// propagation fires several accept-link requests at once; without
		// this lock two of them could both pass the "already linked?" check
		// below before either appends, writing the same peer twice (the
		// "listed twice" duplicate).
		interlinkMu.Lock()

		// Idempotent: if already linked by this caller URL, return the existing IDs.
		// Still hand back the existing peers list (v6.5.42) so a repeat link
		// from a fresh admin who didn't ride out the original cluster
		// propagation can finish the job — also why ExistingPeers is
		// computed BEFORE the new-link branch appends `req.CallerURL`,
		// so the caller never sees itself in its own propagation list.
		for _, ls := range appCfg.InterLink {
			if normalizeInterlinkURL(ls.URL) == normalizeInterlinkURL(req.CallerURL) {
				resp := system.AcceptLinkResponse{
					RemoteID:      ls.ID,
					Hostname:      hostname,
					ExistingPeers: buildInterlinkPeerList(appCfg, req.CallerURL),
				}
				interlinkMu.Unlock()
				jsonOK(w, resp)
				return
			}
		}

		// Snapshot the peer list BEFORE appending the new caller — we don't
		// want the caller to receive itself in ExistingPeers and recursively
		// link to itself. Slice copy is cheap (just URL+Hostname strings).
		existingPeers := buildInterlinkPeerList(appCfg, req.CallerURL)

		localID := newID()
		appCfg.InterLink = append(appCfg.InterLink, config.LinkedServer{
			ID:           localID,
			URL:          req.CallerURL,
			Hostname:     req.CallerHostname,
			SharedSecret: req.SharedSecret,
			RemoteID:     req.CallerID,
			LinkedBy:     req.AdminUsername,
			LinkedAt:     time.Now(),
		})
		if err := config.SaveAppConfig(appCfg); err != nil {
			interlinkMu.Unlock()
			jsonErr(w, http.StatusInternalServerError, "failed to save config")
			return
		}
		interlinkMu.Unlock()
		alerts.ReconcileLinkedServerSubscribers(appCfg)

		audit.Log(audit.Entry{
			User:    req.AdminUsername,
			Role:    config.RoleAdmin,
			Action:  audit.ActionInterlinkAccepted,
			Target:  req.CallerHostname,
			Result:  audit.ResultOK,
			Details: "InterLink accepted from " + req.CallerURL,
		})

		// Ensure our local user has ZFS access, then push our SSH key back to the caller.
		// Capture the caller's TLS fingerprint (TOFU) and store it for future pinning.
		callerURL, callerSecret, callerLSID := req.CallerURL, req.SharedSecret, localID
		go func() {
			// TOFU: capture and pin the caller's certificate on first outbound contact.
			callerFP := system.CaptureTLSFingerprint(callerURL)
			if callerFP != "" {
				interlinkMu.Lock()
				for i := range appCfg.InterLink {
					if appCfg.InterLink[i].ID == callerLSID {
						appCfg.InterLink[i].TLSFingerprint = callerFP
						config.SaveAppConfig(appCfg) //nolint:errcheck
						break
					}
				}
				interlinkMu.Unlock()
				alerts.ReconcileLinkedServerSubscribers(appCfg)
			}
			if err := system.GrantLocalZFSAccess(); err != nil {
				log.Printf("interlink accept-link: zfs allow failed: %v", err)
			}
			pubKey, err := system.EnsureSSHKey()
			if err != nil {
				log.Printf("interlink accept-link: SSH key setup failed: %v", err)
				return
			}
			if err := system.SendPushSSHKey(callerURL, callerSecret, pubKey, callerFP); err != nil {
				log.Printf("interlink accept-link: push SSH key to %s failed: %v", callerURL, err)
			}
		}()

		jsonOK(w, system.AcceptLinkResponse{
			RemoteID:      localID,
			Hostname:      hostname,
			ExistingPeers: existingPeers,
		})
	}
}

// buildInterlinkPeerList returns the local InterLink config as a list of
// (URL, Hostname) pairs, excluding any entry whose URL matches the given
// excludeURL. Used by HandleInterlinkAcceptLink to populate the
// ExistingPeers field of AcceptLinkResponse so the caller can propagate
// the link to every member of the existing cluster in one shot.
//
// Returns nil (not an empty slice) when there are no peers to share —
// keeps the JSON output clean via omitempty on AcceptLinkResponse.
func buildInterlinkPeerList(appCfg *config.AppConfig, excludeURL string) []system.LinkedPeer {
	if appCfg == nil || len(appCfg.InterLink) == 0 {
		return nil
	}
	out := make([]system.LinkedPeer, 0, len(appCfg.InterLink))
	for _, ls := range appCfg.InterLink {
		if ls.URL == excludeURL {
			continue
		}
		out = append(out, system.LinkedPeer{URL: ls.URL, Hostname: ls.Hostname})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// normalizeInterlinkURL returns a comparison key for a linked-server URL: the
// lowercased host[:port], so links that reach the same peer collapse together
// regardless of scheme casing or a trailing slash. Falls back to the trimmed
// raw string when the URL can't be parsed.
func normalizeInterlinkURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimRight(strings.TrimSpace(raw), "/"))
	}
	return strings.ToLower(u.Host)
}

// interlinkCompleteness scores a LinkedServer so dedupeInterLink keeps the
// richest of several duplicates — the entry that actually works for SSO /
// relay / LXD is the one carrying a pinned fingerprint, a remote ID, and LXD
// trust.
func interlinkCompleteness(ls config.LinkedServer) int {
	n := 0
	if ls.TLSFingerprint != "" {
		n++
	}
	if ls.RemoteID != "" {
		n++
	}
	if ls.LXDTrusted {
		n++
	}
	return n
}

// dedupeInterLink collapses linked-server entries that point at the same peer
// (same normalized URL host). Duplicates arise from the concurrent-append race
// in accept-link during cluster propagation; besides cluttering the list they
// double the ping work behind the "Manage InterLink" screen. Keeps the most
// complete entry (see interlinkCompleteness); ties break toward the newer link.
// Returns true when it changed appCfg.InterLink. Caller holds interlinkMu.
func dedupeInterLink(appCfg *config.AppConfig) bool {
	if appCfg == nil || len(appCfg.InterLink) < 2 {
		return false
	}
	seen := map[string]int{} // normalized URL -> index into kept
	kept := make([]config.LinkedServer, 0, len(appCfg.InterLink))
	changed := false
	for _, ls := range appCfg.InterLink {
		key := normalizeInterlinkURL(ls.URL)
		if idx, ok := seen[key]; ok {
			changed = true
			cur := kept[idx]
			if interlinkCompleteness(ls) > interlinkCompleteness(cur) ||
				(interlinkCompleteness(ls) == interlinkCompleteness(cur) && ls.LinkedAt.After(cur.LinkedAt)) {
				kept[idx] = ls
			}
			continue
		}
		seen[key] = len(kept)
		kept = append(kept, ls)
	}
	if changed {
		appCfg.InterLink = kept
	}
	return changed
}

// dedupeAndPersistInterLink removes duplicate linked-server entries and, if any
// were removed, persists the cleaned list. Called at the top of the list
// handlers so a config that already picked up a duplicate self-heals on the
// next "Manage InterLink" open — no manual editing required.
func dedupeAndPersistInterLink(appCfg *config.AppConfig) {
	interlinkMu.Lock()
	changed := dedupeInterLink(appCfg)
	if changed {
		if err := config.SaveAppConfig(appCfg); err != nil {
			log.Printf("interlink: dedupe save failed: %v", err)
		}
	}
	interlinkMu.Unlock()
	if changed {
		alerts.ReconcileLinkedServerSubscribers(appCfg)
	}
}

// HandleInterlinkCheckUser handles POST /api/interlink/check-user — HMAC-authenticated.
// Returns whether the requested username exists as a non-SMB-only user locally.
func HandleInterlinkCheckUser(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.CheckUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Reject stale requests (±30 s window).
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}

		// Find the LinkedServer whose shared secret validates the HMAC.
		var matched bool
		for _, ls := range appCfg.InterLink {
			expected := system.CheckUserHMAC(ls.SharedSecret, req.Username, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}

		users, _ := config.LoadUsers()
		user := config.FindUserByUsername(users, req.Username)
		exists := user != nil && user.Role != config.RoleSMBOnly

		jsonOK(w, system.CheckUserResponse{Exists: exists})
	}
}

// HandleInterlinkLogin handles GET /interlink-login — no session auth.
// Validates SSO token and creates a session for the user.
func HandleInterlinkLogin(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		serverID := r.URL.Query().Get("server_id")

		// Find the link by our local ID.
		var ls *config.LinkedServer
		for i := range appCfg.InterLink {
			if appCfg.InterLink[i].ID == serverID {
				ls = &appCfg.InterLink[i]
				break
			}
		}
		if ls == nil {
			http.Redirect(w, r, "/login?reason=link_unknown", http.StatusSeeOther)
			return
		}

		username, err := interlink.ValidateToken(ls.SharedSecret, token)
		if err != nil {
			http.Redirect(w, r, "/login?reason=link_expired", http.StatusSeeOther)
			return
		}

		users, _ := config.LoadUsers()
		user := config.FindUserByUsername(users, username)
		if user == nil || user.Role == config.RoleSMBOnly {
			// User doesn't exist locally — show normal login.
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		hardCap, idle := sessionDurationsFor(appCfg.WebSession)
		sess, err := session.Default.Create(user.ID, user.Username, user.Role, hardCap, idle)
		if err != nil {
			http.Redirect(w, r, "/login?reason=session_error", http.StatusSeeOther)
			return
		}

		audit.Log(audit.Entry{
			User:    user.Username,
			Role:    user.Role,
			Action:  audit.ActionLogin,
			Result:  audit.ResultOK,
			Details: "InterLink switch from " + ls.Hostname,
		})

		SetSessionCookie(w, sess.Token, hardCap)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// ─── outbound endpoints (called by local portal UI) ──────────────────────────

// HandleInterlinkListFast handles GET /api/interlink/servers/fast
// Returns server config immediately with last-cached online/lxd_enabled status (no live ping).
func HandleInterlinkListFast(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dedupeAndPersistInterLink(appCfg)
		type serverOut struct {
			ID         string `json:"id"`
			URL        string `json:"url"`
			Hostname   string `json:"hostname"`
			Online     bool   `json:"online"`
			LXDEnabled bool   `json:"lxd_enabled"`
		}
		out := make([]serverOut, 0, len(appCfg.InterLink))
		for _, ls := range appCfg.InterLink {
			s, _ := cachedStatus(ls.ID)
			// Prefer the cache's live hostname over the stored config
			// value (v6.5.43). The stored value is frozen at link time
			// and goes stale when a peer is renamed; the cache holds
			// whatever PingServer reported in the last 30 s. The /list
			// endpoint also persists fresh values back to config, so
			// this fallback path stays correct on a cold start too.
			hostname := ls.Hostname
			if s.Hostname != "" {
				hostname = s.Hostname
			}
			out = append(out, serverOut{
				ID:         ls.ID,
				URL:        ls.URL,
				Hostname:   hostname,
				Online:     s.Online,
				LXDEnabled: s.LXDEnabled,
			})
		}
		jsonOK(w, out)
	}
}

// HandleInterlinkList handles GET /api/interlink/servers
// Returns all linked servers with cached online status and ZFS access check.
func HandleInterlinkList(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dedupeAndPersistInterLink(appCfg)
		type serverOut struct {
			ID            string    `json:"id"`
			URL           string    `json:"url"`
			Hostname      string    `json:"hostname"`
			LinkedBy      string    `json:"linked_by"`
			LinkedAt      time.Time `json:"linked_at"`
			Online        bool      `json:"online"`
			RemoteVersion string    `json:"remote_version,omitempty"`
			ZFSAccess     bool      `json:"zfs_access"`
			LXDEnabled    bool      `json:"lxd_enabled"`
		}

		type result struct {
			id         string
			online     bool
			ver        string
			zfsAccess  bool
			lxdEnabled bool
			// hostname (v6.5.43): the peer's CURRENT system hostname,
			// captured from the live ping. Empty when status came from
			// the in-memory cache without a hostname recorded (e.g.
			// statuses set via SetStatus elsewhere that don't fill the
			// field). Caller uses this to override the stale config
			// value when present.
			hostname string
		}
		ch := make(chan result, len(appCfg.InterLink))
		for _, ls := range appCfg.InterLink {
			ls := ls
			go func() {
				if s, ok := cachedStatus(ls.ID); ok {
					zfsAccess, _ := system.GetRemoteZFSAccess(ls.URL, ls.SharedSecret, ls.TLSFingerprint)
					ch <- result{ls.ID, s.Online, s.RemoteVersion, zfsAccess, s.LXDEnabled, s.Hostname}
					return
				}
				h, v, err := system.PingServer(ls.URL, ls.TLSFingerprint)
				online := err == nil && h != ""
				lxdEnabled := system.RemotePingHasLXD(ls.URL, ls.TLSFingerprint)
				setStatus(ls.ID, serverStatus{Online: online, RemoteVersion: v, LXDEnabled: lxdEnabled, FetchedAt: time.Now(), Hostname: h})
				zfsAccess, _ := system.GetRemoteZFSAccess(ls.URL, ls.SharedSecret, ls.TLSFingerprint)
				ch <- result{ls.ID, online, v, zfsAccess, lxdEnabled, h}
			}()
		}

		// Collect results, but never block longer than interlinkListMaxWait:
		// one unreachable peer must not hang the whole "Manage InterLink"
		// screen. The channel is buffered to len(InterLink), so goroutines
		// still in flight after the deadline can finish and warm the status
		// cache for next time without leaking.
		statusMap := make(map[string]result, len(appCfg.InterLink))
		timeout := time.After(interlinkListMaxWait)
	collect:
		for range appCfg.InterLink {
			select {
			case res := <-ch:
				statusMap[res.id] = res
			case <-timeout:
				break collect
			}
		}
		// Any peer that didn't answer in time: fall back to its last-known
		// cached status, or mark it offline if we've never reached it.
		for _, ls := range appCfg.InterLink {
			if _, ok := statusMap[ls.ID]; ok {
				continue
			}
			if s, ok := cachedStatus(ls.ID); ok {
				statusMap[ls.ID] = result{
					id: ls.ID, online: s.Online, ver: s.RemoteVersion,
					lxdEnabled: s.LXDEnabled, hostname: s.Hostname,
				}
			} else {
				statusMap[ls.ID] = result{id: ls.ID}
			}
		}

		// Persist any hostname drift back to config (v6.5.43). A peer
		// renamed after linking will return a fresh hostname from
		// PingServer; we want every subsequent call (including the
		// /fast endpoint that doesn't ping) to serve the new name.
		// One SaveAppConfig at the end batches every change in one
		// fsync — cheaper than per-peer saves, and avoids the half-
		// applied-state risk if one save errors mid-loop.
		anyChanged := false
		for i := range appCfg.InterLink {
			s := statusMap[appCfg.InterLink[i].ID]
			if s.hostname != "" && s.hostname != appCfg.InterLink[i].Hostname {
				appCfg.InterLink[i].Hostname = s.hostname
				anyChanged = true
			}
		}
		if anyChanged {
			if err := config.SaveAppConfig(appCfg); err != nil {
				log.Printf("interlink: persist refreshed hostnames: %v", err)
			}
		}

		out := make([]serverOut, 0, len(appCfg.InterLink))
		for _, ls := range appCfg.InterLink {
			s := statusMap[ls.ID]
			// Use the live hostname when we have one; fall back to the
			// (now-possibly-refreshed) stored value otherwise.
			hostname := ls.Hostname
			if s.hostname != "" {
				hostname = s.hostname
			}
			out = append(out, serverOut{
				ID:            ls.ID,
				URL:           ls.URL,
				Hostname:      hostname,
				LinkedBy:      ls.LinkedBy,
				LinkedAt:      ls.LinkedAt,
				Online:        s.online,
				RemoteVersion: s.ver,
				ZFSAccess:     s.zfsAccess,
				LXDEnabled:    s.lxdEnabled,
			})
		}
		jsonOK(w, out)
	}
}

// HandleInterlinkLink handles POST /api/interlink/link (admin only)
func HandleInterlinkLink(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)

		var req struct {
			URL      string `json:"url"`
			Username string `json:"username"`
			Password string `json:"password"`
			TOTP     string `json:"totp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		if req.URL == "" || req.Username == "" || req.Password == "" {
			jsonErr(w, http.StatusBadRequest, "url, username, and password are required")
			return
		}

		// Deduplicate.
		for _, ls := range appCfg.InterLink {
			if ls.URL == req.URL {
				jsonErr(w, http.StatusConflict, "server already linked")
				return
			}
		}

		// Verify reachability, get hostname, and capture TLS fingerprint (TOFU pin).
		remoteHostname, _, err := system.PingServer(req.URL, "")
		if err != nil {
			jsonErr(w, http.StatusServiceUnavailable, "cannot reach remote server: "+err.Error())
			return
		}
		remoteFP := system.CaptureTLSFingerprint(req.URL)

		localHostname, _ := os.Hostname()
		if localHostname == "" {
			localHostname = "localhost"
		}

		localID := newID()
		secret := system.GenerateSharedSecret()

		resp, err := system.SendAcceptLink(req.URL, remoteFP, system.AcceptLinkRequest{
			CallerURL:      localURL(r, appCfg),
			CallerHostname: localHostname,
			CallerID:       localID,
			SharedSecret:   secret,
			AdminUsername:  req.Username,
			AdminPassword:  req.Password,
			AdminTOTP:      req.TOTP,
		})
		if err != nil {
			jsonErr(w, http.StatusBadGateway, err.Error())
			return
		}
		if resp.TOTPNeeded {
			jsonOK(w, map[string]bool{"totp_needed": true})
			return
		}

		ls := config.LinkedServer{
			ID:             localID,
			URL:            req.URL,
			Hostname:       remoteHostname,
			SharedSecret:   secret,
			RemoteID:       resp.RemoteID,
			LinkedBy:       sess.Username,
			LinkedAt:       time.Now(),
			TLSFingerprint: remoteFP,
		}
		appCfg.InterLink = append(appCfg.InterLink, ls)
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save config")
			return
		}
		alerts.ReconcileLinkedServerSubscribers(appCfg)
		setStatus(ls.ID, serverStatus{Online: true, RemoteVersion: "", FetchedAt: time.Now()})

		// Ensure our local user has ZFS access, then push our SSH key to the remote.
		// The remote's accept-link handler will reciprocate and push its key back to us.
		if err := system.GrantLocalZFSAccess(); err != nil {
			log.Printf("interlink link: zfs allow failed: %v", err)
		}
		if pubKey, err := system.EnsureSSHKey(); err == nil {
			if err := system.SendPushSSHKey(ls.URL, ls.SharedSecret, pubKey, ls.TLSFingerprint); err != nil {
				log.Printf("interlink link: push SSH key to %s failed: %v", ls.URL, err)
			}
		} else {
			log.Printf("interlink link: SSH key setup failed: %v", err)
		}

		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionInterlinkLinked,
			Target:  remoteHostname,
			Result:  audit.ResultOK,
			Details: "linked " + req.URL,
		})

		// Cluster propagation (v6.5.42): if the just-linked peer already
		// belongs to a cluster (B knew {C, D, …}), iterate B's existing
		// peer list and link with each using the same admin credentials.
		// Best-effort — a per-peer failure (creds rejected, peer offline,
		// TOTP required on that peer's admin account, …) is logged and
		// surfaced in the response, but doesn't roll back the primary
		// A↔B link that already succeeded.
		propagation := propagateInterlink(r, appCfg, sess, req.Username, req.Password, req.TOTP, resp.ExistingPeers)

		jsonOK(w, map[string]interface{}{
			"ok":            true,
			"linked_server": ls,
			// propagation.summary lets the modal show "Also linked to
			// hostX, hostY (1 failed: hostZ — invalid credentials)".
			// Empty array when the remote had no other peers.
			"cluster_propagation": propagation,
		})
	}
}

// interlinkPropagationResult is what HandleInterlinkLink returns in its
// "cluster_propagation" field. The frontend uses Linked/Skipped/Failed
// counts to render a partial-success badge and Details for the per-peer
// breakdown in the result modal.
type interlinkPropagationResult struct {
	Linked  []string                       `json:"linked"`  // hostnames that joined successfully
	Skipped []string                       `json:"skipped"` // hostnames already linked locally before propagation
	Failed  []interlinkPropagationFailure  `json:"failed"`  // hostnames that refused (creds, TOTP, offline, …)
}

type interlinkPropagationFailure struct {
	URL      string `json:"url"`
	Hostname string `json:"hostname"`
	Reason   string `json:"reason"`
}

// propagateInterlink iterates the peers returned by the just-linked
// server's accept-link response and runs the standard accept-link flow
// against each, using the same admin credentials supplied for the
// original link. Mirrors the body of HandleInterlinkLink's main link
// path: ping → capture FP → SendAcceptLink → append to local config →
// push SSH key. Side-effects on appCfg.InterLink are persisted with a
// single SaveAppConfig at the end so callers see the final state.
//
// Takes *http.Request so we can reuse the existing localURL(r, appCfg)
// helper — that one prefers r.Host (the URL the admin actually typed
// in their browser) over a hostname-based fallback, which matters when
// the server sits behind a reverse proxy or uses a non-default name.
func propagateInterlink(r *http.Request, appCfg *config.AppConfig, sess *session.Session, adminUser, adminPass, adminTOTP string, peers []system.LinkedPeer) interlinkPropagationResult {
	result := interlinkPropagationResult{
		Linked:  []string{},
		Skipped: []string{},
		Failed:  []interlinkPropagationFailure{},
	}
	if len(peers) == 0 {
		return result
	}

	localHostname, _ := os.Hostname()
	if localHostname == "" {
		localHostname = "localhost"
	}

	for _, peer := range peers {
		// Skip self defensively: a misconfigured remote could conceivably
		// include the caller's own URL in its peer list. SendAcceptLink to
		// ourselves would hit our own accept-link handler under our own
		// session and create a self-loop. Hard to trigger but worth a
		// guard.
		if isLocalInterlinkURL(peer.URL, appCfg) {
			continue
		}

		// Already linked? Skip — the operation is idempotent and there's
		// nothing to do. This handles the common "user adds the same
		// cluster twice" case without producing fake "Failed: already
		// linked" entries.
		alreadyLinked := false
		for _, ls := range appCfg.InterLink {
			if ls.URL == peer.URL {
				alreadyLinked = true
				break
			}
		}
		if alreadyLinked {
			result.Skipped = append(result.Skipped, peer.Hostname)
			continue
		}

		// Reachability + TOFU fingerprint capture, same as the manual
		// flow above. If we can't even ping, record the failure with the
		// connection error and move on.
		remoteHostname, _, err := system.PingServer(peer.URL, "")
		if err != nil {
			log.Printf("interlink propagate: ping %s failed: %v", peer.URL, err)
			result.Failed = append(result.Failed, interlinkPropagationFailure{
				URL: peer.URL, Hostname: peer.Hostname, Reason: "unreachable: " + err.Error(),
			})
			continue
		}
		remoteFP := system.CaptureTLSFingerprint(peer.URL)

		localID := newID()
		secret := system.GenerateSharedSecret()

		// Use the same caller-URL synthesis as the manual flow so peers
		// see consistent identity regardless of whether the admin reached
		// us via hostname, IP, or proxy. r.Host wins when set.
		callerURL := localURL(r, appCfg)

		resp, err := system.SendAcceptLink(peer.URL, remoteFP, system.AcceptLinkRequest{
			CallerURL:      callerURL,
			CallerHostname: localHostname,
			CallerID:       localID,
			SharedSecret:   secret,
			AdminUsername:  adminUser,
			AdminPassword:  adminPass,
			AdminTOTP:      adminTOTP, // single TOTP is consumed by B; reused here only because per-peer TOTP isn't typed
		})
		if err != nil {
			log.Printf("interlink propagate: accept-link %s failed: %v", peer.URL, err)
			result.Failed = append(result.Failed, interlinkPropagationFailure{
				URL: peer.URL, Hostname: peer.Hostname, Reason: err.Error(),
			})
			continue
		}
		if resp.TOTPNeeded {
			// Per-peer TOTP would need its own code — we have only one in
			// hand (just consumed by the primary target). Report it as a
			// distinct failure so the UI can guide the user to add this
			// peer manually with its own TOTP.
			result.Failed = append(result.Failed, interlinkPropagationFailure{
				URL: peer.URL, Hostname: peer.Hostname, Reason: "remote admin requires a fresh 2FA code — link this peer manually",
			})
			continue
		}

		ls := config.LinkedServer{
			ID:             localID,
			URL:            peer.URL,
			Hostname:       remoteHostname,
			SharedSecret:   secret,
			RemoteID:       resp.RemoteID,
			LinkedBy:       sess.Username,
			LinkedAt:       time.Now(),
			TLSFingerprint: remoteFP,
		}
		appCfg.InterLink = append(appCfg.InterLink, ls)
		setStatus(ls.ID, serverStatus{Online: true, RemoteVersion: "", FetchedAt: time.Now()})

		// Best-effort SSH key push, same as the manual flow.
		if pubKey, err := system.EnsureSSHKey(); err == nil {
			if err := system.SendPushSSHKey(ls.URL, ls.SharedSecret, pubKey, ls.TLSFingerprint); err != nil {
				log.Printf("interlink propagate: push SSH key to %s failed: %v", ls.URL, err)
			}
		}

		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionInterlinkLinked,
			Target:  remoteHostname,
			Result:  audit.ResultOK,
			Details: "auto-linked via cluster propagation (peer of " + peer.Hostname + ")",
		})
		result.Linked = append(result.Linked, remoteHostname)
	}

	// One save covers every successful peer addition.
	if len(result.Linked) > 0 {
		if err := config.SaveAppConfig(appCfg); err != nil {
			log.Printf("interlink propagate: SaveAppConfig: %v", err)
		}
		alerts.ReconcileLinkedServerSubscribers(appCfg)
	}
	return result
}

// isLocalInterlinkURL returns true if the given URL points back at this
// server. Best-effort check used to keep the propagation loop from
// linking the caller to itself when a misbehaving remote includes the
// caller in its own peer list. The accept-link handler already strips
// the caller from ExistingPeers, but a paranoid second check costs
// almost nothing and protects against future regressions / a remote on
// an older binary.
func isLocalInterlinkURL(url string, appCfg *config.AppConfig) bool {
	if url == "" {
		return false
	}
	host, _ := os.Hostname()
	port := 8443
	if appCfg != nil && appCfg.Port != 0 {
		port = appCfg.Port
	}
	candidates := []string{
		fmt.Sprintf("https://%s:%d", host, port),
		fmt.Sprintf("https://localhost:%d", port),
		fmt.Sprintf("https://127.0.0.1:%d", port),
	}
	for _, c := range candidates {
		if url == c {
			return true
		}
	}
	return false
}

// HandleInterlinkUnlink handles DELETE /api/interlink/{id} (admin only).
// After removing locally it also notifies the remote server to remove us (best-effort).
func HandleInterlinkUnlink(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		id := mux.Vars(r)["id"]

		var removed *config.LinkedServer
		kept := make([]config.LinkedServer, 0, len(appCfg.InterLink))
		for _, ls := range appCfg.InterLink {
			if ls.ID == id {
				lsCopy := ls
				removed = &lsCopy
			} else {
				kept = append(kept, ls)
			}
		}
		if removed == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		appCfg.InterLink = kept
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save config")
			return
		}
		alerts.ReconcileLinkedServerSubscribers(appCfg)

		statusCacheMu.Lock()
		delete(statusCache, id)
		statusCacheMu.Unlock()

		// Best-effort: tell the remote to remove us from its list too.
		if removed.RemoteID != "" {
			go system.SendRemoteUnlink(removed.URL, removed.SharedSecret, removed.RemoteID, removed.TLSFingerprint) //nolint:errcheck
		}

		audit.Log(audit.Entry{
			User:    sess.Username,
			Role:    sess.Role,
			Action:  audit.ActionInterlinkUnlinked,
			Target:  removed.Hostname,
			Result:  audit.ResultOK,
			Details: "unlinked " + removed.URL,
		})

		jsonOK(w, map[string]string{"message": "unlinked"})
	}
}

// HandleInterlinkRemotePools handles POST /api/interlink/remote-pools — no session auth.
// HMAC-authenticated by a peer; returns this server's pool names and process user.
func HandleInterlinkRemotePools(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.RemotePoolsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			if hmac.Equal([]byte(system.RemotePoolsHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		pools, err := system.GetAllPools()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "cannot get pools: "+err.Error())
			return
		}
		rPools := make([]system.RemotePool, 0, len(pools))
		for _, p := range pools {
			rPools = append(rPools, system.RemotePool{
				Name:      p.Name,
				Available: int64(p.UsableAvail),
			})
		}
		jsonOK(w, system.RemotePoolsResponse{
			Pools:       rPools,
			ProcessUser: system.GetProcessUser(),
			// v6.5.19+: advertise our own IPs so a peer's syncoid can
			// reach us directly even when the InterLink URL points at
			// a reverse proxy that doesn't forward SSH.
			SSHHosts: system.LocalSSHHosts(),
			// v6.6.13+: advertise our SSH host keys so the caller can pin
			// them (verified over this authenticated channel) and self-heal
			// after a reinstall/re-key instead of failing on a changed key.
			SSHHostKeys: system.LocalSSHHostKeys(),
		})
	}
}

// HandleInterlinkRemoteFolders handles POST /api/interlink/remote-folders — no session auth.
// HMAC-authenticated by a peer; returns the dataset paths (one or more levels deep) under
// the requested pool, with the pool prefix stripped so the caller gets folder names like
// "" (pool root), "DRONE", "backups/nightly".
func HandleInterlinkRemoteFolders(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.RemoteFoldersRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		if req.Pool == "" || strings.ContainsAny(req.Pool, "/ \t\n") {
			jsonErr(w, http.StatusBadRequest, "invalid pool name")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			if hmac.Equal([]byte(system.RemoteFoldersHMAC(ls.SharedSecret, req.Pool, req.Timestamp, req.Nonce)), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		dsList, err := system.ListDatasets(req.Pool)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "cannot list datasets: "+err.Error())
			return
		}
		folders := make([]string, 0, len(dsList))
		prefix := req.Pool + "/"
		for _, d := range dsList {
			if d.Name == req.Pool {
				continue
			}
			if strings.HasPrefix(d.Name, prefix) {
				folders = append(folders, strings.TrimPrefix(d.Name, prefix))
			}
		}
		jsonOK(w, system.RemoteFoldersResponse{Folders: folders})
	}
}

// HandleInterlinkPushSSHKey handles POST /api/interlink/push-ssh-key — no session auth.
// HMAC-authenticated by a peer; adds the caller's SSH public key to authorized_keys
// and grants the caller's process user ZFS interlink permissions on all local pools.
func HandleInterlinkPushSSHKey(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.PushSSHKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			if hmac.Equal([]byte(system.PushSSHKeyHMAC(ls.SharedSecret, req.PublicKey, req.ProcessUser, req.Timestamp, req.Nonce)), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if err := system.AddSSHAuthorizedKey(req.PublicKey); err != nil {
			jsonErr(w, http.StatusInternalServerError, "cannot add SSH key: "+err.Error())
			return
		}
		// Grant ZFS permissions to our own process user so that when the remote
		// SSHes in as us and runs "sudo zfs recv", the delegated permissions are set.
		if err := system.GrantLocalZFSAccess(); err != nil {
			log.Printf("interlink push-ssh-key: zfs allow failed: %v", err)
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkGrantZFSAccess handles POST /api/interlink/grant-zfs-access — no session auth.
// HMAC-authenticated by a peer; runs zfs allow on all local pools so newly-created pools
// are covered even if they didn't exist when the InterLink was first established.
func HandleInterlinkGrantZFSAccess(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.CheckZFSAccessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			if hmac.Equal([]byte(system.GrantZFSAccessHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		if err := system.GrantLocalZFSAccess(); err != nil {
			jsonErr(w, http.StatusInternalServerError, "zfs allow failed: "+err.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkCheckZFSAccess handles POST /api/interlink/check-zfs-access — no session auth.
// HMAC-authenticated by a peer; reports whether the given process user has the required
// ZFS permissions on at least one local pool.
func HandleInterlinkCheckZFSAccess(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.CheckZFSAccessRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		var matched bool
		for _, ls := range appCfg.InterLink {
			if hmac.Equal([]byte(system.CheckZFSAccessHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		jsonOK(w, map[string]bool{"has_access": system.CheckLocalZFSAccess()})
	}
}

// HandleInterlinkRemoteUnlink handles POST /api/interlink/remote-unlink — no session auth.
// Called by a peer when it unlinks us; removes the matching entry from our list.
func HandleInterlinkRemoteUnlink(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.RemoteUnlinkRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		// Reject stale requests (±30 s window).
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}

		// Find the LinkedServer whose ID matches and whose secret validates the HMAC.
		var matched *config.LinkedServer
		for i := range appCfg.InterLink {
			ls := &appCfg.InterLink[i]
			if ls.ID != req.RemoteID {
				continue
			}
			expected := system.RemoteUnlinkHMAC(ls.SharedSecret, req.RemoteID, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = ls
				break
			}
		}
		if matched == nil {
			// Return 200 anyway — idempotent, don't leak info.
			jsonOK(w, map[string]string{"message": "ok"})
			return
		}

		kept := make([]config.LinkedServer, 0, len(appCfg.InterLink)-1)
		for _, ls := range appCfg.InterLink {
			if ls.ID != matched.ID {
				kept = append(kept, ls)
			}
		}
		appCfg.InterLink = kept
		config.SaveAppConfig(appCfg) //nolint:errcheck
		alerts.ReconcileLinkedServerSubscribers(appCfg)

		statusCacheMu.Lock()
		delete(statusCache, matched.ID)
		statusCacheMu.Unlock()

		audit.Log(audit.Entry{
			User:    "system",
			Role:    config.RoleAdmin,
			Action:  audit.ActionInterlinkUnlinked,
			Target:  matched.Hostname,
			Result:  audit.ResultOK,
			Details: "remote-initiated unlink from " + matched.URL,
		})

		jsonOK(w, map[string]string{"message": "ok"})
	}
}

// HandleInterlinkSwitch handles POST /api/interlink/switch
// Accepts an optional "mode" field: "direct" (default, existing redirect behaviour)
// or "relay" (stay on this portal, proxy API calls to the remote).
func HandleInterlinkSwitch(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)

		var req struct {
			ServerID string `json:"server_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}

		var ls *config.LinkedServer
		for i := range appCfg.InterLink {
			if appCfg.InterLink[i].ID == req.ServerID {
				ls = &appCfg.InterLink[i]
				break
			}
		}
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}

		checkResp, err := system.CheckUserOnRemote(ls.URL, ls.SharedSecret, sess.Username, ls.TLSFingerprint)
		if err != nil || !checkResp.Exists {
			jsonOK(w, map[string]interface{}{
				"user_exists":  false,
				"redirect_url": "",
			})
			return
		}

		// Use relay if global relay mode is enabled.
		useRelay := appCfg.InterlinkRelayMode

		if useRelay {
			// Relay mode: store relay state on the session, return relay:true.
			cookie, cookieErr := r.Cookie("zfsnas_session")
			if cookieErr != nil {
				jsonErr(w, http.StatusUnauthorized, "no session cookie")
				return
			}
			session.SetRelay(cookie.Value, &session.RelayState{
				ServerID: ls.ID,
				Hostname: ls.Hostname,
			})
			jsonOK(w, map[string]interface{}{
				"user_exists": true,
				"relay":       true,
				"hostname":    ls.Hostname,
				"relay_url":   ls.URL,
			})
			return
		}

		// Default: direct mode — generate SSO token and return redirect URL.
		token := interlink.GenerateToken(ls.SharedSecret, sess.Username)
		redirectURL := ls.URL + "/interlink-login?token=" + token + "&server_id=" + ls.RemoteID

		jsonOK(w, map[string]interface{}{
			"user_exists":  true,
			"redirect_url": redirectURL,
		})
	}
}

// HandleInterlinkGetRelayMode handles GET /api/interlink/relay-mode
// Returns the global relay mode setting.
func HandleInterlinkGetRelayMode(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]bool{"relay_mode": appCfg.InterlinkRelayMode})
	}
}

// HandleInterlinkSetRelayMode handles PUT /api/interlink/relay-mode
// Saves the global relay mode preference.
func HandleInterlinkSetRelayMode(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RelayMode bool `json:"relay_mode"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		appCfg.InterlinkRelayMode = req.RelayMode
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save config")
			return
		}
		alerts.ReconcileLinkedServerSubscribers(appCfg)
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkRelayExit handles POST /api/interlink/relay-exit
// Clears the relay state for the current session (exits relay mode).
func HandleInterlinkRelayExit(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("zfsnas_session")
	if err == nil {
		session.ClearRelay(cookie.Value)
	}
	jsonOK(w, map[string]bool{"ok": true})
}

// localURL returns this server's externally-visible base URL for use in link handshakes.
func localURL(r *http.Request, appCfg *config.AppConfig) string {
	if r.Host != "" {
		return "https://" + r.Host
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "localhost"
	}
	return fmt.Sprintf("https://%s:%d", h, appCfg.Port)
}
