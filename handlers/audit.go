package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

// HandleAuditLog returns all audit log entries (local server only).
//
// With ?limit=N (the activity drawer polls this every 10 s, also over slow
// VPN links) it returns only the newest N, still oldest-first, the full count
// in X-Audit-Total, and an ETag: an unchanged log answers 304 without being
// read. The browser's own cache can't be relied on for this (it is off behind
// a self-signed certificate), so the drawer sends If-None-Match itself.
func HandleAuditLog(w http.ResponseWriter, r *http.Request) {
	limit := auditLimit(r)
	if limit > 0 {
		if size, mod, ok := audit.Stamp(); ok {
			etag := fmt.Sprintf(`"a%d-%d-%d"`, size, mod, limit)
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	entries, err := audit.Read()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to read audit log")
		return
	}
	if limit > 0 {
		w.Header().Set("X-Audit-Total", strconv.Itoa(len(entries)))
		if len(entries) > limit {
			entries = entries[len(entries)-limit:]
		}
	}
	jsonOK(w, entries)
}

// auditLimit reads ?limit=; 0 = everything.
func auditLimit(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("limit"))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// HandleAuditByTarget returns audit log entries whose Target field equals or
// contains the given value. Used by the per-instance Logs tab to surface every
// known event tied to a specific VM / container (start, stop, snapshot,
// state-change, OOM kill, etc.). Newest-first; capped via ?limit= (default
// 200). Empty result is fine — caller treats absence as "no events yet".
func HandleAuditByTarget(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	if target == "" {
		jsonErr(w, http.StatusBadRequest, "target query parameter required")
		return
	}
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	all, err := audit.Read()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to read audit log")
		return
	}
	out := make([]audit.Entry, 0, limit)
	// audit.Read returns oldest-first; walk the slice in reverse so the
	// newest matches land at the head and we can short-circuit at `limit`.
	for i := len(all) - 1; i >= 0 && len(out) < limit; i-- {
		e := all[i]
		if entryTargetMatches(e.Target, target) {
			out = append(out, e)
		}
	}
	jsonOK(w, out)
}

// entryTargetMatches accepts an exact match or "name/<sub>" form. Some
// entries store "<vm>/<snapshot>" or "<vm> → <newname>" in Target, so we
// treat any Target that begins with "<name>" followed by "/", " ", or end-
// of-string as belonging to that instance.
func entryTargetMatches(target, name string) bool {
	if target == name {
		return true
	}
	if strings.HasPrefix(target, name+"/") || strings.HasPrefix(target, name+" ") {
		return true
	}
	return false
}

// HandleAuditAggregate returns the local audit log merged with every
// InterLink peer's. Each entry's System field identifies its origin
// (peer hostname for remote entries, local hostname for local ones).
// Entries are returned sorted descending by timestamp so the most recent
// activity across the whole InterLink fleet appears first.
//
// Per-peer fetch failures are silently skipped — the user still gets the
// rest of the data rather than an empty page when one peer is offline.
func HandleAuditAggregate(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all, err := audit.Read()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to read audit log")
			return
		}

		// Fan out to peers in parallel. 5-second per-peer timeout (enforced
		// by the interlinkClientFor http.Client we already use elsewhere).
		var (
			mu sync.Mutex
			wg sync.WaitGroup
		)
		for i := range appCfg.InterLink {
			ls := appCfg.InterLink[i]
			if ls.URL == "" {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				entries, err := system.GetRemoteAudit(ls.URL, ls.SharedSecret, ls.TLSFingerprint)
				if err != nil {
					return
				}
				// Belt-and-suspenders — peer's audit.Read already stamps
				// System, but if a peer were running an older version we
				// still want a hostname rather than blank.
				for j := range entries {
					if entries[j].System == "" {
						entries[j].System = ls.Hostname
					}
				}
				mu.Lock()
				all = append(all, entries...)
				mu.Unlock()
			}()
		}
		wg.Wait()

		// Newest first.
		sort.SliceStable(all, func(i, j int) bool {
			return all[i].Timestamp.After(all[j].Timestamp)
		})

		limit := auditLimit(r)
		if limit == 0 {
			jsonOK(w, all)
			return
		}
		// The peers are always asked, so the answer can only be compared
		// after the merge; the browser still gets 304 when nothing changed.
		w.Header().Set("X-Audit-Total", strconv.Itoa(len(all)))
		if len(all) > limit {
			all = all[:limit]
		}
		body, err := json.Marshal(all)
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to encode audit log")
			return
		}
		sum := sha256.Sum256(body)
		etag := `"m` + hex.EncodeToString(sum[:12]) + `"`
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(body) //nolint:errcheck
	}
}

// HandleAuditPeerList serves a peer's request for the local audit log over
// the InterLink HMAC channel. Mirrors the validation pattern used by
// HandleLXDRemoteStoragePools and friends.
func HandleAuditPeerList(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.InterlinkAuditRequest
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
			expected := system.InterlinkAuditHMAC(ls.SharedSecret, req.Timestamp, req.Nonce)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		entries, err := audit.Read()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "audit read failed")
			return
		}
		jsonOK(w, map[string][]audit.Entry{"entries": entries})
	}
}

// HandleInterlinkMACOwner answers a peer: which instance here has this MAC.
func HandleInterlinkMACOwner(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.InterlinkMACOwnerRequest
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
			expected := system.InterlinkMACOwnerHMAC(ls.SharedSecret, req.Timestamp, req.Nonce, req.MAC)
			if hmac.Equal([]byte(expected), []byte(req.HMAC)) {
				matched = true
				break
			}
		}
		if !matched {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		jsonOK(w, map[string]*system.LXDInstanceOwner{"owner": system.LXDInstanceByMAC(req.MAC)})
	}
}

// sdnOwnerAnswer is what /api/sdn/hostinfo/owner reports.
type sdnOwnerAnswer struct {
	Owner    *system.LXDInstanceOwner `json:"owner,omitempty"`
	Server   string                   `json:"server,omitempty"`
	ServerID string                   `json:"server_id,omitempty"`
	Asked    int                      `json:"asked"`  // peers that answered
	Failed   int                      `json:"failed"` // peers that did not
}

var sdnOwnerCache = struct {
	sync.Mutex
	m map[string]struct {
		at time.Time
		a  sdnOwnerAnswer
	}
}{m: map[string]struct {
	at time.Time
	a  sdnOwnerAnswer
}{}}

// HandleSDNHostOwner — GET /api/sdn/hostinfo/owner?mac=…: asks every InterLink
// peer not known to be offline which instance has this MAC. Separate from the
// card's own request so a slow peer never holds the card up.
func HandleSDNHostOwner(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hw, err := net.ParseMAC(r.URL.Query().Get("mac"))
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "not a MAC address")
			return
		}
		mac := strings.ToLower(hw.String())
		sdnOwnerCache.Lock()
		c, ok := sdnOwnerCache.m[mac]
		sdnOwnerCache.Unlock()
		if ok && time.Since(c.at) < time.Minute {
			jsonOK(w, c.a)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		var (
			mu sync.Mutex
			wg sync.WaitGroup
			a  sdnOwnerAnswer
		)
		for i := range appCfg.InterLink {
			ls := appCfg.InterLink[i]
			if ls.URL == "" {
				continue
			}
			if s, known := cachedStatus(ls.ID); known && !s.Online {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				o, err := system.GetRemoteMACOwner(ctx, ls.URL, ls.SharedSecret, ls.TLSFingerprint, mac)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					a.Failed++
					return
				}
				a.Asked++
				if o != nil && a.Owner == nil {
					a.Owner, a.ServerID, a.Server = o, ls.ID, ls.Hostname
					if s, known := cachedStatus(ls.ID); known && s.Hostname != "" {
						a.Server = s.Hostname
					}
				}
			}()
		}
		wg.Wait()
		sdnOwnerCache.Lock()
		if len(sdnOwnerCache.m) > 1024 {
			sdnOwnerCache.m = map[string]struct {
				at time.Time
				a  sdnOwnerAnswer
			}{}
		}
		sdnOwnerCache.m[mac] = struct {
			at time.Time
			a  sdnOwnerAnswer
		}{time.Now(), a}
		sdnOwnerCache.Unlock()
		jsonOK(w, a)
	}
}
