package handlers

// Health view of Manage InterLink: every link tried with real signed requests,
// and the repairs for what they find.

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/internal/session"
	"zfsnas/internal/totp"
	"zfsnas/system"

	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
)

// interlinkClockSlack: signed requests are accepted 30 s old and 5 s early.
const interlinkClockSlack = 5

// interlinkHealth is one linked server, as seen from here.
type interlinkHealth struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
	URL      string `json:"url"`
	Version  string `json:"version,omitempty"`

	Reach       string `json:"reach"` // ok | unreachable
	ReachDetail string `json:"reach_detail,omitempty"`
	ReachBack   string `json:"reach_back"` // it to us: ok, a reason, unknown
	BackDetail  string `json:"back_detail,omitempty"`
	Secret      string `json:"secret"` // ok | mismatch | unknown
	IDsMatch    *bool  `json:"ids_match,omitempty"`

	Cert    string `json:"cert"` // ok | missing | changed | unknown
	Pinned  string `json:"pinned,omitempty"`
	Live    string `json:"live,omitempty"`
	Clock   *int   `json:"clock_skew,omitempty"`
	ClockOK bool   `json:"clock_ok"`

	Account     string `json:"account"` // exists | missing | unknown
	AccountRole string `json:"account_role,omitempty"`
	ZFSAccess   *bool  `json:"zfs_access,omitempty"`
	IncusTrust  *bool  `json:"incus_trust,omitempty"`

	NeedsUpdate bool                       `json:"needs_update,omitempty"`
	Links       []system.InterlinkLinkTest `json:"links,omitempty"`
	Users       []system.InterlinkUser     `json:"users,omitempty"`
}

func interlinkUsersList() []system.InterlinkUser {
	users, _ := config.LoadUsers()
	out := make([]system.InterlinkUser, 0, len(users))
	for _, u := range users {
		if u.Role != config.RoleSMBOnly {
			out = append(out, system.InterlinkUser{Username: u.Username, Role: u.Role})
		}
	}
	return out
}

// interlinkCheckOne runs every check on one link.
func interlinkCheckOne(ls config.LinkedServer, username string) interlinkHealth {
	h := interlinkHealth{ID: ls.ID, Hostname: ls.Hostname, URL: ls.URL, Reach: "ok", ReachBack: "unknown", Secret: "unknown", Cert: "unknown", Account: "unknown", ClockOK: true}
	p, err := system.ProbeInterlink(ls.URL)
	if err != nil {
		h.Reach, h.ReachDetail = "unreachable", err.Error()
		return h
	}
	h.Version = p.Version
	if p.Hostname != "" {
		h.Hostname = p.Hostname
	}
	skew := p.ClockSkew
	h.Clock = &skew
	h.ClockOK = interlinkClockInRange(skew)

	h.Pinned, h.Live = ls.TLSFingerprint, system.CaptureTLSFingerprint(ls.URL)
	switch {
	case h.Live == "":
	case ls.TLSFingerprint == "":
		h.Cert = "missing"
	case ls.TLSFingerprint == h.Live:
		h.Cert = "ok"
	default:
		// Nothing signed goes to a server that may not be the one we linked.
		h.Cert = "changed"
		return h
	}

	r, err := system.AskPeerHealth(ls.URL, ls.SharedSecret, username, ls.TLSFingerprint, true)
	switch reason := system.ClassifyInterlinkErr(err); {
	case err == nil:
		h.Secret = "ok"
		ids := ls.RemoteID == r.LinkID && r.LinkRemoteID == ls.ID
		h.IDsMatch = &ids
		h.ReachBack, h.BackDetail = r.Back.Status, r.Back.Detail
		h.Account = "missing"
		if r.AccountRole != "" {
			h.Account, h.AccountRole = "exists", r.AccountRole
		}
		h.Links, h.Users = r.Links, r.Users
	case reason == "secret_mismatch":
		h.Secret = "mismatch"
	case reason == "needs_update":
		// Too old to answer: check-user still proves the secret and the account.
		h.NeedsUpdate = true
		if c, err := system.CheckUserOnRemote(ls.URL, ls.SharedSecret, username, ls.TLSFingerprint); err == nil {
			h.Secret, h.Account = "ok", "missing"
			if c.Exists {
				h.Account = "exists"
			}
		} else if system.ClassifyInterlinkErr(err) == "secret_mismatch" {
			h.Secret = "mismatch"
		}
	}
	if h.Secret == "ok" {
		if ok, err := system.GetRemoteZFSAccess(ls.URL, ls.SharedSecret, ls.TLSFingerprint); err == nil {
			h.ZFSAccess = &ok
		}
		if system.RemotePingHasLXD(ls.URL, ls.TLSFingerprint) && isLXDAvailable() {
			t := ls.LXDTrusted
			h.IncusTrust = &t
		}
	}
	return h
}

// interlinkClockInRange: skew is how far the peer is ahead of us. A signed
// request of ours looks old to a peer ahead, and early to a peer behind.
func interlinkClockInRange(skew int) bool {
	return skew < 30-interlinkClockSlack && skew > -interlinkClockSlack
}

// HandleInterlinkHealth — GET /api/interlink/health.
func HandleInterlinkHealth(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		links := append([]config.LinkedServer(nil), appCfg.InterLink...)
		out := make([]interlinkHealth, len(links))
		var wg sync.WaitGroup
		for i := range links {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				out[i] = interlinkCheckOne(links[i], sess.Username)
			}(i)
		}
		wg.Wait()
		hostname, _ := os.Hostname()
		jsonOK(w, map[string]any{"hostname": hostname, "username": sess.Username, "users": interlinkUsersList(), "servers": out})
	}
}

// HandleInterlinkPeerHealth — POST /api/interlink/peer-health, HMAC-signed by a peer.
func HandleInterlinkPeerHealth(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req system.PeerHealthRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		age := time.Since(time.Unix(req.Timestamp, 0))
		if age > 30*time.Second || age < -5*time.Second {
			jsonErr(w, http.StatusUnauthorized, "request timestamp out of range")
			return
		}
		links := append([]config.LinkedServer(nil), appCfg.InterLink...)
		var caller *config.LinkedServer
		for i := range links {
			if hmac.Equal([]byte(system.PeerHealthHMAC(links[i].SharedSecret, req.Username, req.Timestamp, req.Nonce)), []byte(req.HMAC)) {
				caller = &links[i]
				break
			}
		}
		if caller == nil {
			jsonErr(w, http.StatusUnauthorized, "invalid HMAC")
			return
		}
		hostname, _ := os.Hostname()
		resp := system.PeerHealthResponse{Hostname: hostname, LinkID: caller.ID, LinkRemoteID: caller.RemoteID, Users: interlinkUsersList()}
		users, _ := config.LoadUsers()
		if u := config.FindUserByUsername(users, req.Username); u != nil && u.Role != config.RoleSMBOnly {
			resp.AccountRole = u.Role
		}
		tests := make([]system.InterlinkLinkTest, len(links))
		var wg sync.WaitGroup
		for i := range links {
			if !req.Cluster && links[i].ID != caller.ID {
				continue
			}
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				l := links[i]
				tests[i] = system.TestInterlink(l.ID, l.URL, l.Hostname, l.SharedSecret, l.TLSFingerprint)
			}(i)
		}
		wg.Wait()
		for i := range links {
			if links[i].ID == caller.ID {
				resp.Back = tests[i]
			}
			if req.Cluster {
				resp.Links = append(resp.Links, tests[i])
			}
		}
		jsonOK(w, resp)
	}
}

func interlinkByID(appCfg *config.AppConfig, id string) *config.LinkedServer {
	for i := range appCfg.InterLink {
		if appCfg.InterLink[i].ID == id {
			return &appCfg.InterLink[i]
		}
	}
	return nil
}

// HandleInterlinkRepairLink — POST /api/interlink/{id}/repair-link: a new
// secret on both sides, authorised by the remote admin. A wrong secret cannot
// prove anything, so the password is the only way in. The link keeps its ID.
func HandleInterlinkRepairLink(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		ls := interlinkByID(appCfg, mux.Vars(r)["id"])
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			TOTP     string `json:"totp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || req.Password == "" {
			jsonErr(w, http.StatusBadRequest, "username and password are required")
			return
		}
		hostname, _ := os.Hostname()
		secret := system.GenerateSharedSecret()
		resp, err := system.SendAcceptLink(ls.URL, ls.TLSFingerprint, system.AcceptLinkRequest{
			CallerURL:      localURL(r, appCfg),
			CallerHostname: hostname,
			CallerID:       ls.ID,
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
		// A version without the fix answers OK and keeps its old secret.
		if t := system.TestInterlink(ls.ID, ls.URL, ls.Hostname, secret, ls.TLSFingerprint); t.Status == "secret_mismatch" {
			jsonErr(w, http.StatusConflict, ls.Hostname+" kept its old key: update it to this version, then repair again")
			return
		}
		interlinkMu.Lock()
		ls.SharedSecret, ls.RemoteID = secret, resp.RemoteID
		err = config.SaveAppConfig(appCfg)
		interlinkMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save config")
			return
		}
		if pubKey, err := system.EnsureSSHKey(); err == nil {
			if err := system.SendPushSSHKey(ls.URL, ls.SharedSecret, pubKey, ls.TLSFingerprint); err != nil {
				log.Printf("interlink repair: push SSH key to %s failed: %v", ls.URL, err)
			}
		}
		statusCacheMu.Lock()
		delete(statusCache, ls.ID)
		statusCacheMu.Unlock()
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionInterlinkLinked, Target: ls.Hostname, Result: audit.ResultOK, Details: "link key repaired"})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkAcceptCert — POST /api/interlink/{id}/accept-cert: pin the
// certificate the admin was shown. Refused if it changed again meanwhile.
func HandleInterlinkAcceptCert(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		ls := interlinkByID(appCfg, mux.Vars(r)["id"])
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		var req struct {
			Fingerprint string `json:"fingerprint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Fingerprint == "" {
			jsonErr(w, http.StatusBadRequest, "fingerprint is required")
			return
		}
		if live := system.CaptureTLSFingerprint(ls.URL); live != req.Fingerprint {
			jsonErr(w, http.StatusConflict, "the server now presents a different certificate: check again")
			return
		}
		old := ls.TLSFingerprint
		interlinkMu.Lock()
		ls.TLSFingerprint = req.Fingerprint
		err := config.SaveAppConfig(appCfg)
		interlinkMu.Unlock()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save config")
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionInterlinkLinked, Target: ls.Hostname, Result: audit.ResultOK,
			Details: "TLS certificate accepted: " + req.Fingerprint + " (was " + old + ")"})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkRepairAccess — POST /api/interlink/{id}/repair-access: SSH key
// and ZFS permissions again, over the working link.
func HandleInterlinkRepairAccess(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ls := interlinkByID(appCfg, mux.Vars(r)["id"])
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		if err := system.GrantLocalZFSAccess(); err != nil {
			log.Printf("interlink repair: zfs allow failed: %v", err)
		}
		pubKey, err := system.EnsureSSHKey()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "SSH key: "+err.Error())
			return
		}
		if err := system.SendPushSSHKey(ls.URL, ls.SharedSecret, pubKey, ls.TLSFingerprint); err != nil {
			jsonErr(w, http.StatusBadGateway, err.Error())
			return
		}
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkCreateAccount — POST /api/interlink/{id}/create-account: a
// local account on a peer, with the same role, and either this password
// (copy) or a new one. Authorised by the peer's admin.
func HandleInterlinkCreateAccount(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := MustSession(r)
		ls := interlinkByID(appCfg, mux.Vars(r)["id"])
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		var req struct {
			Account      string `json:"account"`
			CopyPassword bool   `json:"copy_password"`
			NewPassword  string `json:"new_password"`
			Username     string `json:"username"`
			Password     string `json:"password"`
			TOTP         string `json:"totp"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Account == "" || req.Username == "" || req.Password == "" {
			jsonErr(w, http.StatusBadRequest, "account, username and password are required")
			return
		}
		users, err := config.LoadUsers()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load users")
			return
		}
		u := config.FindUserByUsername(users, req.Account)
		if u == nil || u.Role == config.RoleSMBOnly {
			jsonErr(w, http.StatusNotFound, "no such account on this server")
			return
		}
		hash := u.PasswordHash
		if !req.CopyPassword {
			if len(req.NewPassword) < 8 {
				jsonErr(w, http.StatusBadRequest, "password must be at least 8 characters")
				return
			}
			b, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
			if err != nil {
				jsonErr(w, http.StatusInternalServerError, "failed to hash password")
				return
			}
			hash = string(b)
		}
		var perms json.RawMessage
		if u.StandardPerms != nil {
			perms, _ = json.Marshal(u.StandardPerms)
		}
		resp, err := system.SendAcceptAccount(ls.URL, ls.TLSFingerprint, system.AcceptAccountRequest{
			AdminUsername: req.Username, AdminPassword: req.Password, AdminTOTP: req.TOTP,
			Username: u.Username, Email: u.Email, Role: u.Role, PasswordHash: hash, StandardPerms: perms,
		})
		if err != nil {
			if system.ClassifyInterlinkErr(err) == "needs_update" {
				jsonErr(w, http.StatusConflict, ls.Hostname+" must be updated to this version first")
				return
			}
			jsonErr(w, http.StatusBadGateway, system.InterlinkErrorMessage(err))
			return
		}
		if resp.TOTPNeeded {
			jsonOK(w, map[string]bool{"totp_needed": true})
			return
		}
		audit.Log(audit.Entry{User: sess.Username, Role: sess.Role, Action: audit.ActionInterlinkLinked, Target: ls.Hostname, Result: audit.ResultOK,
			Details: "account " + u.Username + " created there"})
		jsonOK(w, map[string]bool{"ok": true})
	}
}

// HandleInterlinkAcceptAccount — POST /api/interlink/accept-account, no
// session: the admin's password and 2FA on this server authorise it. It makes
// a portal login only: no Linux, SSH or SMB account.
func HandleInterlinkAcceptAccount(w http.ResponseWriter, r *http.Request) {
	var req system.AcceptAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Role {
	case config.RoleAdmin, config.RoleReadOnly, config.RoleStandard:
	default:
		jsonErr(w, http.StatusBadRequest, "invalid role")
		return
	}
	if req.Username == "" {
		jsonErr(w, http.StatusBadRequest, "username is required")
		return
	}
	if c, err := bcrypt.Cost([]byte(req.PasswordHash)); err != nil || c < bcrypt.DefaultCost {
		jsonErr(w, http.StatusBadRequest, "invalid password hash")
		return
	}
	config.LockUsers()
	defer config.UnlockUsers()
	users, err := config.LoadUsers()
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to load users")
		return
	}
	admin := config.FindUserByUsername(users, req.AdminUsername)
	if admin == nil || admin.Role != config.RoleAdmin || bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(req.AdminPassword)) != nil {
		jsonErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if admin.TOTPEnabled {
		if req.AdminTOTP == "" {
			jsonOK(w, system.AcceptAccountResponse{TOTPNeeded: true})
			return
		}
		if !totp.Verify(admin.TOTPSecret, req.AdminTOTP) {
			jsonErr(w, http.StatusUnauthorized, "invalid 2FA code")
			return
		}
	}
	if config.FindUserByUsername(users, req.Username) != nil {
		jsonErr(w, http.StatusConflict, "username already exists")
		return
	}
	u := config.User{ID: newID(), Username: req.Username, Email: req.Email, PasswordHash: req.PasswordHash, Role: req.Role, CreatedAt: time.Now()}
	if len(req.StandardPerms) > 0 && req.Role == config.RoleStandard {
		var p config.StandardPermissions
		if err := json.Unmarshal(req.StandardPerms, &p); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid permissions")
			return
		}
		u.StandardPerms = &p
	}
	if err := config.SaveUsers(append(users, u)); err != nil {
		jsonErr(w, http.StatusInternalServerError, "failed to save users")
		return
	}
	audit.Log(audit.Entry{User: req.AdminUsername, Role: config.RoleAdmin, Action: audit.ActionCreateUser, Target: req.Username, Result: audit.ResultOK, Details: "created over InterLink, portal login only"})
	jsonOK(w, system.AcceptAccountResponse{OK: true})
}

// interlinkForward runs a POST on a linked server as the signed-in user (as
// relay does), which needs that user to be allowed there.
func interlinkForward(w http.ResponseWriter, sess *session.Session, ls *config.LinkedServer, path string, body []byte) {
	out, err := http.NewRequest(http.MethodPost, ls.URL+path, bytes.NewReader(body))
	if err != nil {
		jsonErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	ts, nonce, sig := relayIdentityHeaders(ls, sess.Username)
	out.Header.Set("Content-Type", "application/json")
	out.Header.Set("X-Interlink-Relay-User", sess.Username)
	out.Header.Set("X-Interlink-Relay-TS", strconv.FormatInt(ts, 10))
	out.Header.Set("X-Interlink-Relay-Nonce", nonce)
	out.Header.Set("X-Interlink-Relay-HMAC", sig)
	resp, err := system.InterlinkClientForRelay(ls.TLSFingerprint).Do(out)
	if err != nil {
		jsonErr(w, http.StatusBadGateway, err.Error())
		return
	}
	defer resp.Body.Close()
	// Its router's own 404, not a JSON answer: it doesn't have this route.
	if resp.StatusCode == http.StatusNotFound && !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		jsonErr(w, http.StatusConflict, ls.Hostname+" must be updated to this version first")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body) //nolint:errcheck
}

// HandleInterlinkLinkPeer — POST /api/interlink/{id}/link-peer: ask a linked
// server to link to another one, for a pair this server is not part of.
func HandleInterlinkLinkPeer(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ls := interlinkByID(appCfg, mux.Vars(r)["id"])
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		interlinkForward(w, MustSession(r), ls, "/api/interlink/link", body)
	}
}

// HandleInterlinkRepairPeer — POST /api/interlink/{id}/repair-peer: repair
// link_id, a link held by that linked server, for a pair this server is not
// part of.
func HandleInterlinkRepairPeer(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ls := interlinkByID(appCfg, mux.Vars(r)["id"])
		if ls == nil {
			jsonErr(w, http.StatusNotFound, "linked server not found")
			return
		}
		var req struct {
			LinkID   string `json:"link_id"`
			Username string `json:"username"`
			Password string `json:"password"`
			TOTP     string `json:"totp"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil || req.LinkID == "" {
			jsonErr(w, http.StatusBadRequest, "link_id is required")
			return
		}
		body, _ := json.Marshal(map[string]string{"username": req.Username, "password": req.Password, "totp": req.TOTP})
		interlinkForward(w, MustSession(r), ls, "/api/interlink/"+url.PathEscape(req.LinkID)+"/repair-link", body)
	}
}
