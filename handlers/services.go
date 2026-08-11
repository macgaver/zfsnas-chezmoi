package handlers

// Services API + discovery orchestrator (v6.8.1).
// Design: PLANS/plan-version-6.8.1.md §4 (discovery), §6 (icons), §10 (API).
//
// Discovery is deliberately cache-then-refresh: `incus exec` into every guest is
// expensive, so HTTP handlers always answer from services.json and a background
// goroutine refreshes it. Nothing here runs while the master toggle is off.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"zfsnas/internal/audit"
	"zfsnas/internal/config"
	"zfsnas/system"
)

const serviceDiscoveryInterval = 5 * time.Minute

// serviceDiscoveryMu serialises discovery passes so a manual refresh and the
// background ticker can't interleave and lose each other's writes.
var serviceDiscoveryMu sync.Mutex

// serviceIconDir is where cached icon bytes live.
func serviceIconDir() string { return filepath.Join(config.Dir(), "service-icons") }

// StartServiceDiscovery launches the background discovery poller.
func StartServiceDiscovery(appCfg *config.AppConfig) {
	go func() {
		// Let the host settle before the first (relatively expensive) sweep.
		time.Sleep(45 * time.Second)
		for {
			if appCfg.ServiceDiscoveryOn() {
				if err := runServiceDiscovery(appCfg); err != nil {
					log.Printf("services: discovery pass: %v", err)
				}
			}
			time.Sleep(serviceDiscoveryInterval)
		}
	}()
}

// scannableInstance reports whether a discovery pass should try to enumerate
// this instance's containers. Only running instances can answer, and backup
// clones (bkup--*) are transient copies whose containers are not services.
// An instance that fails this test is never authoritative: its absence from a
// pass says nothing about whether its services still exist.
func scannableInstance(inst system.LXDInstance) bool {
	return inst.Status == "Running" && !strings.HasPrefix(inst.Name, "bkup--")
}

// runServiceDiscovery performs one full sweep: every RUNNING VM/LXC is probed
// for a container runtime, its containers are grouped into services, and the
// result is merged into the stored list. Services of stopped or unreachable
// instances are retained by MergeServices (marked "unknown") so they stay
// visible and startable; services missing from an instance we DID successfully
// scan are marked gone and pruned after config.ServiceGoneGrace.
func runServiceDiscovery(appCfg *config.AppConfig) error {
	serviceDiscoveryMu.Lock()
	defer serviceDiscoveryMu.Unlock()

	if !appCfg.ServiceDiscoveryOn() {
		return nil
	}
	instances, err := system.ListLXDInstances()
	if err != nil {
		return err
	}

	existing, err := config.LoadServices()
	if err != nil {
		return err
	}
	// Services we already know about. A container that has stopped reports no
	// ports, so the eligibility rule alone would drop a service the user merely
	// stopped; this set lets grouping recognise it. See system.GroupServices.
	knownIDs := make(map[string]bool, len(existing))
	for _, e := range existing {
		if e.Source == "discovered" {
			knownIDs[e.ID] = true
		}
	}

	now := time.Now()
	var discovered []config.ServiceEntry
	// scanned = instances this pass could actually enumerate; alive = every
	// instance that still exists. MergeServices needs both to tell "the
	// container is gone" from "we could not look". See config.MergeServices.
	scanned := map[string]bool{}
	alive := map[string]bool{}
	for _, inst := range instances {
		alive[inst.Name] = true
		if !scannableInstance(inst) {
			continue
		}
		if !system.DockerProbe(inst.Name).Available {
			continue
		}
		containers, err := system.DockerListContainers(inst.Name)
		if err != nil {
			continue
		}
		scanned[inst.Name] = true
		known := func(c system.DockerContainer) bool {
			return knownIDs[config.ServiceID(inst.Name, c.Project, c.Name)]
		}
		for _, svc := range system.GroupServices(containers, known) {
			// Choose an address the host can ACTUALLY reach, rather than
			// trusting the instance's single best-guess IP. Multi-homed guests
			// (the norm once Docker is installed) otherwise produce URLs that
			// can never load — the field failure that motivated this.
			ip, reachable, reason := resolveServiceAddr(inst, svc.Port)
			discovered = append(discovered, config.ServiceEntry{
				ID:           config.ServiceID(inst.Name, svc.Project, svc.Container),
				Source:       "discovered",
				Instance:     inst.Name,
				InstanceType: inst.Type,
				Project:      svc.Project,
				Container:    svc.Container,
				ContainerID:  svc.ContainerID,
				Image:        svc.Image,
				IP:                ip,
				DetectedPort:      svc.Port,
				PublishedPorts:    svc.AllPorts,
				Reachable:         reachable,
				UnreachableReason: reason,
				Tags:         inst.Tags,
				LastSeen:     now,
				LastState:    svc.State,
			})
		}
	}

	return config.SaveServices(config.MergeServices(existing, discovered, scanned, alive, now))
}

// serviceOut is the API shape. It adds the computed fields the UI needs so the
// frontend never has to re-derive the URL or open mode.
type serviceOut struct {
	config.ServiceEntry
	DisplayName string `json:"display_name"`
	URL         string `json:"url"`          // direct app URL (new tab / window)
	ProxyURL    string `json:"proxy_url"`    // same-origin proxied URL (panel)
	Openable    bool   `json:"openable"`     // false when no port is known
	EffectiveOpenMode string `json:"effective_open_mode"`
	// Resolved form of the Pinned pointer, so the UI never has to know about
	// the "unset means follow open_mode" rule.
	PinnedEffective bool `json:"pinned_effective"`
}

func decorateService(e config.ServiceEntry, proxyOn bool) serviceOut {
	out := serviceOut{ServiceEntry: e}
	out.PinnedEffective = e.PinnedOn()

	out.DisplayName = e.Name
	if out.DisplayName == "" {
		out.DisplayName = e.Project
	}
	if out.DisplayName == "" {
		out.DisplayName = e.Container
	}

	if t, err := resolveServiceTarget(e); err == nil {
		out.URL = t.BrowserURL() + strings.TrimRight(t.Path, "/")
		out.Openable = true
		// The proxy serves the upstream host root, so the entry URL carries the
		// service's own path.
		out.ProxyURL = "/s/" + e.ID + "/" + strings.Trim(t.Path, "/")
		if !strings.HasSuffix(out.ProxyURL, "/") {
			out.ProxyURL += "/"
		}
	}

	// Default to a NEW TAB, not the embedded panel. Proxied embedding works for
	// a minority of real-world apps (mixed content, anti-framing headers,
	// localStorage under a sandbox, absolute asset paths), whereas a top-level
	// navigation always works. Embedding is now strictly opt-in per service.
	out.EffectiveOpenMode = e.OpenMode
	if out.EffectiveOpenMode == "" {
		out.EffectiveOpenMode = "tab"
	}
	// With the proxy off, the panel can only work for HTTPS apps (mixed
	// content blocks the rest), so fall back to a window rather than paint a
	// frame that is guaranteed to be blank. See spec §2.7.
	if !proxyOn && out.EffectiveOpenMode == "panel" && !strings.HasPrefix(out.URL, "https://") {
		out.EffectiveOpenMode = "window"
	}
	// The proxy dials from THIS host. If the host has no route to the service,
	// embedding cannot work — the user's browser may still reach it, so a new
	// tab is the useful default. But only when the user has NOT made an explicit
	// choice: silently overriding a deliberate "embed in panel" selection is
	// worse than showing them why it failed.

	return out
}

// HandleListServices returns the stored service list (never blocks on a scan).
func HandleListServices(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !appCfg.ServiceDiscoveryOn() {
			jsonOK(w, []serviceOut{})
			return
		}
		list, err := config.LoadServices()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load services")
			return
		}
		proxyOn := appCfg.ServiceProxyOn()
		out := make([]serviceOut, 0, len(list))
		for _, e := range list {
			out = append(out, decorateService(e, proxyOn))
		}
		jsonOK(w, out)
	}
}

// HandleRefreshServices runs one discovery pass synchronously.
func HandleRefreshServices(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !appCfg.ServiceDiscoveryOn() {
			jsonErr(w, http.StatusForbidden, "service discovery is disabled")
			return
		}
		if err := runServiceDiscovery(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "discovery failed: "+err.Error())
			return
		}
		jsonOK(w, map[string]string{"message": "refreshed"})
	}
}

// HandleCreateService adds a user-defined custom service.
func HandleCreateService(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name         string `json:"name"`
			URL          string `json:"url"`
			Instance     string `json:"instance"`
			IconOverride string `json:"icon_override"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		req.Name = strings.TrimSpace(req.Name)
		req.URL = strings.TrimSpace(req.URL)
		if req.Name == "" || req.URL == "" {
			jsonErr(w, http.StatusBadRequest, "name and url are required")
			return
		}
		entry := config.ServiceEntry{
			Source:       "custom",
			Name:         req.Name,
			URLOverride:  req.URL,
			Instance:     req.Instance,
			IconOverride: req.IconOverride,
			LastState:    "custom",
		}
		// Validate the target now so a bad URL is rejected at creation, not at
		// first click — and so an SSRF attempt never gets persisted.
		if _, err := resolveServiceTarget(entry); err != nil {
			jsonErr(w, http.StatusBadRequest, "unusable service URL: "+err.Error())
			return
		}
		buf := make([]byte, 8)
		rand.Read(buf) //nolint:errcheck
		entry.ID = "custom-" + hex.EncodeToString(buf)

		list, err := config.LoadServices()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load services")
			return
		}
		list = append(list, entry)
		if err := config.SaveServices(list); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save services")
			return
		}
		auditService(r, "custom service created: "+entry.Name)
		jsonOK(w, decorateService(entry, appCfg.ServiceProxyOn()))
	}
}

// HandleUpdateService applies the gear-dialog overrides.
func HandleUpdateService(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		var req struct {
			Name           *string `json:"name"`
			PortOverride   *int    `json:"port_override"`
			SchemeOverride *string `json:"scheme_override"`
			PathOverride   *string `json:"path_override"`
			URLOverride    *string `json:"url_override"`
			OpenMode       *string `json:"open_mode"`
			Hidden         *bool   `json:"hidden"`
			IconOverride    *string `json:"icon_override"`
			IgnoreTLSErrors *bool   `json:"ignore_tls_errors"`
			Pinned          *bool   `json:"pinned"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		list, err := config.LoadServices()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load services")
			return
		}
		idx := -1
		for i := range list {
			if list[i].ID == id {
				idx = i
				break
			}
		}
		if idx < 0 {
			jsonErr(w, http.StatusNotFound, "service not found")
			return
		}
		e := list[idx]
		if req.Name != nil {
			e.Name = strings.TrimSpace(*req.Name)
		}
		if req.PortOverride != nil {
			e.PortOverride = *req.PortOverride
		}
		if req.SchemeOverride != nil {
			s := strings.ToLower(strings.TrimSpace(*req.SchemeOverride))
			if s != "" && s != "http" && s != "https" {
				jsonErr(w, http.StatusBadRequest, "scheme must be http or https")
				return
			}
			e.SchemeOverride = s
		}
		if req.PathOverride != nil {
			e.PathOverride = strings.TrimSpace(*req.PathOverride)
		}
		if req.URLOverride != nil {
			e.URLOverride = strings.TrimSpace(*req.URLOverride)
		}
		if req.OpenMode != nil {
			m := strings.ToLower(strings.TrimSpace(*req.OpenMode))
			switch m {
			case "", "panel", "tab", "window":
				e.OpenMode = m
			default:
				jsonErr(w, http.StatusBadRequest, "open_mode must be panel, tab or window")
				return
			}
		}
		if req.Hidden != nil {
			e.Hidden = *req.Hidden
		}
		if req.IconOverride != nil {
			e.IconOverride = strings.TrimSpace(*req.IconOverride)
		}
		if req.IgnoreTLSErrors != nil {
			v := *req.IgnoreTLSErrors
			e.IgnoreTLSErrors = &v
		}
		// Pinning is now its own decision, independent of how the service opens.
		if req.Pinned != nil {
			v := *req.Pinned
			e.Pinned = &v
		}
		// Re-validate: an override must not be able to aim the proxy somewhere
		// the allowlist would refuse.
		if e.DetectedPort > 0 || e.PortOverride > 0 || e.URLOverride != "" {
			if _, err := resolveServiceTarget(e); err != nil {
				jsonErr(w, http.StatusBadRequest, "unusable target: "+err.Error())
				return
			}
		}
		list[idx] = e
		if err := config.SaveServices(list); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save services")
			return
		}
		auditService(r, "service updated: "+id)
		jsonOK(w, decorateService(e, appCfg.ServiceProxyOn()))
	}
}

// HandleDeleteService removes a custom service. Discovered services cannot be
// deleted (they would reappear on the next sweep) — they are hidden instead.
func HandleDeleteService(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		list, err := config.LoadServices()
		if err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to load services")
			return
		}
		out := make([]config.ServiceEntry, 0, len(list))
		found := false
		for _, e := range list {
			if e.ID == id {
				if e.Source != "custom" {
					jsonErr(w, http.StatusBadRequest,
						"discovered services cannot be deleted — use \"don't list in left menu\" to hide it")
					return
				}
				found = true
				continue
			}
			out = append(out, e)
		}
		if !found {
			jsonErr(w, http.StatusNotFound, "service not found")
			return
		}
		if err := config.SaveServices(out); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save services")
			return
		}
		auditService(r, "custom service deleted: "+id)
		jsonOK(w, map[string]string{"message": "deleted"})
	}
}

// HandleServiceAction starts/stops/restarts the container behind a service.
func HandleServiceAction(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		var req struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		switch req.Action {
		case "start", "stop", "restart":
		default:
			jsonErr(w, http.StatusBadRequest, "action must be start, stop or restart")
			return
		}
		entry, ok := findService(id)
		if !ok {
			jsonErr(w, http.StatusNotFound, "service not found")
			return
		}
		if entry.Source == "custom" || entry.Instance == "" || entry.Container == "" {
			jsonErr(w, http.StatusBadRequest, "this service has no container to control")
			return
		}
		target := entry.ContainerID
		if target == "" {
			target = entry.Container
		}
		if err := system.DockerContainerAction(entry.Instance, target, req.Action, nil); err != nil {
			jsonErr(w, http.StatusInternalServerError, req.Action+" failed: "+err.Error())
			return
		}
		auditService(r, "service "+req.Action+": "+entry.Instance+"/"+entry.Container)
		jsonOK(w, map[string]string{"message": req.Action + " ok"})
	}
}

// HandleServiceIcon serves a cached icon. Icons are attacker-influenced bytes
// served from our own origin, so they go out with a locked-down content policy
// and no sniffing (spec §2.4).
func HandleServiceIcon(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		entry, ok := findService(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		key := system.IconCacheKey(entry.IconOverride, entry.Image, entry.Container)
		data, ct, ok := system.LoadCachedIcon(serviceIconDir(), key)
		if !ok {
			// Try to fetch it now; a miss is not an error — the UI falls back
			// to its generic glyph. The service's own URL is passed so the
			// fetcher can fall back to its favicon when no icon-pack entry
			// matches, which is the common case for less well-known apps.
			// resolveProxyTarget, not resolveServiceTarget: fetching a favicon is
			// the PORTAL making an outbound request, so it keeps the private-
			// address policy (spec §2.4) even though a custom service is now
			// free to point at a public URL for the browser's benefit. Such a
			// service just gets the generic glyph unless an icon is set by hand.
			svcURL := ""
			if t, err := resolveProxyTarget(entry); err == nil {
				svcURL = t.BaseURL() + strings.TrimRight(t.Path, "/")
			}
			if d, c, err := system.FetchServiceIcon(entry.IconOverride, entry.Image, svcURL, entry.IgnoreTLSOn()); err == nil {
				if err := system.CacheIcon(serviceIconDir(), key, d, c); err == nil {
					data, ct = d, c
					ok = true
				}
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		w.Header().Set("Cache-Control", "private, max-age=86400")
		w.Write(data) //nolint:errcheck
	}
}

func auditService(r *http.Request, details string) {
	sess := MustSession(r)
	audit.Log(audit.Entry{
		User:    sess.Username,
		Role:    sess.Role,
		Action:  audit.ActionUpdateSettings,
		Result:  audit.ResultOK,
		Details: details,
	})
}

// ── Settings (Settings → Virtualization) ────────────────────────────────────

// HandleGetServiceSettings returns the three Services toggles.
func HandleGetServiceSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		jsonOK(w, map[string]interface{}{
			"discovery_enabled": appCfg.ServiceDiscoveryOn(),
			"proxy_enabled":     appCfg.ServiceProxyEnabled == nil || *appCfg.ServiceProxyEnabled,
		})
	}
}

// HandleSetServiceSettings persists the toggles. Changes take effect without a
// restart: discovery re-reads appCfg each tick and the proxy checks
// ServiceProxyOn() on every request.
func HandleSetServiceSettings(appCfg *config.AppConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			DiscoveryEnabled bool `json:"discovery_enabled"`
			ProxyEnabled     bool `json:"proxy_enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, http.StatusBadRequest, "invalid request body")
			return
		}
		d, p := req.DiscoveryEnabled, req.ProxyEnabled
		appCfg.ServiceDiscoveryEnabled = &d
		appCfg.ServiceProxyEnabled = &p
		if err := config.SaveAppConfig(appCfg); err != nil {
			jsonErr(w, http.StatusInternalServerError, "failed to save settings")
			return
		}
		auditService(r, fmt.Sprintf("service settings: discovery=%v proxy=%v",
			req.DiscoveryEnabled, req.ProxyEnabled))
		jsonOK(w, map[string]interface{}{
			"discovery_enabled": appCfg.ServiceDiscoveryOn(),
			"proxy_enabled":     req.ProxyEnabled,
		})
	}
}


// resolveServiceAddr picks the instance address that actually answers on the
// service's port. It returns the chosen IP plus whether anything answered and,
// if not, a short human reason for the UI.
//
// Candidates come from the instance's full address list (best guess first),
// minus loopback and Docker's in-guest bridges. When the service publishes no
// port there is nothing to probe, so we fall back to the best-guess address and
// simply report it as not openable.
func resolveServiceAddr(inst system.LXDInstance, port int) (ip string, reachable bool, reason string) {
	candidates := inst.IPv4All
	if len(candidates) == 0 && inst.IPv4 != "" {
		candidates = []string{inst.IPv4}
	}
	if port <= 0 {
		return inst.IPv4, false, "no published web port"
	}
	if got, ok := system.PickReachableAddr(candidates, port); ok {
		return got, true, ""
	}
	usable := system.FilterCandidateAddrs(candidates)
	if len(usable) == 0 {
		return inst.IPv4, false, "instance has no reachable address (only in-guest Docker bridges)"
	}
	return usable[0], false,
		fmt.Sprintf("no route from this server to %s:%d — the instance may be on a network this host cannot reach", usable[0], port)
}
