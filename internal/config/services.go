package config

// Services (v6.8.1) — discovered Docker/Podman applications inside VMs and
// LXCs, plus user-created custom entries. Design: PLANS/plan-version-6.8.1.md.
//
// The store is deliberately merge-based rather than replace-based: a discovery
// pass refreshes only the facts it observed and carries every user override
// forward, so re-scanning never resets someone's chosen port, icon or open
// mode. Entries not seen in a pass are retained (marked "unknown") so the
// services of a STOPPED instance stay listed — greyed and startable — instead
// of disappearing from the UI.

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// ServiceEntry is one discovered or user-created application.
type ServiceEntry struct {
	ID     string `json:"id"`
	Source string `json:"source"` // "discovered" | "custom"

	// Provenance (discovered services).
	Instance     string `json:"instance,omitempty"`
	InstanceType string `json:"instance_type,omitempty"` // "container" | "virtual-machine"
	Project      string `json:"project,omitempty"`       // compose project ("" = standalone)
	Container    string `json:"container,omitempty"`     // elected primary container
	ContainerID  string `json:"container_id,omitempty"`
	Image        string `json:"image,omitempty"`

	// User overrides — never clobbered by a discovery pass.
	Name           string `json:"name,omitempty"`
	PortOverride   int    `json:"port_override,omitempty"`
	SchemeOverride string `json:"scheme_override,omitempty"` // "http" | "https"
	PathOverride   string `json:"path_override,omitempty"`
	URLOverride    string `json:"url_override,omitempty"` // custom services
	OpenMode       string `json:"open_mode,omitempty"`    // "panel" | "tab" | "window"
	Hidden         bool   `json:"hidden,omitempty"`       // omit from the Icon View
	// Pinned puts the service in the left menu whatever its open mode is —
	// pinning and embedding used to be the same decision, which meant a service
	// you wanted one click away had to be embedded even when embedding was the
	// wrong way to open it. nil keeps the old behaviour for entries saved before
	// this existed: embedded services were implicitly pinned. See PinnedOn.
	Pinned *bool `json:"pinned,omitempty"`
	IconOverride   string `json:"icon_override,omitempty"`
	// IgnoreTLSErrors controls certificate verification when the upstream is
	// HTTPS. nil = ignore (the default): self-hosted apps overwhelmingly use
	// self-signed certificates, and the target is already constrained to an
	// allowlisted private address, so verifying by default would simply break
	// them. Set false to enforce verification for a specific service.
	IgnoreTLSErrors *bool `json:"ignore_tls_errors,omitempty"`

	// Discovered / cached facts.
	// IP is the parent instance's address at last discovery. The proxy dials
	// this value (never anything from the request) and re-validates it, so the
	// stored record IS the allowlist.
	IP           string    `json:"ip,omitempty"`
	DetectedPort int       `json:"detected_port,omitempty"`
	// PublishedPorts is every port the container exposes. Surfaced in the gear
	// so a wrong auto-pick can be corrected by choosing from reality rather
	// than guessing — a mis-set override silently points the proxy at another
	// container entirely.
	PublishedPorts []int  `json:"published_ports,omitempty"`
	// Reachable records whether the ZNAS host could actually open a TCP
	// connection to IP:port at last discovery. A guest can be perfectly healthy
	// yet sit on a VLAN this host has no route to — in that case the proxy can
	// never work, and saying so beats rendering a frame that silently spins.
	// NOTE: no omitempty. `false` is the meaningful value here — omitting it
	// would make "unreachable" indistinguishable from "not reported" in the
	// API, which silently disabled the unreachable warning in the UI.
	Reachable         bool   `json:"reachable"`
	UnreachableReason string `json:"unreachable_reason,omitempty"`
	Tags         []string  `json:"tags,omitempty"` // replicated from the parent instance
	LastSeen     time.Time `json:"last_seen,omitempty"`
	LastState    string    `json:"last_state,omitempty"` // "running" | "exited" | "unknown"
}

// ServiceID is the stable key for a service.
//
// For a compose stack the id is derived from the PROJECT, not the container:
// a later scan may elect a different primary container (a stack gaining a
// reverse proxy, say), and keying on the container would orphan every override
// the user had set. Standalone containers key on the container name and carry a
// different kind byte so `project "foo"` and `container "foo"` never collide.
func ServiceID(instance, project, container string) string {
	kind, key := "c", container
	if project != "" {
		kind, key = "p", project
	}
	sum := sha256.Sum256([]byte(instance + "\x00" + kind + "\x00" + key))
	return hex.EncodeToString(sum[:8])
}

// LoadServices reads the persisted service list. A missing file is not an
// error — it simply means nothing has been discovered yet.
func LoadServices() ([]ServiceEntry, error) {
	var s []ServiceEntry
	if err := loadJSON("services.json", &s); err != nil {
		return nil, err
	}
	if s == nil {
		s = []ServiceEntry{}
	}
	return s, nil
}

// IgnoreTLSOn reports whether upstream certificate errors are ignored for this
// service. Absent = true, so existing and newly discovered services keep
// working against self-signed certificates.
func (e *ServiceEntry) IgnoreTLSOn() bool {
	return e.IgnoreTLSErrors == nil || *e.IgnoreTLSErrors
}

// PinnedOn reports whether this service belongs in the left menu. Unset falls
// back to the rule that predates the flag — an embedded service was pinned by
// definition — so nothing moves out of the menu on upgrade.
func (e *ServiceEntry) PinnedOn() bool {
	if e.Pinned != nil {
		return *e.Pinned
	}
	return e.OpenMode == "panel"
}

// SaveServices persists the service list.
func SaveServices(s []ServiceEntry) error { return saveJSON("services.json", s) }

// MergeServices folds a discovery pass into the stored list.
//
//   - Discovered facts (instance, container, image, port, tags, state) are
//     refreshed from the pass.
//   - Every user override is carried forward untouched.
//   - Entries not seen this pass keep their data and are marked "unknown", so a
//     stopped instance's services remain listed (greyed) and startable.
//   - Custom (user-created) services are never modified by discovery.
//
// Order is stable: existing entries keep their position, new ones are appended.
func MergeServices(existing, discovered []ServiceEntry) []ServiceEntry {
	byID := make(map[string]ServiceEntry, len(existing)+len(discovered))
	order := make([]string, 0, len(existing)+len(discovered))
	for _, e := range existing {
		if _, dup := byID[e.ID]; !dup {
			order = append(order, e.ID)
		}
		byID[e.ID] = e
	}

	seen := make(map[string]bool, len(discovered))
	for _, d := range discovered {
		seen[d.ID] = true
		prev, ok := byID[d.ID]
		if !ok {
			byID[d.ID] = d
			order = append(order, d.ID)
			continue
		}
		// Refresh observed facts only — everything else is a user override.
		prev.Instance, prev.InstanceType = d.Instance, d.InstanceType
		prev.Project, prev.Container, prev.ContainerID = d.Project, d.Container, d.ContainerID
		prev.Image = d.Image
		prev.IP = d.IP
		prev.DetectedPort = d.DetectedPort
		prev.PublishedPorts = d.PublishedPorts
		prev.Reachable, prev.UnreachableReason = d.Reachable, d.UnreachableReason
		prev.Tags = d.Tags
		prev.LastSeen, prev.LastState = d.LastSeen, d.LastState
		byID[d.ID] = prev
	}

	out := make([]ServiceEntry, 0, len(order))
	for _, id := range order {
		e := byID[id]
		if e.Source != "custom" && !seen[e.ID] {
			// Instance stopped, unreachable, or discovery disabled this pass.
			e.LastState = "unknown"
		}
		out = append(out, e)
	}
	return out
}
