package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"zfsnas/internal/config"
)

// A homepage API key may pin the widget's single capacity metric to a specific
// pool. The selection is stored on APIKeyEntry.PoolTarget as "<kind>:<name>"
// where kind is "zfs" or "mergerfs". Empty = default (the first zpool), which
// keeps every pre-existing key behaving exactly as before.

// parsePoolTarget splits a stored PoolTarget into its kind and name. Anything
// unrecognized (no prefix, unknown kind, empty name) returns ("","") so the
// caller falls back to the default pool.
func parsePoolTarget(v string) (kind, name string) {
	k, n, ok := strings.Cut(v, ":")
	if !ok || n == "" {
		return "", ""
	}
	if k != "zfs" && k != "mergerfs" {
		return "", ""
	}
	return k, n
}

// validatePoolTarget reports whether v is an acceptable PoolTarget given the
// currently available zpool and MergerFS pool names. Empty is always valid
// (default). A non-empty value must name an existing pool of the stated kind.
func validatePoolTarget(v string, zpools, mergerfs []string) error {
	if v == "" {
		return nil
	}
	kind, name := parsePoolTarget(v)
	if kind == "" {
		return fmt.Errorf("invalid pool target %q (expected \"zfs:<name>\" or \"mergerfs:<name>\")", v)
	}
	var list []string
	switch kind {
	case "zfs":
		list = zpools
	case "mergerfs":
		list = mergerfs
	}
	for _, n := range list {
		if n == name {
			return nil
		}
	}
	return fmt.Errorf("no %s pool named %q", kind, name)
}

// ── request-scoped API key ──────────────────────────────────────────────────

type apiKeyCtxKeyType struct{}

var apiKeyCtxKey apiKeyCtxKeyType

// withAPIKey returns a copy of r carrying the matched API key entry.
func withAPIKey(r *http.Request, k config.APIKeyEntry) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), apiKeyCtxKey, k))
}

// apiKeyFromRequest returns the API key the request authenticated with, if any.
// Session-authenticated requests (browser) carry no key.
func apiKeyFromRequest(r *http.Request) (config.APIKeyEntry, bool) {
	k, ok := r.Context().Value(apiKeyCtxKey).(config.APIKeyEntry)
	return k, ok
}

// homepagePoolTargetFor returns the (kind, name) capacity target for the
// request's API key, or ("","") for the default (first zpool).
func homepagePoolTargetFor(r *http.Request) (kind, name string) {
	if k, ok := apiKeyFromRequest(r); ok {
		return parsePoolTarget(k.PoolTarget)
	}
	return "", ""
}
