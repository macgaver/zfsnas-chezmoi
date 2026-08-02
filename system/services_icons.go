package system

// Service icon cache (v6.8.1). Design: PLANS/plan-version-6.8.1.md §6, with the
// security constraints in §2.4.
//
// Icons are fetched once (from a pinned icon pack or the service's own favicon)
// and cached as opaque bytes, then served from the portal's own origin. That
// last point is why the content-type gate below is strict rather than
// permissive.

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// maxIconBytes bounds anything we are willing to store or serve.
const maxIconBytes = 512 * 1024

// allowedIconTypes is a strict RASTER allowlist.
//
// SVG is deliberately absent: it is an active-content format (it can carry
// <script>), and because cached icons are served from the portal's own origin,
// accepting an attacker-supplied SVG would be stored XSS against the portal.
// Anything not on this list is refused rather than sniffed.
var allowedIconTypes = map[string]bool{
	"image/png":                true,
	"image/jpeg":               true,
	"image/webp":               true,
	"image/gif":                true,
	"image/x-icon":             true,
	"image/vnd.microsoft.icon": true,
}

// IconContentTypeAllowed reports whether a fetched icon may be cached & served.
func IconContentTypeAllowed(ct string) bool {
	base, _, _ := strings.Cut(ct, ";")
	return allowedIconTypes[strings.ToLower(strings.TrimSpace(base))]
}

// CacheIcon stores icon bytes plus their content-type under dir. Both the size
// cap and the content-type gate are enforced here, so every write path gets
// them regardless of which fetcher produced the bytes.
func CacheIcon(dir, key string, data []byte, ct string) error {
	if len(data) == 0 || len(data) > maxIconBytes {
		return fmt.Errorf("icon size %d out of range", len(data))
	}
	if !IconContentTypeAllowed(ct) {
		return fmt.Errorf("icon content-type %q refused", ct)
	}
	if strings.ContainsAny(key, "/\\.") {
		return fmt.Errorf("invalid icon key %q", key) // no path traversal
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, key+".bin"), data, 0o640); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, key+".type"), []byte(ct), 0o640)
}

// LoadCachedIcon returns cached icon bytes and their content-type. The stored
// type is re-validated on read so a hand-edited cache cannot smuggle an active
// content-type back in.
func LoadCachedIcon(dir, key string) ([]byte, string, bool) {
	if strings.ContainsAny(key, "/\\.") {
		return nil, "", false
	}
	data, err := os.ReadFile(filepath.Join(dir, key+".bin"))
	if err != nil || len(data) == 0 {
		return nil, "", false
	}
	ctb, err := os.ReadFile(filepath.Join(dir, key+".type"))
	if err != nil {
		return nil, "", false
	}
	ct := strings.TrimSpace(string(ctb))
	if !IconContentTypeAllowed(ct) {
		return nil, "", false
	}
	return data, ct, true
}

// ── Icon resolution ──────────────────────────────────────────────────────────

// iconPackBase is the single pinned host we will fetch icon art from. Keeping
// it a constant (rather than anything derived from user input) means the icon
// fetcher can never be pointed at an arbitrary URL.
const iconPackBase = "https://cdn.jsdelivr.net/gh/homarr-labs/dashboard-icons/png/"

// imageSlugRe strips a registry, namespace and tag from a container image name:
// "ghcr.io/linuxserver/jellyfin:latest" → "jellyfin".
var imageSlugRe = regexp.MustCompile(`^(?:[^/]+\.[^/]+/)?(?:[^/]+/)*([^/:@]+)`)

// iconClient bounds every outbound icon fetch. Redirects are capped and the
// overall time is short: an icon is never worth stalling a page render.
var iconClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// iconClientInsecure skips upstream certificate verification when fetching a
// favicon, matching the proxy's per-service default: self-hosted apps almost
// always present a self-signed certificate, and the target is an already
// validated private address.
var iconClientInsecure = &http.Client{
	Timeout:   8 * time.Second,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// ImageSlug reduces a container image reference to a bare application name,
// which is what the icon pack is keyed on.
func ImageSlug(image string) string {
	m := imageSlugRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(image)))
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// imageNamespaceRe captures the namespace of an image reference:
// "ghcr.io/immich-app/immich-server" → "immich-app".
var imageNamespaceRe = regexp.MustCompile(`^(?:[^/]+\.[^/]+/)?([^/:@]+)/`)

// containerNameSuffixes are the decorations container images add to an app's
// real name. "immich-server" is the image; "immich" is the icon.
var containerNameSuffixes = []string{
	"-server", "-app", "-web", "-ui", "-docker", "-ce", "-oss", "-unprivileged",
}

// IconSlugCandidates derives the names worth trying against the icon pack, most
// specific first. A container image seldom matches a pack entry exactly:
// ghcr.io/immich-app/immich-server:release must reach "immich", and
// zoraxydocker/zoraxy must reach "zoraxy". Returning several candidates instead
// of one is what lifts icon coverage from "exact matches only" to most apps.
func IconSlugCandidates(image string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v == "" || seen[v] || !isSafeIconSlug(v) {
			return
		}
		seen[v] = true
		out = append(out, v)
	}

	name := ImageSlug(image)
	add(name)
	// Strip container-ish suffixes: immich-server → immich.
	for _, suf := range containerNameSuffixes {
		if strings.HasSuffix(name, suf) && len(name) > len(suf) {
			add(strings.TrimSuffix(name, suf))
		}
	}
	// The namespace often IS the app: immich-app/… → immich, and it also covers
	// vendor-suffixed orgs like zoraxydocker.
	if m := imageNamespaceRe.FindStringSubmatch(strings.ToLower(strings.TrimSpace(image))); len(m) == 2 {
		ns := m[1]
		add(ns)
		for _, suf := range append([]string{"-app"}, containerNameSuffixes...) {
			if strings.HasSuffix(ns, suf) && len(ns) > len(suf) {
				add(strings.TrimSuffix(ns, suf))
			}
		}
	}
	return out
}

// faviconLinkRe finds a <link rel="...icon..."> and captures its href. Quoted
// and unquoted attribute forms both occur in the wild.
var faviconLinkRe = regexp.MustCompile(`(?is)<link\b[^>]*\brel\s*=\s*["']?[^"'>]*icon[^"'>]*["']?[^>]*>`)
var hrefAttrRe = regexp.MustCompile(`(?is)\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))`)

// ParseFaviconHref returns the href of the first icon <link> in an HTML head,
// or "" when the document declares none (the caller then tries /favicon.ico).
func ParseFaviconHref(body []byte) string {
	for _, tag := range faviconLinkRe.FindAll(body, -1) {
		m := hrefAttrRe.FindSubmatch(tag)
		if m == nil {
			continue
		}
		for _, g := range m[1:] {
			if len(g) > 0 {
				return string(g)
			}
		}
	}
	return ""
}

// IconCacheKey is a stable, filesystem-safe key for a service's icon. Keyed on
// the resolved slug so every container running the same image shares one cached
// icon instead of refetching per service.
func IconCacheKey(iconOverride, image, container string) string {
	src := iconOverride
	if src == "" {
		src = ImageSlug(image)
	}
	if src == "" {
		src = container
	}
	sum := sha256.Sum256([]byte(strings.ToLower(src)))
	return hex.EncodeToString(sum[:8])
}

// FetchServiceIcon retrieves icon bytes for a service, preferring an explicit
// user override and otherwise deriving a slug from the container image. It only
// ever contacts the pinned icon-pack host, and everything it returns has passed
// the raster content-type gate and the size cap.
func FetchServiceIcon(iconOverride, image, serviceURL string, insecureTLS bool) ([]byte, string, error) {
	// 1) An explicit override always wins and is looked up in the pack.
	if ov := strings.TrimSpace(iconOverride); ov != "" {
		if !isSafeIconSlug(strings.ToLower(ov)) {
			return nil, "", fmt.Errorf("unsupported icon name %q", ov)
		}
		return fetchPackIcon(strings.ToLower(ov))
	}

	// 2) The icon pack, tried across every plausible name for this image.
	for _, slug := range IconSlugCandidates(image) {
		if data, ct, err := fetchPackIcon(slug); err == nil {
			return data, ct, nil
		}
	}

	// 3) The app's OWN favicon. Many self-hosted apps ship a good one, and it is
	// by definition the right icon for that service even when no pack entry
	// exists. Restricted to the service's already-validated URL.
	if serviceURL != "" {
		if data, ct, err := fetchFaviconFor(serviceURL, insecureTLS); err == nil {
			return data, ct, nil
		}
	}
	return nil, "", fmt.Errorf("no icon found")
}

// fetchPackIcon retrieves one named icon from the pinned pack host.
func fetchPackIcon(slug string) ([]byte, string, error) {
	if !isSafeIconSlug(slug) {
		return nil, "", fmt.Errorf("unsafe slug")
	}
	return fetchIconBytes(iconClient, iconPackBase+slug+".png")
}

// fetchFaviconFor discovers and downloads a service's own favicon: the declared
// <link rel="icon"> when present, else the conventional /favicon.ico.
func fetchFaviconFor(serviceURL string, insecureTLS bool) ([]byte, string, error) {
	base, err := url.Parse(serviceURL)
	if err != nil {
		return nil, "", err
	}
	client := iconClient
	if insecureTLS {
		client = iconClientInsecure
	}

	// Read a bounded slice of the document to find a declared icon.
	if resp, err := client.Get(serviceURL); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
		resp.Body.Close()
		if href := ParseFaviconHref(body); href != "" {
			if ref, err := url.Parse(href); err == nil {
				if abs := base.ResolveReference(ref); abs.Host == base.Host {
					// Same host only — never follow an icon reference off to a
					// third-party origin.
					if data, ct, err := fetchIconBytes(client, abs.String()); err == nil {
						return data, ct, nil
					}
				}
			}
		}
	}
	fav := *base
	fav.Path, fav.RawQuery, fav.Fragment = "/favicon.ico", "", ""
	return fetchIconBytes(client, fav.String())
}

// fetchIconBytes performs one bounded, content-type-checked download.
func fetchIconBytes(client *http.Client, u string) ([]byte, string, error) {
	resp, err := client.Get(u)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("icon fetch: status %d", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !IconContentTypeAllowed(ct) {
		return nil, "", fmt.Errorf("icon content-type %q refused", ct)
	}
	// LimitReader caps what we will read even if the server lies about length.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxIconBytes+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) == 0 || len(data) > maxIconBytes {
		return nil, "", fmt.Errorf("icon size %d out of range", len(data))
	}
	return data, ct, nil
}

// isSafeIconSlug allows only characters that are meaningful in an icon name.
func isSafeIconSlug(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
