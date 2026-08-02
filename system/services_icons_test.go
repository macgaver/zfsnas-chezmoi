package system

import "testing"

// SVG can embed <script>, and cached icons are served from the portal's own
// origin — accepting one would be stored XSS. This gate is a security control
// (spec §2.4); these cases pin it.
func TestIconContentTypeRejectsActiveContent(t *testing.T) {
	for _, ct := range []string{
		"image/svg+xml",
		"image/svg+xml; charset=utf-8",
		"IMAGE/SVG+XML",
		"  image/svg+xml  ",
		"text/html",
		"application/javascript",
		"application/xml",
		"text/plain",
		"application/octet-stream",
		"",
	} {
		if IconContentTypeAllowed(ct) {
			t.Errorf("content-type %q must be rejected", ct)
		}
	}
}

func TestIconContentTypeAllowsRaster(t *testing.T) {
	for _, ct := range []string{
		"image/png",
		"image/jpeg",
		"image/webp",
		"image/gif",
		"image/x-icon",
		"image/vnd.microsoft.icon",
		"image/png; charset=binary",
		"IMAGE/PNG",
	} {
		if !IconContentTypeAllowed(ct) {
			t.Errorf("content-type %q must be allowed", ct)
		}
	}
}

// A container image rarely matches an icon-pack name exactly. Real examples:
// ghcr.io/immich-app/immich-server:release, linuxserver/jellyfin,
// ghcr.io/dispatcharr/dispatcharr:latest. Deriving several candidates (and
// stripping the -server/-web/-app suffixes that container images add) is what
// turns those into a pack hit.
func TestIconSlugCandidates(t *testing.T) {
	cases := map[string][]string{
		"ghcr.io/immich-app/immich-server:release": {"immich-server", "immich", "immich-app"},
		"linuxserver/jellyfin":                     {"jellyfin"},
		"jellyfin/jellyfin:latest":                 {"jellyfin"},
		"zoraxydocker/zoraxy:latest":               {"zoraxy", "zoraxydocker"},
		"nginxinc/nginx-unprivileged:alpine":       {"nginx-unprivileged", "nginx", "nginxinc"},
	}
	for image, want := range cases {
		got := IconSlugCandidates(image)
		for _, w := range want {
			found := false
			for _, g := range got {
				if g == w {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("IconSlugCandidates(%q) = %v, missing %q", image, got, w)
			}
		}
	}
}

// Candidates must be safe to interpolate into a URL and free of duplicates.
func TestIconSlugCandidatesAreSafe(t *testing.T) {
	for _, c := range IconSlugCandidates("ghcr.io/Some_Org/Weird..Name:tag") {
		if !isSafeIconSlug(c) {
			t.Errorf("unsafe candidate %q", c)
		}
	}
	got := IconSlugCandidates("jellyfin/jellyfin")
	seen := map[string]bool{}
	for _, c := range got {
		if seen[c] {
			t.Errorf("duplicate candidate %q in %v", c, got)
		}
		seen[c] = true
	}
}

// Favicon discovery: prefer a declared <link rel=icon>, else /favicon.ico.
func TestParseFaviconHref(t *testing.T) {
	cases := map[string]string{
		`<link rel="icon" href="/favicon-96.png">`:                    "/favicon-96.png",
		`<link rel="shortcut icon" href="static/fav.ico">`:            "static/fav.ico",
		`<link rel="apple-touch-icon" href="/apple.png">`:             "/apple.png",
		`<link rel="stylesheet" href="/a.css"><link rel=icon href=/b.png>`: "/b.png",
		`<html><head></head></html>`:                                  "",
	}
	for in, want := range cases {
		if got := ParseFaviconHref([]byte(in)); got != want {
			t.Errorf("ParseFaviconHref(%q) = %q, want %q", in, got, want)
		}
	}
}
