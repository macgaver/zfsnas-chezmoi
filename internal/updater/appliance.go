package updater

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
)

// applianceReleasesAPI lists the USB appliance image releases. The images live
// in their own repository: a 1.5 GB ISO per release would otherwise bury the
// portal's binary releases, and the two ship on independent schedules.
const applianceReleasesAPI = "https://api.github.com/repos/macgaver/znas-usb-appliance/releases?per_page=30"

// applianceISORe matches the published image name, e.g.
// znas-usb-appliance-v26-04-1-1.iso -> Ubuntu 26.04.1, appliance build 1.
// The asset name — not the release tag — is the source of truth for the
// version, so a mistyped tag cannot make an old image look new.
var applianceISORe = regexp.MustCompile(`^znas-usb-appliance-v(\d+)-(\d+)-(\d+)-(\d+)\.iso$`)

// ApplianceImageRelease is one published appliance image.
type ApplianceImageRelease struct {
	Version     string `json:"version"` // "26.04.1-1"
	Tag         string `json:"tag"`
	Name        string `json:"name"`
	Body        string `json:"body"` // release notes, raw markdown
	PublishedAt string `json:"published_at"`
	ISOName     string `json:"iso_name"`
	ISOURL      string `json:"iso_url"`
	ISOSize     int64  `json:"iso_size"`
	SHA256URL   string `json:"sha256_url"`
	SigURL      string `json:"sig_url"` // cosign signature of the ISO; required to install
}

// ApplianceVersionFromISOName returns "26.04.1-1" for a published image name,
// or "" when the name is not an appliance image.
func ApplianceVersionFromISOName(name string) string {
	m := applianceISORe.FindStringSubmatch(name)
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s-%s", m[1], m[2], m[3], m[4])
}

// CheckApplianceReleases returns every published (non-draft, non-prerelease)
// appliance image, in GitHub's order (newest first). Releases without an ISO
// asset are skipped; picking the highest version is the caller's job.
func CheckApplianceReleases() ([]ApplianceImageRelease, error) {
	resp, err := metaClient.Get(applianceReleasesAPI)
	if err != nil {
		return nil, fmt.Errorf("github API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github API returned status %d", resp.StatusCode)
	}
	var raw []ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return parseApplianceReleases(raw), nil
}

// ghRelease is the subset of GitHub's release JSON the appliance check reads.
type ghRelease struct {
	TagName     string `json:"tag_name"`
	Name        string `json:"name"`
	Body        string `json:"body"`
	PublishedAt string `json:"published_at"`
	Draft       bool   `json:"draft"`
	Prerelease  bool   `json:"prerelease"`
	Assets      []struct {
		Name               string `json:"name"`
		Size               int64  `json:"size"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

func parseApplianceReleases(rels []ghRelease) []ApplianceImageRelease {
	var out []ApplianceImageRelease
	for _, r := range rels {
		if r.Draft || r.Prerelease {
			continue
		}
		urls := map[string]string{}
		for _, a := range r.Assets {
			urls[a.Name] = a.BrowserDownloadURL
		}
		for _, a := range r.Assets {
			v := ApplianceVersionFromISOName(a.Name)
			if v == "" {
				continue
			}
			out = append(out, ApplianceImageRelease{
				Version:     v,
				Tag:         r.TagName,
				Name:        r.Name,
				Body:        r.Body,
				PublishedAt: r.PublishedAt,
				ISOName:     a.Name,
				ISOURL:      a.BrowserDownloadURL,
				ISOSize:     a.Size,
				SHA256URL:   urls[a.Name+".sha256"],
				SigURL:      urls[a.Name+".sig"],
			})
		}
	}
	return out
}
