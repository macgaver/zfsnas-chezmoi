package updater

import (
	"encoding/json"
	"testing"
)

func TestApplianceVersionFromISOName(t *testing.T) {
	cases := map[string]string{
		"znas-usb-appliance-v26-04-1-1.iso":        "26.04.1-1",
		"znas-usb-appliance-v26-04-0-12.iso":       "26.04.0-12",
		"znas-usb-appliance-v26-04-1-1.iso.sha256": "",
		"znas-usb-appliance-v26-04-1-1.iso.sig":    "",
		"znas-usb-appliance-v26-04-1.iso":          "",
		"zfsnas-usb-6.9.3.iso":                     "",
	}
	for in, want := range cases {
		if got := ApplianceVersionFromISOName(in); got != want {
			t.Errorf("%s: got %q want %q", in, got, want)
		}
	}
}

func TestParseApplianceReleases(t *testing.T) {
	const js = `[
	 {"tag_name":"v26.04.2-1","draft":true,"assets":[{"name":"znas-usb-appliance-v26-04-2-1.iso"}]},
	 {"tag_name":"v26.04.2-0","prerelease":true,"assets":[{"name":"znas-usb-appliance-v26-04-2-0.iso"}]},
	 {"tag_name":"v26.04.1-2","assets":[
	   {"name":"znas-usb-appliance-v26-04-1-2.iso","size":1500,"browser_download_url":"u/iso"},
	   {"name":"znas-usb-appliance-v26-04-1-2.iso.sha256","browser_download_url":"u/sha"},
	   {"name":"znas-usb-appliance-v26-04-1-2.iso.sig","browser_download_url":"u/sig"}]},
	 {"tag_name":"notes-only","assets":[{"name":"README.md"}]}
	]`
	var raw []ghRelease
	if err := json.Unmarshal([]byte(js), &raw); err != nil {
		t.Fatal(err)
	}
	got := parseApplianceReleases(raw)
	if len(got) != 1 {
		t.Fatalf("want 1 release (drafts/prereleases/no-ISO skipped), got %+v", got)
	}
	r := got[0]
	if r.Version != "26.04.1-2" || r.ISOURL != "u/iso" || r.SHA256URL != "u/sha" || r.SigURL != "u/sig" || r.ISOSize != 1500 {
		t.Errorf("bad parse: %+v", r)
	}
}
