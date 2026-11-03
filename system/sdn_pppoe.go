package system

// PPPoE sessions (spec §6.1): pppd is started by ifupdown ("inet ppp",
// "provider znas-<id>") from files written here at every apply and at boot.

import (
	"os"
	"path/filepath"
	"strings"

	"zfsnas/internal/sdn"
)

var sdnPPPDir = "/etc/ppp"

// sdnWritePPP writes the peers files of the PPPoE interfaces, removes ours
// that are no longer configured, and splices our credentials into the chap
// and pap secrets (an ISP may use either).
func sdnWritePPP(c *sdn.Config) error {
	want := map[string]bool{}
	has := false
	peersDir := filepath.Join(sdnPPPDir, "peers")
	for _, in := range c.Interfaces {
		if in.Kind != "pppoe" {
			continue
		}
		if !has {
			if err := os.MkdirAll(peersDir, 0755); err != nil {
				sdnRun.Run(nil, "mkdir", "-p", peersDir) //nolint:errcheck
			}
			has = true
		}
		name := sdn.PPPoEPeerName(in.ID)
		want[name] = true
		if err := sdnWriteFile(filepath.Join(peersDir, name), []byte(sdn.PPPoEPeers(in))); err != nil {
			return err
		}
	}
	if ents, err := os.ReadDir(peersDir); err == nil {
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), sdn.PPPoEPeerName("")) && !want[e.Name()] {
				sdnRemoveFile(filepath.Join(peersDir, e.Name())) //nolint:errcheck
			}
		}
	}
	for _, f := range []string{"chap-secrets", "pap-secrets"} {
		p := filepath.Join(sdnPPPDir, f)
		cur, err := os.ReadFile(p)
		if err != nil && !os.IsNotExist(err) {
			// Not readable as the portal user: sudo cat.
			if cur, err = sdnRun.Run(nil, "cat", p); err != nil {
				return err
			}
		}
		next := sdn.SpliceSecrets(string(cur), c.Interfaces)
		if next == string(cur) || (!has && len(cur) == 0) {
			continue
		}
		if err := sdnWriteSecret(p, []byte(next)); err != nil {
			return err
		}
	}
	return nil
}

// sdnPPPKey is what, beyond the stanza, makes a PPPoE session restart.
func sdnPPPKey(in sdn.Interface) string {
	if in.Kind != "pppoe" {
		return ""
	}
	return sdn.PPPoEPeers(in) + sdn.SpliceSecrets("", []sdn.Interface{in})
}

// SDNPPPInstalled reports whether pppd (package ppp) is present.
func SDNPPPInstalled() bool { return binaryPresent("/usr/sbin/pppd") || binaryPresent("pppd") }
