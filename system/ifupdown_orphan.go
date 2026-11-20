package system

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

// An /etc/network/interfaces that nothing applies (ifupdown not installed) is
// not harmless on a NetworkManager host: NetworkManager's ifupdown plugin —
// on by default on Ubuntu with "[ifupdown] managed=false" — stops managing
// every NIC the file names at its next reload or boot, and that NIC loses its
// address. The bridge step of 6.11.17 and earlier wrote such a file on Ubuntu
// hosts without ifupdown (issue #187), and the next reboot, or the netplan
// apply of "Configure Static IP", took the host offline.

const orphanIfupdownPath = "/etc/network/interfaces"

var orphanStanzaRe = regexp.MustCompile(`(?m)^\s*(?:iface|auto|allow-hotplug)\s+([^\s#]+)`)

// ifupdownFileNICs lists the interfaces an interfaces(5) file names, lo excepted.
func ifupdownFileNICs(content string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range orphanStanzaRe.FindAllStringSubmatch(content, -1) {
		for _, n := range strings.Fields(m[1]) {
			if n != "lo" && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out
}

// znasBridgeLeftover: the file holds a bridge stanza the ZNAS bridge step writes.
func znasBridgeLeftover(content string) bool {
	return strings.Contains(content, "bridge_ports") && regexp.MustCompile(`(?m)^\s*iface\s+vmbr\d+\s`).MatchString(content)
}

// orphanIfupdownAction decides whether the file must be cleared: nothing
// applies it, NetworkManager runs, and it names NICs — the one about to be
// configured (iface != "") or, with iface == "", a bridge left by ZNAS. A
// file a user wrote on purpose (no ZNAS bridge) is left alone at start-up.
func orphanIfupdownAction(content, iface string, ifupInstalled, nmActive bool) bool {
	if ifupInstalled || !nmActive {
		return false
	}
	nics := ifupdownFileNICs(content)
	if len(nics) == 0 {
		return false
	}
	if iface == "" {
		return znasBridgeLeftover(content)
	}
	for _, n := range nics {
		if n == iface {
			return true
		}
	}
	return znasBridgeLeftover(content)
}

// RepairOrphanIfupdownFile moves such a file aside (timestamped copy) and
// leaves a loopback-only one, so NetworkManager manages the NICs again. It
// does not reload NetworkManager: the change takes effect at its next reload
// or boot — exactly when the stale file would have cut the host off. Returns
// whether it changed anything.
func RepairOrphanIfupdownFile(iface string, logf func(string)) (bool, error) {
	data, err := os.ReadFile(orphanIfupdownPath)
	if err != nil {
		return false, nil
	}
	if !orphanIfupdownAction(string(data), iface, ifupdownInstalled(), networkManagerActive()) {
		return false, nil
	}
	backup := fmt.Sprintf("%s.pre-znas-%d", orphanIfupdownPath, time.Now().Unix())
	if err := writeRoot(backup, data, 0o644); err != nil {
		return false, fmt.Errorf("back up %s: %w", orphanIfupdownPath, err)
	}
	body := "# Cleared by ZNAS: ifupdown is not installed, so nothing applied this file,\n" +
		"# and NetworkManager stopped managing every interface it listed.\n" +
		"# The previous content is in " + backup + ".\n\n" +
		"auto lo\niface lo inet loopback\n"
	if err := writeRoot(orphanIfupdownPath, []byte(body), 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", orphanIfupdownPath, err)
	}
	msg := "Cleared " + orphanIfupdownPath + " (named " + strings.Join(ifupdownFileNICs(string(data)), ", ") +
		" but ifupdown is not installed, so NetworkManager would drop them); previous content in " + backup
	if logf != nil {
		logf(msg)
	} else {
		log.Print(msg)
	}
	return true, nil
}
