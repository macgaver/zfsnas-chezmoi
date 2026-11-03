// Package oui names the maker of a network card from its MAC address.
//
// oui.tsv.gz holds the IEEE registries (MA-L, MA-M, MA-S and IAB) as sorted
// "prefix<TAB>organization" lines, the prefix being 6, 7 or 9 lowercase hex
// digits. It comes from Debian's ieee-data package and travels in the binary,
// so lookups work without Internet access.
package oui

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"strings"
	"sync"
)

//go:embed oui.tsv.gz
var data []byte

// Virtual cards: prefixes software generates, not in the registries.
var virtual = map[string]string{"10666a": "Incus (virtual network card)", "525400": "QEMU (virtual network card)"}

var load = sync.OnceValue(func() map[string]string {
	m := map[string]string{}
	z, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return m
	}
	b, err := io.ReadAll(z)
	if err != nil {
		return m
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "\t"); ok {
			m[k] = v
		}
	}
	return m
})

func digits(mac string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(mac) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r != ':' && r != '-' && r != '.':
			return ""
		}
	}
	return b.String()
}

// Hypervisor: the MAC comes from a prefix virtual machines and containers use,
// so it may be an instance of a ZNAS server. Proxmox's is here for VMs imported
// from it, which keep their address.
func Hypervisor(mac string) bool {
	d := digits(mac)
	if len(d) != 12 {
		return false
	}
	switch d[:6] {
	case "10666a", "00163e", "525400", "bc2411":
		return true
	}
	return false
}

// Vendor returns the organization a MAC address was assigned to, "" when
// unknown. The longest registered prefix wins.
func Vendor(mac string) string {
	d := digits(mac)
	if len(d) != 12 {
		return ""
	}
	if v := virtual[d[:6]]; v != "" {
		return v
	}
	m := load()
	for _, n := range []int{9, 7, 6} {
		if v := m[d[:n]]; v != "" {
			return v
		}
	}
	return ""
}

// Private reports a locally administered address: chosen by the device or its
// software (phones' private Wi-Fi addresses), so it names no maker.
func Private(mac string) bool {
	d := digits(mac)
	if len(d) != 12 {
		return false
	}
	return strings.ContainsRune("2367abef", rune(d[1]))
}
