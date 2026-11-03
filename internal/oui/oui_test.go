package oui

import "testing"

func TestVendor(t *testing.T) {
	for mac, want := range map[string]string{
		"10:E9:92:00:00:01": "INGRAM MICRO SERVICES",        // MA-L, upper case
		"10-e9-92-00-00-01": "INGRAM MICRO SERVICES",        // other separator
		"8c:1f:64:af:a0:01": "DATA ELECTRONIC DEVICES, INC", // MA-S beats the registry's own block
		"10:66:6a:d1:d9:52": "Incus (virtual network card)",
		"not a mac":         "",
		"":                  "",
	} {
		if got := Vendor(mac); got != want {
			t.Errorf("Vendor(%q) = %q, want %q", mac, got, want)
		}
	}
}

func TestPrivate(t *testing.T) {
	for mac, want := range map[string]bool{
		"10:e9:92:00:00:01": false,
		"da:a1:19:00:00:01": true,
		"02:00:00:00:00:01": true,
		"06:00:00:00:00:01": true,
		"0a:00:00:00:00:01": true,
		"0e:00:00:00:00:01": true,
		"":                  false,
	} {
		if got := Private(mac); got != want {
			t.Errorf("Private(%q) = %v, want %v", mac, got, want)
		}
	}
}
