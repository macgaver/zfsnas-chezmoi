package handlers

import (
	"testing"

	"zfsnas/system"
)

// TestFoldShareClients verifies that a share client whose source IP matches a
// hosted VM/container is folded into that consumer's ClientOf (no remote box),
// while unmatched clients fall through to a remote box.
func TestFoldShareClients(t *testing.T) {
	consumers := []mapConsumer{
		{ID: "smb:media", Type: "smb", Name: "media"},
		{ID: "nfs:1", Type: "nfs", Name: "/tank/exports"},
		{ID: "vm:plex", Type: "vm", Name: "plex", IP: "10.0.0.20"},
		{ID: "container:web", Type: "container", Name: "web", IP: "10.0.0.30"},
		{ID: "vm:noip", Type: "vm", Name: "noip"}, // running but no detected IP
	}
	clients := []pendingShareClient{
		{consumerID: "smb:media", cl: system.ShareClient{IP: "10.0.0.20"}},                   // → vm:plex
		{consumerID: "nfs:1", cl: system.ShareClient{IP: "10.0.0.20"}},                       // → vm:plex (2nd share)
		{consumerID: "smb:media", cl: system.ShareClient{IP: "10.0.0.30"}},                   // → container:web
		{consumerID: "smb:media", cl: system.ShareClient{IP: "10.0.0.20"}},                   // dup → no double entry
		{consumerID: "smb:media", cl: system.ShareClient{IP: "192.168.1.5", FQDN: "laptop"}}, // → remote
	}

	var remotes []string
	addRemote := func(key, label, ip, consumerID string) {
		remotes = append(remotes, key+"|"+label+"|"+consumerID)
	}

	foldShareClients(consumers, clients, addRemote)

	plex := consumers[2]
	if got := plex.ClientOf; len(got) != 2 || got[0] != "smb:media" || got[1] != "nfs:1" {
		t.Fatalf("vm:plex ClientOf = %v, want [smb:media nfs:1] (deduped)", got)
	}
	web := consumers[3]
	if len(web.ClientOf) != 1 || web.ClientOf[0] != "smb:media" {
		t.Fatalf("container:web ClientOf = %v, want [smb:media]", web.ClientOf)
	}
	if len(remotes) != 1 {
		t.Fatalf("expected exactly 1 remote box, got %v", remotes)
	}
	if remotes[0] != "client:192.168.1.5|laptop|smb:media" {
		t.Fatalf("unexpected remote: %q", remotes[0])
	}
}

// TestFoldShareClientsNoVMs confirms that with no matching VMs every client
// becomes a remote box (the pre-existing behaviour).
func TestFoldShareClientsNoVMs(t *testing.T) {
	consumers := []mapConsumer{{ID: "smb:media", Type: "smb"}}
	clients := []pendingShareClient{
		{consumerID: "smb:media", cl: system.ShareClient{IP: "10.0.0.9"}},
	}
	n := 0
	foldShareClients(consumers, clients, func(_, _, _, _ string) { n++ })
	if n != 1 {
		t.Fatalf("expected 1 remote box, got %d", n)
	}
	if consumers[0].ClientOf != nil {
		t.Fatalf("share consumer should have no ClientOf, got %v", consumers[0].ClientOf)
	}
}
