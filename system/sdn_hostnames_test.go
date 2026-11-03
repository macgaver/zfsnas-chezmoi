package system

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Names shown for the addresses of an IDS alert: the inside name (Incus
// instance, DHCP lease) and the reverse-DNS name, cached.
func TestSDNHostNames(t *testing.T) {
	dir := t.TempDir()
	oldLease, oldPTR, oldLocal := sdnLegacyLeasePath, sdnLookupAddr, sdnIDSLocal
	t.Cleanup(func() { sdnLegacyLeasePath, sdnLookupAddr, sdnIDSLocal = oldLease, oldPTR, oldLocal })
	sdnLegacyLeasePath = filepath.Join(dir, "leases")
	os.WriteFile(sdnLegacyLeasePath, []byte("1900000000 aa:bb:cc:dd:ee:ff 10.97.8.20 laptop-anne *\n"), 0644)
	pub := netip.MustParseAddr("69.156.169.77")
	sdnIDSLocal = func(a netip.Addr) bool { return a == pub }
	var calls atomic.Int32
	sdnLookupAddr = func(ctx context.Context, ip string) ([]string, error) {
		calls.Add(1)
		switch ip {
		case "69.156.169.77":
			return []string{"bas1-montreal.dsl.bell.ca."}, nil
		case "10.97.8.20":
			return []string{"laptop-anne.lan."}, nil
		}
		return nil, errors.New("no PTR")
	}
	sdnTC.mu.Lock()
	sdnTC.names = map[netip.Addr]string{netip.MustParseAddr("10.97.8.10"): "web01"}
	sdnTC.mu.Unlock()
	t.Cleanup(func() { sdnTC.mu.Lock(); sdnTC.names = nil; sdnTC.mu.Unlock() })
	sdnHostNameCache.reset()

	now := time.Unix(1_800_000_000, 0)
	got := SDNHostNames(nil, []string{"69.156.169.77", "10.97.8.20", "10.97.8.10", "8.8.4.4", "not-an-ip"}, now)
	if g := got["69.156.169.77"]; g.FQDN != "bas1-montreal.dsl.bell.ca" || g.Name != "This ZNAS" {
		t.Fatalf("public: %+v", g)
	}
	if g := got["10.97.8.20"]; g.Name != "laptop-anne" || g.FQDN != "laptop-anne.lan" {
		t.Fatalf("lease: %+v", g)
	}
	if g := got["10.97.8.10"]; g.Name != "web01" || g.FQDN != "" {
		t.Fatalf("instance: %+v", g)
	}
	if _, ok := got["not-an-ip"]; ok {
		t.Fatal("garbage answered")
	}
	n := calls.Load()
	SDNHostNames(nil, []string{"69.156.169.77", "8.8.4.4"}, now.Add(time.Minute))
	if calls.Load() != n {
		t.Fatalf("PTR not cached (failures too): %d → %d", n, calls.Load())
	}
}
