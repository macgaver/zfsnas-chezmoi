package system

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/sdn"
)

// SDNHostName is what is known about one address: its inside name (this
// server, an Incus instance, a DHCP lease) and its reverse-DNS name.
type SDNHostName struct {
	Name string `json:"name,omitempty"`
	FQDN string `json:"fqdn,omitempty"`
}

var sdnLookupAddr = net.DefaultResolver.LookupAddr

const (
	sdnPTRTimeout = 1500 * time.Millisecond
	sdnPTRKeep    = 30 * time.Minute // found
	sdnPTRKeepNo  = 5 * time.Minute  // no PTR record (or no answer in time)
)

type sdnPTRCache struct {
	mu sync.Mutex
	m  map[string]sdnPTREntry
}

type sdnPTREntry struct {
	fqdn string
	at   time.Time
}

func (c *sdnPTRCache) reset() { c.mu.Lock(); c.m = map[string]sdnPTREntry{}; c.mu.Unlock() }

var sdnHostNameCache = &sdnPTRCache{m: map[string]sdnPTREntry{}}

// SDNHostNames answers for up to 16 addresses (the rest is ignored), the
// reverse-DNS lookups in parallel.
func SDNHostNames(c *sdn.Config, ips []string, now time.Time) map[string]SDNHostName {
	if c == nil {
		c = &sdn.Config{}
	}
	leases := map[string]string{}
	for _, l := range SDNDHCPLeases(c) {
		if l.Hostname != "" {
			leases[l.IP] = l.Hostname
		}
	}
	out := map[string]SDNHostName{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, s := range ips {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		s = a.String()
		mu.Lock()
		_, dup := out[s]
		n := len(out)
		mu.Unlock()
		if dup || n >= 16 {
			continue
		}
		var h SDNHostName
		switch {
		case sdnIDSLocal(a):
			h.Name = "This ZNAS"
		case leases[s] != "":
			h.Name = leases[s]
		default:
			sdnTC.mu.Lock()
			h.Name = sdnTC.names[a]
			sdnTC.mu.Unlock()
		}
		sdnHostNameCache.mu.Lock()
		e, ok := sdnHostNameCache.m[s]
		sdnHostNameCache.mu.Unlock()
		keep := sdnPTRKeepNo
		if e.fqdn != "" {
			keep = sdnPTRKeep
		}
		cached := ok && now.Sub(e.at) < keep
		if cached {
			h.FQDN = e.fqdn
		}
		mu.Lock()
		out[s] = h
		mu.Unlock()
		if cached {
			continue
		}
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), sdnPTRTimeout)
			names, _ := sdnLookupAddr(ctx, s)
			cancel()
			fqdn := ""
			if len(names) > 0 {
				fqdn = strings.TrimSuffix(names[0], ".")
			}
			sdnHostNameCache.mu.Lock()
			if len(sdnHostNameCache.m) > 8192 {
				sdnHostNameCache.m = map[string]sdnPTREntry{}
			}
			sdnHostNameCache.m[s] = sdnPTREntry{fqdn: fqdn, at: now}
			sdnHostNameCache.mu.Unlock()
			mu.Lock()
			h := out[s]
			h.FQDN = fqdn
			out[s] = h
			mu.Unlock()
		}(s)
	}
	wg.Wait()
	return out
}
