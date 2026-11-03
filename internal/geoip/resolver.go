package geoip

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"net/netip"
	"path/filepath"
	"sort"
	"sync"
)

// File names of the DB-IP Lite databases inside the geo directory.
const (
	CountryFile = "dbip-country-lite.mmdb"
	CityFile    = "dbip-city-lite.mmdb"
	ASNFile     = "dbip-asn-lite.mmdb"
)

// Info is what the traffic statistics keep about a public address.
type Info struct {
	CountryCode string  `json:"cc,omitempty"`
	Country     string  `json:"country,omitempty"`
	City        string  `json:"city,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	ASN         uint    `json:"asn,omitempty"`
	ASOrg       string  `json:"as_org,omitempty"`
}

// Resolver answers lookups from whichever of the three databases exist.
type Resolver struct {
	country, city, asn *DB
	mu                 sync.Mutex
	cache              map[netip.Addr]Info
	cidrs              map[string][]string // country code → merged CIDRs (built once)
}

func NewResolver(dir string) *Resolver {
	return NewResolverFiles(filepath.Join(dir, CountryFile), filepath.Join(dir, CityFile), filepath.Join(dir, ASNFile))
}

// NewResolverFiles opens databases by path: DB-IP Lite and MaxMind GeoLite2
// share the same record layout.
func NewResolverFiles(country, city, asn string) *Resolver {
	r := &Resolver{cache: map[netip.Addr]Info{}}
	r.country, _ = Open(country)
	r.city, _ = Open(city)
	r.asn, _ = Open(asn)
	return r
}

func (r *Resolver) Close() {
	for _, d := range []*DB{r.country, r.city, r.asn} {
		if d != nil {
			d.Close()
		}
	}
}

// HasCountry reports whether country data (for rules) is available.
func (r *Resolver) HasCountry() bool { return r != nil && (r.country != nil || r.city != nil) }

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[k]
	}
	s, _ := cur.(string)
	return s
}

func num(m map[string]any, path ...string) float64 {
	var cur any = m
	for _, k := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0
		}
		cur = mm[k]
	}
	switch x := cur.(type) {
	case float64:
		return x
	case float32:
		return float64(x)
	}
	return 0
}

// Lookup returns what is known about ip; private and special addresses are
// never looked up.
func (r *Resolver) Lookup(ip netip.Addr) Info {
	if r == nil || !IsPublic(ip) {
		return Info{}
	}
	r.mu.Lock()
	if in, ok := r.cache[ip]; ok {
		r.mu.Unlock()
		return in
	}
	r.mu.Unlock()
	var in Info
	if r.city != nil {
		if rec, ok, _ := r.city.Lookup(ip); ok {
			in.CountryCode, in.Country = str(rec, "country", "iso_code"), str(rec, "country", "names", "en")
			if in.CountryCode == "" { // GeoLite2 leaves some networks (anycast, satellite) to their registered country
				in.CountryCode, in.Country = str(rec, "registered_country", "iso_code"), str(rec, "registered_country", "names", "en")
			}
			in.City = str(rec, "city", "names", "en")
			in.Lat, in.Lon = num(rec, "location", "latitude"), num(rec, "location", "longitude")
		}
	}
	if in.CountryCode == "" && r.country != nil {
		if rec, ok, _ := r.country.Lookup(ip); ok {
			in.CountryCode, in.Country = str(rec, "country", "iso_code"), str(rec, "country", "names", "en")
			if in.CountryCode == "" {
				in.CountryCode, in.Country = str(rec, "registered_country", "iso_code"), str(rec, "registered_country", "names", "en")
			}
		}
	}
	if r.asn != nil {
		if rec, ok, _ := r.asn.Lookup(ip); ok {
			in.ASN = uint(asUint(rec["autonomous_system_number"]))
			in.ASOrg, _ = rec["autonomous_system_organization"].(string)
		}
	}
	r.mu.Lock()
	if len(r.cache) > 4096 {
		r.cache = map[netip.Addr]Info{}
	}
	r.cache[ip] = in
	r.mu.Unlock()
	return in
}

// CountryCIDRs returns the merged IPv4 networks of a country, for nftables
// country sets. A missing database is an error: a country rule must never
// silently match nothing.
func (r *Resolver) CountryCIDRs(cc string) ([]string, error) {
	if r == nil {
		return nil, errors.New("country database not available — download it from Firewall → Traffic first")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cidrs == nil {
		src := r.country
		if src == nil {
			src = r.city
		}
		if src == nil {
			return nil, errors.New("country database not available — download it from Firewall → Traffic first")
		}
		ranges := map[string][][2]uint32{}
		err := src.Networks(func(p netip.Prefix, rec map[string]any) bool {
			c := str(rec, "country", "iso_code")
			if c == "" {
				return true
			}
			a := p.Addr().As4()
			start := binary.BigEndian.Uint32(a[:])
			end := start | (1<<(32-p.Bits()) - 1)
			if p.Bits() == 0 {
				end = ^uint32(0)
			}
			ranges[c] = append(ranges[c], [2]uint32{start, end})
			return true
		})
		if err != nil {
			return nil, err
		}
		r.cidrs = map[string][]string{}
		for c, rs := range ranges {
			r.cidrs[c] = rangesToCIDRs(rs)
		}
	}
	return r.cidrs[cc], nil
}

// rangesToCIDRs merges overlapping/adjacent ranges and splits them into the
// fewest CIDR blocks.
func rangesToCIDRs(rs [][2]uint32) []string {
	sort.Slice(rs, func(i, j int) bool { return rs[i][0] < rs[j][0] })
	var merged [][2]uint32
	for _, r := range rs {
		if n := len(merged); n > 0 && uint64(r[0]) <= uint64(merged[n-1][1])+1 {
			if r[1] > merged[n-1][1] {
				merged[n-1][1] = r[1]
			}
			continue
		}
		merged = append(merged, r)
	}
	var out []string
	for _, m := range merged {
		start, end := uint64(m[0]), uint64(m[1])
		for start <= end {
			// largest block aligned at start and not past end
			size := 32
			if start != 0 {
				size = bits.TrailingZeros32(uint32(start))
			}
			for size > 0 && start+(1<<size)-1 > end {
				size--
			}
			var a [4]byte
			binary.BigEndian.PutUint32(a[:], uint32(start))
			out = append(out, netip.PrefixFrom(netip.AddrFrom4(a), 32-size).String())
			start += 1 << size
		}
	}
	return out
}

var nonPublic = func() []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return ps
}()

// IsPublic reports whether ip is a routable public IPv4 address.
func IsPublic(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
