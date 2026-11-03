package geoip

import (
	"bytes"
	"encoding/binary"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// writeTestDB builds a tiny .mmdb: each prefix gets its record. ipVersion 6
// stores IPv4 under ::/96 like DB-IP does.
func writeTestDB(t *testing.T, ipVersion, recordSize int, dbType string, recs map[string]map[string]any) string {
	t.Helper()
	type node struct{ kid, leaf [2]int }
	nodes := []node{{kid: [2]int{-1, -1}, leaf: [2]int{-1, -1}}}
	var data bytes.Buffer
	var offsets []int
	keys := make([]string, 0, len(recs))
	for k := range recs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := netip.MustParsePrefix(k)
		offsets = append(offsets, data.Len())
		encode(&data, recs[k])
		var bits []int
		if ipVersion == 6 {
			bits = make([]int, 96)
		}
		a := p.Addr().As4()
		for i := 0; i < p.Bits(); i++ {
			bits = append(bits, int(a[i/8]>>(7-i%8))&1)
		}
		n := 0
		for i, b := range bits {
			if i == len(bits)-1 {
				nodes[n].leaf[b] = len(offsets) - 1
				break
			}
			if nodes[n].kid[b] < 0 {
				nodes = append(nodes, node{kid: [2]int{-1, -1}, leaf: [2]int{-1, -1}})
				nodes[n].kid[b] = len(nodes) - 1
			}
			n = nodes[n].kid[b]
		}
	}
	N := uint32(len(nodes))
	val := func(nd node, side int) uint32 {
		switch {
		case nd.leaf[side] >= 0:
			return N + 16 + uint32(offsets[nd.leaf[side]])
		case nd.kid[side] >= 0:
			return uint32(nd.kid[side])
		}
		return N
	}
	var tree bytes.Buffer
	for _, nd := range nodes {
		l, r := val(nd, 0), val(nd, 1)
		switch recordSize {
		case 24:
			tree.Write([]byte{byte(l >> 16), byte(l >> 8), byte(l), byte(r >> 16), byte(r >> 8), byte(r)})
		case 28:
			tree.Write([]byte{byte(l >> 16), byte(l >> 8), byte(l), byte((l>>24)<<4 | (r>>24)&0x0F), byte(r >> 16), byte(r >> 8), byte(r)})
		default:
			var b [8]byte
			binary.BigEndian.PutUint32(b[:4], l)
			binary.BigEndian.PutUint32(b[4:], r)
			tree.Write(b[:])
		}
	}
	var out bytes.Buffer
	out.Write(tree.Bytes())
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.Write(metaMarker)
	encode(&out, map[string]any{"node_count": uint32(N), "record_size": uint16(recordSize), "ip_version": uint16(ipVersion),
		"database_type": dbType, "build_epoch": uint64(1761609600)})
	p := filepath.Join(t.TempDir(), "test.mmdb")
	if err := os.WriteFile(p, out.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func ctrl(buf *bytes.Buffer, typ, size int) {
	field, extra := size, []byte(nil)
	if size >= 29 { // sizes 29..284: field 29 + one extra byte
		field, extra = 29, []byte{byte(size - 29)}
	}
	if typ <= 7 {
		buf.WriteByte(byte(typ<<5 | field))
	} else {
		buf.WriteByte(byte(field))
		buf.WriteByte(byte(typ - 7))
	}
	buf.Write(extra)
}

func encode(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case string:
		ctrl(buf, 2, len(x))
		buf.WriteString(x)
	case float64:
		ctrl(buf, 3, 8)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], math.Float64bits(x))
		buf.Write(b[:])
	case uint16:
		ctrl(buf, 5, 2)
		buf.Write([]byte{byte(x >> 8), byte(x)})
	case uint32:
		ctrl(buf, 6, 4)
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], x)
		buf.Write(b[:])
	case uint64:
		ctrl(buf, 9, 8)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], x)
		buf.Write(b[:])
	case map[string]any:
		ks := make([]string, 0, len(x))
		for k := range x {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		ctrl(buf, 7, len(x))
		for _, k := range ks {
			encode(buf, k)
			encode(buf, x[k])
		}
	case []any:
		ctrl(buf, 11, len(x))
		for _, e := range x {
			encode(buf, e)
		}
	}
}

func cityRec(cc, country, city string, lat, lon float64) map[string]any {
	return map[string]any{
		"country":  map[string]any{"iso_code": cc, "names": map[string]any{"en": country}},
		"city":     map[string]any{"names": map[string]any{"en": city}},
		"location": map[string]any{"latitude": lat, "longitude": lon},
	}
}

func TestLookup_TreeShapes(t *testing.T) {
	for _, ipv := range []int{4, 6} {
		for _, rs := range []int{24, 28, 32} {
			p := writeTestDB(t, ipv, rs, "DBIP-City-Lite", map[string]map[string]any{
				"89.160.20.0/24": cityRec("SE", "Sweden", "Stockholm", 59.33, 18.07),
				"81.2.69.0/24":   cityRec("GB", "United Kingdom", "London", 51.5, -0.12),
			})
			db, err := Open(p)
			if err != nil {
				t.Fatalf("ipv%d rs%d: %v", ipv, rs, err)
			}
			rec, ok, err := db.Lookup(netip.MustParseAddr("89.160.20.112"))
			if err != nil || !ok {
				t.Fatalf("ipv%d rs%d: lookup %v %v", ipv, rs, ok, err)
			}
			if rec["country"].(map[string]any)["iso_code"] != "SE" || rec["location"].(map[string]any)["latitude"].(float64) != 59.33 {
				t.Fatalf("ipv%d rs%d: wrong record %v", ipv, rs, rec)
			}
			if _, ok, _ := db.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
				t.Fatalf("ipv%d rs%d: 8.8.8.8 must not be found", ipv, rs)
			}
			db.Close()
		}
	}
}

func TestNetworksWalk(t *testing.T) {
	p := writeTestDB(t, 6, 28, "DBIP-Country-Lite", map[string]map[string]any{
		"89.160.20.0/24": {"country": map[string]any{"iso_code": "SE"}},
		"89.160.21.0/24": {"country": map[string]any{"iso_code": "SE"}},
		"81.2.69.0/24":   {"country": map[string]any{"iso_code": "GB"}},
	})
	db, _ := Open(p)
	defer db.Close()
	var got []string
	_ = db.Networks(func(pf netip.Prefix, rec map[string]any) bool {
		got = append(got, pf.String()+"="+rec["country"].(map[string]any)["iso_code"].(string))
		return true
	})
	want := "81.2.69.0/24=GB,89.160.20.0/24=SE,89.160.21.0/24=SE"
	sort.Strings(got)
	if s := join(got); s != want {
		t.Fatalf("got %s", s)
	}
}

func join(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ","
		}
		out += x
	}
	return out
}

func TestResolver(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, ipv int, recs map[string]map[string]any) {
		b, _ := os.ReadFile(writeTestDB(t, ipv, 24, name, recs))
		_ = os.WriteFile(filepath.Join(dir, name), b, 0644)
	}
	write("dbip-country-lite.mmdb", 6, map[string]map[string]any{
		"89.160.20.0/24": {"country": map[string]any{"iso_code": "SE", "names": map[string]any{"en": "Sweden"}}},
		"89.160.21.0/24": {"country": map[string]any{"iso_code": "SE", "names": map[string]any{"en": "Sweden"}}},
		"81.2.69.0/24":   {"country": map[string]any{"iso_code": "GB", "names": map[string]any{"en": "United Kingdom"}}},
	})
	write("dbip-city-lite.mmdb", 6, map[string]map[string]any{"89.160.20.0/24": cityRec("SE", "Sweden", "Stockholm", 59.33, 18.07)})
	write("dbip-asn-lite.mmdb", 6, map[string]map[string]any{"89.160.20.0/24": {"autonomous_system_number": uint32(2119), "autonomous_system_organization": "Telenor"}})
	r := NewResolver(dir)
	defer r.Close()
	in := r.Lookup(netip.MustParseAddr("89.160.20.112"))
	if in.CountryCode != "SE" || in.Country != "Sweden" || in.City != "Stockholm" || in.Lat != 59.33 || in.ASN != 2119 || in.ASOrg != "Telenor" {
		t.Fatalf("info %+v", in)
	}
	if r.Lookup(netip.MustParseAddr("10.1.2.3")).CountryCode != "" {
		t.Fatal("private addresses are never looked up")
	}
	cidrs, err := r.CountryCIDRs("SE")
	if err != nil || join(cidrs) != "89.160.20.0/23" {
		t.Fatalf("SE cidrs %v %v (adjacent /24s must merge)", cidrs, err)
	}
	if _, err := NewResolver(t.TempDir()).CountryCIDRs("SE"); err == nil {
		t.Fatal("missing country DB must be an error, never an empty set")
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "89.160.20.112": true, "10.1.1.1": false, "172.16.5.5": false, "192.168.2.130": false,
		"100.64.1.1": false, "127.0.0.1": false, "169.254.1.1": false, "224.0.0.22": false, "0.0.0.0": false,
		"255.255.255.255": false, "192.0.2.1": false, "198.18.0.1": false,
	} {
		if got := IsPublic(netip.MustParseAddr(ip)); got != want {
			t.Errorf("IsPublic(%s) = %v", ip, got)
		}
	}
}

// A corrupt database with a pointer that points at itself must fail, not
// recurse until the stack overflows.
func TestDecodePointerCycle(t *testing.T) {
	d := &decoder{b: []byte{0x20, 0x00}} // pointer (type 1, size 0) to offset 0 = itself
	if _, _, err := d.decode(0); err == nil {
		t.Fatal("pointer cycle not detected")
	}
}
