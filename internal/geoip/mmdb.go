// Package geoip reads MaxMind-format (.mmdb) databases — the format of the
// DB-IP Lite country/city/ASN databases the Firewall's traffic statistics and
// country rules use — without any third-party dependency. Only what the
// feature needs is implemented: IPv4 lookups (in IPv4 or IPv6 trees) and an
// IPv4 network walk to build per-country address sets.
package geoip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
)

var metaMarker = []byte("\xab\xcd\xefMaxMind.com")

// DB is an open .mmdb file. Lookups use ReadAt: the file is not loaded into
// memory (the city database is ~130 MB).
type DB struct {
	f          *os.File
	nodeCount  uint32
	recordSize int
	ipVersion  int
	treeSize   int64
	dataStart  int64
	ipv4Start  uint32
	tree       []byte // whole search tree, loaded by Networks (fast walk)
	Type       string
	BuildEpoch uint64
}

func Open(path string) (*DB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	// Metadata is in the last 128 KiB.
	n := fi.Size()
	tail := int64(128 << 10)
	if tail > n {
		tail = n
	}
	buf := make([]byte, tail)
	if _, err := f.ReadAt(buf, n-tail); err != nil {
		f.Close()
		return nil, err
	}
	i := bytes.LastIndex(buf, metaMarker)
	if i < 0 {
		f.Close()
		return nil, errors.New("not a MaxMind DB file (no metadata marker)")
	}
	md := &decoder{b: buf[i+len(metaMarker):]}
	v, _, err := md.decode(0)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("metadata: %w", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		f.Close()
		return nil, errors.New("metadata is not a map")
	}
	d := &DB{f: f}
	d.nodeCount = uint32(asUint(m["node_count"]))
	d.recordSize = int(asUint(m["record_size"]))
	d.ipVersion = int(asUint(m["ip_version"]))
	d.Type, _ = m["database_type"].(string)
	d.BuildEpoch = asUint(m["build_epoch"])
	switch d.recordSize {
	case 24, 28, 32:
	default:
		f.Close()
		return nil, fmt.Errorf("unsupported record size %d", d.recordSize)
	}
	d.treeSize = int64(d.recordSize*2/8) * int64(d.nodeCount)
	d.dataStart = d.treeSize + 16
	if d.ipVersion == 6 {
		// IPv4 lives at ::a.b.c.d: follow 96 zero bits.
		node := uint32(0)
		for i := 0; i < 96 && node < d.nodeCount; i++ {
			l, _, err := d.node(node)
			if err != nil {
				f.Close()
				return nil, err
			}
			node = l
		}
		d.ipv4Start = node
	}
	return d, nil
}

func (d *DB) Close() error { return d.f.Close() }

func asUint(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case uint16:
		return uint64(x)
	case int32:
		return uint64(x)
	}
	return 0
}

// node returns the left and right records of a tree node.
func (d *DB) node(n uint32) (uint32, uint32, error) {
	size := d.recordSize * 2 / 8
	var b []byte
	if d.tree != nil {
		b = d.tree[int64(n)*int64(size) : int64(n+1)*int64(size)]
	} else {
		b = make([]byte, size)
		if _, err := d.f.ReadAt(b, int64(n)*int64(size)); err != nil {
			return 0, 0, err
		}
	}
	switch d.recordSize {
	case 24:
		return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), uint32(b[3])<<16 | uint32(b[4])<<8 | uint32(b[5]), nil
	case 28:
		l := uint32(b[3]&0xF0)<<20 | uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
		r := uint32(b[3]&0x0F)<<24 | uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
		return l, r, nil
	default:
		return binary.BigEndian.Uint32(b[0:4]), binary.BigEndian.Uint32(b[4:8]), nil
	}
}

// Lookup returns the decoded record for an IPv4 address.
func (d *DB) Lookup(ip netip.Addr) (map[string]any, bool, error) {
	if !ip.Is4() {
		return nil, false, nil
	}
	a := ip.As4()
	node := d.ipv4Start
	for i := 0; i < 32 && node < d.nodeCount; i++ {
		l, r, err := d.node(node)
		if err != nil {
			return nil, false, err
		}
		if a[i/8]&(0x80>>(i%8)) == 0 {
			node = l
		} else {
			node = r
		}
	}
	return d.record(node)
}

func (d *DB) record(rec uint32) (map[string]any, bool, error) {
	if rec <= d.nodeCount {
		return nil, false, nil
	}
	off := int64(rec-d.nodeCount) - 16
	v, err := d.decodeAt(off)
	if err != nil {
		return nil, false, err
	}
	m, _ := v.(map[string]any)
	return m, m != nil, nil
}

// decodeAt decodes one value at a data-section offset. It reads a window
// big enough for any record the Lite databases hold and grows it on need.
func (d *DB) decodeAt(off int64) (any, error) { return d.decodeAtDepth(off, 0) }

func (d *DB) decodeAtDepth(off int64, depth int) (any, error) {
	for win := int64(4096); ; win *= 4 {
		b := make([]byte, win)
		n, err := d.f.ReadAt(b, d.dataStart+off)
		if n == 0 && err != nil {
			return nil, err
		}
		dec := &decoder{b: b[:n], base: off, db: d, depth: depth}
		v, _, derr := dec.decode(0)
		if derr == nil {
			return v, nil
		}
		if !errors.Is(derr, errShort) || int64(n) < win {
			return nil, derr
		}
	}
}

// Networks walks the IPv4 part of the tree and calls fn for every network
// that has data. Returning false stops the walk.
func (d *DB) Networks(fn func(p netip.Prefix, rec map[string]any) bool) error {
	type item struct {
		node uint32
		ip   uint32
		bits int
	}
	// A private copy of the tree for the walk: lookups running at the same
	// time keep reading the file (no shared mutable state).
	walker := d
	if d.treeSize < 256<<20 {
		t := make([]byte, d.treeSize)
		if _, err := d.f.ReadAt(t, 0); err != nil {
			return err
		}
		cp := *d
		cp.tree = t
		walker = &cp
	}
	stack := []item{{d.ipv4Start, 0, 0}}
	cache := map[uint32]map[string]any{}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if it.node >= d.nodeCount {
			if it.node == d.nodeCount {
				continue
			}
			rec, ok := cache[it.node]
			if !ok {
				var err error
				rec, _, err = d.record(it.node)
				if err != nil {
					return err
				}
				cache[it.node] = rec
			}
			var a [4]byte
			binary.BigEndian.PutUint32(a[:], it.ip)
			if !fn(netip.PrefixFrom(netip.AddrFrom4(a), it.bits), rec) {
				return nil
			}
			continue
		}
		if it.bits >= 32 {
			continue
		}
		l, r, err := walker.node(it.node)
		if err != nil {
			return err
		}
		stack = append(stack, item{r, it.ip | 1<<(31-it.bits), it.bits + 1}, item{l, it.ip, it.bits + 1})
	}
	return nil
}

// ── data section decoder ──────────────────────────────────────────────────

var errShort = errors.New("short buffer")

type decoder struct {
	b     []byte
	base  int64 // data-section offset of b[0] (for pointers)
	db    *DB
	depth int // pointer nesting: a corrupt file must not recurse forever
}

func (dc *decoder) need(i, n int) error {
	if i+n > len(dc.b) {
		return errShort
	}
	return nil
}

func (dc *decoder) decode(i int) (any, int, error) {
	if err := dc.need(i, 1); err != nil {
		return nil, 0, err
	}
	ctrl := dc.b[i]
	i++
	typ := int(ctrl >> 5)
	if typ == 1 { // pointer
		if dc.depth > 32 {
			return nil, 0, errors.New("pointer nesting too deep (corrupt database)")
		}
		dc.depth++
		defer func() { dc.depth-- }()
		ss := int(ctrl>>3) & 3
		vvv := uint32(ctrl & 7)
		var p uint32
		switch ss {
		case 0:
			if err := dc.need(i, 1); err != nil {
				return nil, 0, err
			}
			p = vvv<<8 | uint32(dc.b[i])
			i++
		case 1:
			if err := dc.need(i, 2); err != nil {
				return nil, 0, err
			}
			p = (vvv<<16 | uint32(dc.b[i])<<8 | uint32(dc.b[i+1])) + 2048
			i += 2
		case 2:
			if err := dc.need(i, 3); err != nil {
				return nil, 0, err
			}
			p = (vvv<<24 | uint32(dc.b[i])<<16 | uint32(dc.b[i+1])<<8 | uint32(dc.b[i+2])) + 526336
			i += 3
		default:
			if err := dc.need(i, 4); err != nil {
				return nil, 0, err
			}
			p = binary.BigEndian.Uint32(dc.b[i:])
			i += 4
		}
		var v any
		var err error
		if dc.db != nil {
			v, err = dc.db.decodeAtDepth(int64(p), dc.depth)
		} else { // metadata never uses pointers; resolve in-buffer for tests
			rel := int(int64(p) - dc.base)
			if rel < 0 {
				return nil, 0, errors.New("pointer before buffer")
			}
			v, _, err = dc.decode(rel)
		}
		return v, i, err
	}
	if typ == 0 {
		if err := dc.need(i, 1); err != nil {
			return nil, 0, err
		}
		typ = 7 + int(dc.b[i])
		i++
	}
	size := int(ctrl & 0x1f)
	switch size {
	case 29:
		if err := dc.need(i, 1); err != nil {
			return nil, 0, err
		}
		size = 29 + int(dc.b[i])
		i++
	case 30:
		if err := dc.need(i, 2); err != nil {
			return nil, 0, err
		}
		size = 285 + int(binary.BigEndian.Uint16(dc.b[i:]))
		i += 2
	case 31:
		if err := dc.need(i, 3); err != nil {
			return nil, 0, err
		}
		size = 65821 + int(uint32(dc.b[i])<<16|uint32(dc.b[i+1])<<8|uint32(dc.b[i+2]))
		i += 3
	}
	switch typ {
	case 2: // utf8 string
		if err := dc.need(i, size); err != nil {
			return nil, 0, err
		}
		return string(dc.b[i : i+size]), i + size, nil
	case 3: // double
		if err := dc.need(i, 8); err != nil {
			return nil, 0, err
		}
		return math.Float64frombits(binary.BigEndian.Uint64(dc.b[i:])), i + 8, nil
	case 4: // bytes
		if err := dc.need(i, size); err != nil {
			return nil, 0, err
		}
		return append([]byte(nil), dc.b[i:i+size]...), i + size, nil
	case 5, 6, 9, 10: // unsigned ints (uint128 truncated: not used by the Lite DBs)
		if err := dc.need(i, size); err != nil {
			return nil, 0, err
		}
		var v uint64
		for k := 0; k < size; k++ {
			v = v<<8 | uint64(dc.b[i+k])
		}
		return v, i + size, nil
	case 8: // int32
		if err := dc.need(i, size); err != nil {
			return nil, 0, err
		}
		var v uint32
		for k := 0; k < size; k++ {
			v = v<<8 | uint32(dc.b[i+k])
		}
		return int32(v), i + size, nil
	case 7: // map
		m := make(map[string]any, size)
		for k := 0; k < size; k++ {
			key, n, err := dc.decode(i)
			if err != nil {
				return nil, 0, err
			}
			ks, ok := key.(string)
			if !ok {
				return nil, 0, errors.New("map key is not a string")
			}
			val, n2, err := dc.decode(n)
			if err != nil {
				return nil, 0, err
			}
			m[ks] = val
			i = n2
		}
		return m, i, nil
	case 11: // array
		a := make([]any, 0, size)
		for k := 0; k < size; k++ {
			val, n, err := dc.decode(i)
			if err != nil {
				return nil, 0, err
			}
			a = append(a, val)
			i = n
		}
		return a, i, nil
	case 14: // boolean
		return size != 0, i, nil
	case 15: // float
		if err := dc.need(i, 4); err != nil {
			return nil, 0, err
		}
		return math.Float32frombits(binary.BigEndian.Uint32(dc.b[i:])), i + 4, nil
	}
	return nil, 0, fmt.Errorf("unsupported data type %d", typ)
}
