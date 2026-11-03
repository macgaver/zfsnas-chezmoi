// Package traffic turns kernel connection tracking into the Firewall's
// traffic statistics: who connected to us and what we connected to, by
// remote IP / country / city, with the inside host and data volumes, plus
// blocked attempts. Spec: PLANS/spec-sdn-firewall.md §12.
package traffic

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"zfsnas/internal/geoip"
)

// Flow is one conntrack entry or event.
type Flow struct {
	ID                                   uint64
	Proto                                string
	OrigSrc, OrigDst, ReplySrc, ReplyDst netip.Addr
	OrigSport, OrigDport, ReplySport     uint16
	BytesOrig, BytesReply                uint64
	PktsOrig, PktsReply                  uint64
	Destroy                              bool
	At                                   time.Time
}

// ParseConntrack reads one line of `conntrack -L -o extended,id` or
// `conntrack -E -o timestamp,extended,id`. The first src/dst/ports/counters
// are the original direction (the initiator), the second the reply.
func ParseConntrack(line string) (Flow, bool) {
	var f Flow
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return f, false
	}
	seen := map[string]int{}
	gotProto := false
	for i, tok := range fields {
		switch {
		case strings.HasPrefix(tok, "[") && strings.HasSuffix(tok, "]"):
			inner := tok[1 : len(tok)-1]
			if inner == "DESTROY" {
				f.Destroy = true
			} else if sec, frac, ok := strings.Cut(inner, "."); ok {
				if s, err := strconv.ParseInt(sec, 10, 64); err == nil {
					ns, _ := strconv.ParseInt((frac + "000000000")[:9], 10, 64)
					f.At = time.Unix(s, ns)
				}
			}
		case !gotProto && (tok == "tcp" || tok == "udp" || tok == "icmp" || tok == "unknown" || tok == "sctp" || tok == "gre") && i > 0:
			f.Proto, gotProto = tok, true
		case strings.Contains(tok, "="):
			k, v, _ := strings.Cut(tok, "=")
			n := seen[k]
			seen[k] = n + 1
			orig := n == 0
			switch k {
			case "src":
				a, _ := netip.ParseAddr(v)
				if orig {
					f.OrigSrc = a
				} else {
					f.ReplySrc = a
				}
			case "dst":
				a, _ := netip.ParseAddr(v)
				if orig {
					f.OrigDst = a
				} else {
					f.ReplyDst = a
				}
			case "sport":
				p, _ := strconv.Atoi(v)
				if orig {
					f.OrigSport = uint16(p)
				} else {
					f.ReplySport = uint16(p)
				}
			case "dport":
				p, _ := strconv.Atoi(v)
				if orig {
					f.OrigDport = uint16(p)
				}
			case "packets":
				p, _ := strconv.ParseUint(v, 10, 64)
				if orig {
					f.PktsOrig = p
				} else {
					f.PktsReply = p
				}
			case "bytes":
				p, _ := strconv.ParseUint(v, 10, 64)
				if orig {
					f.BytesOrig = p
				} else {
					f.BytesReply = p
				}
			case "id":
				// icmp carries its own id= twice before the conntrack id;
				// the conntrack id is the last one on the line.
				if p, err := strconv.ParseUint(v, 10, 64); err == nil {
					f.ID = p
				}
			}
		}
	}
	if !gotProto || !f.OrigSrc.IsValid() || !f.ReplySrc.IsValid() || f.ID == 0 {
		return f, false
	}
	return f, true
}

// Env gives the classifier the facts about this router.
type Env struct {
	Local   func(netip.Addr) bool       // an address of this box
	IfaceOf func(netip.Addr) string     // interface holding a local address ("" if none)
	NameOf  func(netip.Addr) string     // inside host name (instance, DHCP, DNS) or ""
	Geo     func(netip.Addr) geoip.Info // public addresses only
}

// Rec is one aggregated line of the statistics.
type Rec struct {
	Dir      string    `json:"dir"` // in | out | blk
	Remote   string    `json:"remote,omitempty"`
	Inside   string    `json:"inside,omitempty"`
	Name     string    `json:"name,omitempty"`
	Proto    string    `json:"proto,omitempty"`
	PubIP    string    `json:"pub_ip,omitempty"`
	PubPort  uint16    `json:"pub_port,omitempty"`
	Port     uint16    `json:"port,omitempty"` // inside port (in), remote port (out), targeted port (blk)
	Iface    string    `json:"iface,omitempty"`
	Rule     string    `json:"rule,omitempty"` // blk: the rule that dropped it
	BytesIn  uint64    `json:"bytes_in,omitempty"`
	BytesOut uint64    `json:"bytes_out,omitempty"`
	Pkts     uint64    `json:"pkts,omitempty"`
	Sessions uint64    `json:"sessions,omitempty"`
	CC       string    `json:"cc,omitempty"`
	Country  string    `json:"country,omitempty"`
	City     string    `json:"city,omitempty"`
	Lat      float64   `json:"lat,omitempty"`
	Lon      float64   `json:"lon,omitempty"`
	ASN      uint      `json:"asn,omitempty"`
	ASOrg    string    `json:"as_org,omitempty"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

func (r *Rec) geo(g geoip.Info) {
	r.CC, r.Country, r.City, r.Lat, r.Lon, r.ASN, r.ASOrg = g.CountryCode, g.Country, g.City, g.Lat, g.Lon, g.ASN, g.ASOrg
}

// Classify maps a flow to its statistics line. Incoming: the initiator is
// public. Outgoing: the initiator is inside (private or this box) and the
// destination public. Private ↔ private traffic is not part of the outside
// tables (ok=false).
func Classify(f Flow, env Env) (key string, r Rec, ok bool) {
	pubSrc, pubDst := geoip.IsPublic(f.OrigSrc), geoip.IsPublic(f.OrigDst)
	local := func(a netip.Addr) bool { return env.Local != nil && env.Local(a) }
	name := func(a netip.Addr) string {
		if local(a) {
			return "This ZNAS"
		}
		if env.NameOf != nil {
			return env.NameOf(a)
		}
		return ""
	}
	iface := func(a netip.Addr) string {
		if env.IfaceOf != nil {
			return env.IfaceOf(a)
		}
		return ""
	}
	r.Proto = f.Proto
	r.Pkts = f.PktsOrig + f.PktsReply
	// This box opening a connection from its own public WAN address is
	// outgoing, not "public to public".
	if local(f.OrigSrc) {
		pubSrc = false
	}
	switch {
	case pubSrc && !(pubDst && !local(f.OrigDst) && f.ReplySrc == f.OrigDst):
		inside := f.ReplySrc // after DNAT; equal to the original destination otherwise
		r.Dir, r.Remote, r.Inside, r.Name = "in", f.OrigSrc.String(), inside.String(), name(inside)
		r.PubIP, r.PubPort, r.Port, r.Iface = f.OrigDst.String(), f.OrigDport, f.ReplySport, iface(f.OrigDst)
		r.BytesIn, r.BytesOut = f.BytesOrig, f.BytesReply
		if env.Geo != nil {
			r.geo(env.Geo(f.OrigSrc))
		}
		key = strings.Join([]string{"in", r.Remote, r.Proto, strconv.Itoa(int(r.PubPort)), r.Inside, strconv.Itoa(int(r.Port))}, "|")
	case !pubSrc && pubDst:
		r.Dir, r.Remote, r.Inside, r.Name = "out", f.OrigDst.String(), f.OrigSrc.String(), name(f.OrigSrc)
		r.Port = f.OrigDport
		r.Iface = iface(f.ReplyDst) // SNAT: the reply comes back to our WAN address
		if r.Iface == "" {
			r.Iface = iface(f.OrigSrc)
		}
		r.BytesOut, r.BytesIn = f.BytesOrig, f.BytesReply
		if env.Geo != nil {
			r.geo(env.Geo(f.OrigDst))
		}
		key = strings.Join([]string{"out", r.Remote, r.Proto, strconv.Itoa(int(r.Port)), r.Inside}, "|")
	default:
		return "", r, false
	}
	return key, r, true
}
