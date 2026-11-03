package system

// IDS alerts behind NAT: Suricata watches the WAN, where every outgoing
// connection carries our public address (SNAT) and every port forward
// targets it (DNAT). The connection-tracking entry of that exact connection
// still knows the inside host: it is looked up when the alert arrives, while
// the connection is usually still open.

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"zfsnas/internal/ids"
	"zfsnas/internal/traffic"
)

const (
	sdnIDSNATPerSec = 10              // conntrack lookups a second at most (port scans)
	sdnIDSNATCache  = 2 * time.Minute // a connection's answer is reused this long
)

var (
	sdnIDSLocal         = SDNIsLocalAddr
	sdnIDSHaveConntrack = func() bool { return binaryPresent("conntrack") }
)

type sdnIDSNATAnswer struct {
	src, dst string
	at       time.Time
}

type sdnIDSNAT struct {
	mu     sync.Mutex
	cache  map[string]sdnIDSNATAnswer
	second int64
	n      int
}

func newSDNIDSNAT() *sdnIDSNAT { return &sdnIDSNAT{cache: map[string]sdnIDSNATAnswer{}} }

var sdnIDSNATResolver = newSDNIDSNAT()

// resolve fills e.SrcInside (outgoing through SNAT) or e.DstInside (a port
// forward) when the alert is about our public address.
func (r *sdnIDSNAT) resolve(e *ids.Event, now time.Time) {
	sa, err1 := netip.ParseAddr(e.Src)
	da, err2 := netip.ParseAddr(e.Dst)
	if err1 != nil || err2 != nil {
		return
	}
	// Our address on one side only (public, or private on a double-NAT /
	// CGNAT link): the other side may be NATed to an inside host.
	out, in := sdnIDSLocal(sa) && !sdnIDSLocal(da), sdnIDSLocal(da) && !sdnIDSLocal(sa)
	if !out && !in {
		return
	}
	proto := strings.ToLower(e.Proto)
	ports := proto == "tcp" || proto == "udp" || proto == "sctp"
	key := strings.Join([]string{proto, e.Src, strconv.Itoa(e.SrcPort), e.Dst, strconv.Itoa(e.DstPort)}, "|")

	r.mu.Lock()
	if a, ok := r.cache[key]; ok && now.Sub(a.at) < sdnIDSNATCache {
		r.mu.Unlock()
		e.SrcInside, e.DstInside = a.src, a.dst
		return
	}
	if s := now.Unix(); s != r.second {
		r.second, r.n = s, 0
		if len(r.cache) > 4096 {
			for k, a := range r.cache {
				if now.Sub(a.at) >= sdnIDSNATCache {
					delete(r.cache, k)
				}
			}
		}
	}
	if r.n >= sdnIDSNATPerSec || !sdnIDSHaveConntrack() {
		r.mu.Unlock()
		return
	}
	r.n++
	r.mu.Unlock()

	args := []string{"-L", "-p", proto, "-o", "extended,id"}
	if out { // our side started it: the reply comes back to our public address
		args = append(args, "--reply-src", e.Dst, "--reply-dst", e.Src)
		if ports {
			args = append(args, "--reply-port-src", strconv.Itoa(e.DstPort), "--reply-port-dst", strconv.Itoa(e.SrcPort))
		}
	} else {
		args = append(args, "-s", e.Src, "-d", e.Dst)
		if ports {
			args = append(args, "--sport", strconv.Itoa(e.SrcPort), "--dport", strconv.Itoa(e.DstPort))
		}
	}
	b, _ := sdnRun.Run(nil, "conntrack", args...)
	var ans sdnIDSNATAnswer
	for _, line := range strings.Split(string(b), "\n") {
		f, ok := traffic.ParseConntrack(line)
		if !ok {
			continue
		}
		if out && f.OrigSrc != sa && !sdnIDSLocal(f.OrigSrc) {
			ans.src = f.OrigSrc.String()
		}
		if in && f.ReplySrc != da && !sdnIDSLocal(f.ReplySrc) {
			ans.dst = f.ReplySrc.String()
		}
		break
	}
	ans.at = now
	r.mu.Lock()
	r.cache[key] = ans
	r.mu.Unlock()
	e.SrcInside, e.DstInside = ans.src, ans.dst
}
