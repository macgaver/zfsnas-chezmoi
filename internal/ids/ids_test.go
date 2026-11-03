package ids

import (
	"path/filepath"
	"testing"
	"time"
)

const eveLine = `{"timestamp":"2026-10-29T13:10:01.123456+0000","flow_id":1,"in_iface":"enp6s0","event_type":"alert","src_ip":"81.2.69.142","src_port":40000,"dest_ip":"10.250.0.2","dest_port":22,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,"rev":20,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}`

func TestParseEVE(t *testing.T) {
	e, ok := ParseEVE([]byte(eveLine))
	if !ok {
		t.Fatal("not parsed")
	}
	if e.SID != 2001219 || e.Signature != "ET SCAN Potential SSH Scan" || e.Severity != 2 || e.Src != "81.2.69.142" ||
		e.DstPort != 22 || e.Proto != "TCP" || e.InIface != "enp6s0" || e.Time.UTC().Format("15:04:05") != "13:10:01" {
		t.Fatalf("%+v", e)
	}
	if _, ok := ParseEVE([]byte(`{"event_type":"stats"}`)); ok {
		t.Fatal("non-alert accepted")
	}
	if _, ok := ParseEVE([]byte(`garbage`)); ok {
		t.Fatal("garbage accepted")
	}
}

func TestStore_AggregatesAndPersists(t *testing.T) {
	p := filepath.Join(t.TempDir(), "alerts.json.gz")
	s := NewStore(p)
	e, _ := ParseEVE([]byte(eveLine))
	s.Add(e)
	e2 := e
	e2.Time = e.Time.Add(time.Minute)
	s.Add(e2)
	e3 := e
	e3.Src = "175.16.199.1"
	s.Add(e3)
	l := s.List(time.Time{})
	if len(l) != 2 {
		t.Fatalf("groups %+v", l)
	}
	var g Group
	for _, x := range l {
		if x.Src == "81.2.69.142" {
			g = x
		}
	}
	if g.Count != 2 || !g.First.Equal(e.Time) || !g.Last.Equal(e2.Time) {
		t.Fatalf("%+v", g)
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2 := NewStore(p)
	if len(s2.List(time.Time{})) != 2 {
		t.Fatal("not reloaded")
	}
}

func TestStore_PrunesOldAndCaps(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "a.json.gz"))
	s.max = 3
	now := time.Now()
	e, _ := ParseEVE([]byte(eveLine))
	e.Time = now.Add(-31 * 24 * time.Hour)
	e.SID = 1
	s.Add(e)
	for i := 2; i <= 5; i++ {
		e.SID = i
		e.Time = now.Add(time.Duration(i) * time.Second)
		s.Add(e)
	}
	_ = s.Save()
	l := s.List(time.Time{})
	if len(l) != 3 || l[0].SID != 5 || l[2].SID != 3 {
		t.Fatalf("%+v", l)
	}
}

func TestStore_ListSince(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "a.json.gz"))
	e, _ := ParseEVE([]byte(eveLine))
	e.Time = time.Now().Add(-2 * time.Hour)
	s.Add(e)
	if len(s.List(time.Now().Add(-time.Hour))) != 0 || len(s.List(time.Now().Add(-3*time.Hour))) != 1 {
		t.Fatal("since filter")
	}
}

// A port scan is one group (one signature, one source, one target), not one
// group per port.
func TestStore_PortScanIsOneGroup(t *testing.T) {
	s := NewStore("")
	e, _ := ParseEVE([]byte(eveLine))
	for p := 1; p <= 30; p++ {
		e.DstPort = p
		s.Add(e)
	}
	e.DstPort = 5
	s.Add(e)
	l := s.List(time.Time{})
	if len(l) != 1 || l[0].Count != 31 || l[0].PortCount != 30 || len(l[0].Ports) != 20 || l[0].DstPort != 5 {
		t.Fatalf("%+v", l)
	}
}

// An alert raised on a reply packet (direction to_client) is filed by who
// started the connection: the flow's source/destination and target port.
func TestParseEVE_OrientedByFlow(t *testing.T) {
	line := `{"timestamp":"2026-10-29T17:00:00.000000-0400","event_type":"alert","in_iface":"ppp0","src_ip":"93.184.216.34","src_port":80,"dest_ip":"69.156.169.77","dest_port":51000,"proto":"TCP","direction":"to_client",` +
		`"flow":{"src_ip":"69.156.169.77","dest_ip":"93.184.216.34","src_port":51000,"dest_port":80},"alert":{"signature_id":2100498,"signature":"GPL ATTACK_RESPONSE id check returned root","category":"x","severity":2}}`
	e, ok := ParseEVE([]byte(line))
	if !ok || e.Src != "69.156.169.77" || e.Dst != "93.184.216.34" || e.DstPort != 80 || e.SrcPort != 51000 {
		t.Fatalf("%+v", e)
	}
	// Older Suricata: no flow object — a to_client packet is swapped.
	old := `{"timestamp":"2026-10-29T17:00:00.000000-0400","event_type":"alert","src_ip":"93.184.216.34","src_port":80,"dest_ip":"10.0.0.5","dest_port":51000,"proto":"TCP","direction":"to_client","alert":{"signature_id":1,"signature":"s","severity":2}}`
	if e, _ := ParseEVE([]byte(old)); e.Src != "10.0.0.5" || e.DstPort != 80 {
		t.Fatalf("no flow: %+v", e)
	}
	// to_server without flow: as is.
	in := `{"timestamp":"2026-10-29T17:00:00.000000-0400","event_type":"alert","src_ip":"1.2.3.4","src_port":4000,"dest_ip":"69.156.169.77","dest_port":22,"proto":"TCP","direction":"to_server","alert":{"signature_id":1,"signature":"s","severity":2}}`
	if e, _ := ParseEVE([]byte(in)); e.Src != "1.2.3.4" || e.DstPort != 22 {
		t.Fatalf("to_server: %+v", e)
	}
}

// Behind NAT: the inside host found for an alert is kept, and two inside
// hosts behind the same public address are two groups, not one.
func TestStore_KeepsInsideHostBehindNAT(t *testing.T) {
	s := NewStore(filepath.Join(t.TempDir(), "a.json.gz"))
	e, _ := ParseEVE([]byte(eveLine)) // 81.2.69.142 → 10.250.0.2:22
	e.DstInside = "10.97.8.10"
	s.Add(e)
	e2 := e
	e2.DstInside = "10.97.8.11"
	s.Add(e2)
	e3 := e
	e3.DstInside = "" // not looked up (rate limit, flow gone): joins the host found last
	s.Add(e3)
	l := s.List(time.Time{})
	if len(l) != 2 {
		t.Fatalf("groups %+v", l)
	}
	got := map[string]int64{}
	for _, g := range l {
		got[g.DstInside] = g.Count
	}
	if got["10.97.8.10"] != 1 || got["10.97.8.11"] != 2 {
		t.Fatalf("%+v", got)
	}
	o := Event{Src: "69.156.169.77", Dst: "45.45.148.8", SrcInside: "10.97.8.20", SID: 1, Proto: "TCP", Time: e.Time}
	s.Add(o)
	for _, g := range s.List(time.Time{}) {
		if g.Src == "69.156.169.77" && g.SrcInside != "10.97.8.20" {
			t.Fatalf("outgoing inside host lost: %+v", g)
		}
	}
}
