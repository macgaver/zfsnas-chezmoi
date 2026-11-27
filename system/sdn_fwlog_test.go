package system

import (
	"strings"
	"testing"
)

func TestParseFWLogLine(t *testing.T) {
	e, ok := parseFWLogLine("znas r:r0000004 IN=enp1s0 OUT= MAC=aa:bb SRC=203.0.113.9 DST=192.168.10.5 LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=0 DF PROTO=TCP SPT=51515 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0")
	if !ok || e.Rule != "r0000004" || e.In != "enp1s0" || e.Out != "" || e.Src != "203.0.113.9" || e.Dst != "192.168.10.5" ||
		e.Proto != "TCP" || e.SPort != 51515 || e.DPort != 22 || e.Len != 60 {
		t.Fatalf("%+v %v", e, ok)
	}
	// ICMP has no ports; the inner header's LEN must not win
	e, ok = parseFWLogLine("znas r:abc12345 IN=wan OUT=lan SRC=1.2.3.4 DST=5.6.7.8 LEN=84 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1 LEN=56")
	if !ok || e.Proto != "ICMP" || e.SPort != 0 || e.Len != 84 || e.Out != "lan" {
		t.Fatalf("icmp: %+v", e)
	}
	if _, ok := parseFWLogLine("some other kernel message SRC=1.1.1.1"); ok {
		t.Fatal("unrelated line parsed")
	}
}

func TestParseFWJournal(t *testing.T) {
	out := strings.Join([]string{
		`{"MESSAGE":"znas r:r1 IN=a OUT= SRC=1.1.1.1 DST=2.2.2.2 LEN=40 PROTO=UDP SPT=1 DPT=53","__REALTIME_TIMESTAMP":"1764230000000000"}`,
		`{"MESSAGE":[122,110,97,115,32,114,58,114,50,32,73,78,61,98,32,83,82,67,61,51,46,51,46,51,46,51,32,68,83,84,61,52,46,52,46,52,46,52,32,80,82,79,84,79,61,84,67,80],"__REALTIME_TIMESTAMP":"1764230005000000"}`,
		`{"MESSAGE":"usb 1-1: new device","__REALTIME_TIMESTAMP":"1764230006000000"}`,
		`not json`,
	}, "\n")
	got := parseFWJournal([]byte(out))
	if len(got) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Rule != "r2" || got[0].Src != "3.3.3.3" || got[1].Rule != "r1" {
		t.Fatalf("newest first / byte-array message: %+v", got)
	}
	if !got[0].Time.After(got[1].Time) {
		t.Fatal("times")
	}
}

func TestSDNFirewallLogFilters(t *testing.T) {
	old := sdnJournalctl
	defer func() { sdnJournalctl = old }()
	var seen []string
	sdnJournalctl = func(args ...string) ([]byte, error) {
		seen = args
		return []byte(`{"MESSAGE":"znas r:r1 IN=a SRC=1.1.1.1 DST=2.2.2.2 PROTO=UDP","__REALTIME_TIMESTAMP":"1"}` + "\n" +
			`{"MESSAGE":"znas r:r10 IN=a SRC=9.9.9.9 DST=2.2.2.2 PROTO=UDP","__REALTIME_TIMESTAMP":"2"}`), nil
	}
	got, err := SDNFirewallLog("r1", 100)
	if err != nil || len(got) != 1 || got[0].Src != "1.1.1.1" {
		t.Fatalf("rule filter (r1 must not match r10): %+v %v", got, err)
	}
	if strings.Join(seen, " ") == "" || !strings.Contains(strings.Join(seen, " "), "--grep znas r:r1 ") {
		t.Fatalf("args %v", seen)
	}
	sdnJournalctl = func(args ...string) ([]byte, error) { return nil, errNoJournalMatch }
	if got, err := SDNFirewallLog("", 10); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("no match must be an empty list, not an error: %v %v", got, err)
	}
	if _, err := SDNFirewallLog("r1; rm -rf /", 10); err == nil {
		t.Fatal("bad rule id accepted")
	}
}
