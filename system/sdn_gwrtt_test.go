package system

import "testing"

func ms(v float64) *float64 { return &v }

func TestRTTRingTrim15m(t *testing.T) {
	var r []RTTPoint
	for ts := int64(0); ts <= 1000; ts += 2 {
		r = pushRTT(r, RTTPoint{TS: ts, MS: ms(1)})
	}
	if r[0].TS != 100 || r[len(r)-1].TS != 1000 {
		t.Fatalf("ring must hold the last 900 s, got %d..%d", r[0].TS, r[len(r)-1].TS)
	}
}

func TestRTTWindow(t *testing.T) {
	pts := []RTTPoint{{TS: 10, MS: ms(9)}, {TS: 20, MS: ms(2)}, {TS: 30, MS: nil}, {TS: 40, MS: ms(4)}, {TS: 50, MS: ms(100)}}
	mn, avg, mx, n := RTTWindow(pts, 10, 40)
	if n != 2 || mn != 2 || mx != 4 || avg != 3 {
		t.Fatalf("got %v %v %v %d", mn, avg, mx, n)
	}
}

func TestRTTWindowAllLost(t *testing.T) {
	if _, _, _, n := RTTWindow([]RTTPoint{{TS: 5}, {TS: 6}}, 0, 10); n != 0 {
		t.Fatal("no answered ping must give n=0")
	}
}

func TestSummarizeRTT(t *testing.T) {
	var s GWRTTSummary
	summarizeRTT(&s, []RTTPoint{{TS: 100, MS: ms(2)}, {TS: 120, MS: nil}, {TS: 140, MS: ms(4)}, {TS: 160, MS: ms(3)}})
	if s.NowMS == nil || *s.NowMS != 3 || s.TS != 160 || *s.AvgMS != 3 || *s.MinMS != 2 || *s.MaxMS != 4 || s.LossPct != 25 || s.Checks != 4 || s.WindowS != 900 {
		t.Fatalf("%+v", s)
	}
	var lost GWRTTSummary
	summarizeRTT(&lost, []RTTPoint{{TS: 1}})
	if lost.NowMS != nil || lost.AvgMS != nil || lost.LossPct != 100 {
		t.Fatalf("all lost: %+v", lost)
	}
}

func TestPingMeanRTT(t *testing.T) {
	out := []byte("64 bytes from 10.11.16.145: icmp_seq=1 ttl=64 time=1.0 ms\n64 bytes from 10.11.16.145: icmp_seq=3 ttl=64 time=2.0 ms\n")
	if d := pingMeanRTT(out); d.Microseconds() != 1500 {
		t.Fatalf("mean of the replies: %v", d)
	}
	if pingMeanRTT([]byte("no reply")) != 0 {
		t.Fatal("no reply = 0")
	}
}
