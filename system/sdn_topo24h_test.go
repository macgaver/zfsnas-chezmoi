package system

import (
	"testing"
	"time"

	"zfsnas/internal/traffic"
)

func TestSDNTopoRefresh24h_OnePassAndThrottled(t *testing.T) {
	now := time.Now()
	st := &traffic.Store{Dir: t.TempDir()}
	at := now.Add(-time.Hour).Truncate(traffic.BucketSize)
	if err := st.Write([]traffic.Bucket{{Start: at, Recs: []traffic.Rec{
		{Dir: "in", Remote: "1.1.1.1", Inside: "10.0.0.5", BytesIn: 100, BytesOut: 20, Sessions: 1},
		{Dir: "out", Remote: "8.8.8.8", Inside: "10.0.0.6", BytesIn: 7, Sessions: 1},
	}}}); err != nil {
		t.Fatal(err)
	}
	sdnTC.mu.Lock()
	oldStore, oldAgg := sdnTC.store, sdnTC.agg
	sdnTC.store, sdnTC.agg = st, traffic.NewAggregator(traffic.Env{})
	sdnTC.mu.Unlock()
	sdnTopo24h.Lock()
	oldTopo := sdnTopo24h.bytes
	sdnTopo24h.bytes, sdnTopo24h.started, sdnTopo24h.running = map[string]uint64{}, time.Time{}, false
	sdnTopo24h.Unlock()
	t.Cleanup(func() {
		sdnTC.mu.Lock()
		sdnTC.store, sdnTC.agg = oldStore, oldAgg
		sdnTC.mu.Unlock()
		sdnTopo24h.Lock()
		sdnTopo24h.bytes, sdnTopo24h.started, sdnTopo24h.running = oldTopo, time.Time{}, false
		sdnTopo24h.Unlock()
	})

	wait := func() map[string]uint64 {
		for i := 0; i < 200; i++ {
			sdnTopo24h.Lock()
			r, m := sdnTopo24h.running, sdnTopo24h.bytes
			sdnTopo24h.Unlock()
			if !r {
				return m
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("refresh never finished")
		return nil
	}
	sdnTopoRefresh24h(now)
	m := wait()
	if m["10.0.0.5"] != 120 || m["10.0.0.6"] != 7 {
		t.Fatalf("totals %v", m)
	}
	sdnTopo24h.Lock()
	first := sdnTopo24h.started
	sdnTopo24h.Unlock()
	sdnTopoRefresh24h(now.Add(9 * time.Minute)) // too soon: no new pass
	sdnTopo24h.Lock()
	again := sdnTopo24h.started
	sdnTopo24h.Unlock()
	if !again.Equal(first) {
		t.Fatal("refreshed again within ten minutes")
	}
	sdnTopoRefresh24h(now.Add(11 * time.Minute))
	wait()
	sdnTopo24h.Lock()
	again = sdnTopo24h.started
	sdnTopo24h.Unlock()
	if again.Equal(first) {
		t.Fatal("not refreshed after ten minutes")
	}
}
