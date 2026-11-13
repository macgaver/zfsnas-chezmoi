package system

import (
	"strings"
	"sync"
	"testing"
)

func TestZpoolStatusMemo(t *testing.T) {
	var mu sync.Mutex
	runs := map[string]int{}
	old := zpoolStatusExec
	zpoolStatusExec = func(pool string, flags ...string) ([]byte, error) {
		mu.Lock()
		runs[pool+"|"+strings.Join(flags, " ")]++
		mu.Unlock()
		return []byte("status of " + pool), nil
	}
	t.Cleanup(func() { zpoolStatusExec = old })

	end := beginPoolStatus("tank")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ { // helpers in parallel share one run per variant
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = zpoolStatusOut("tank")
			_, _ = zpoolStatusOut("tank", "-P")
		}()
	}
	wg.Wait()
	_, _ = zpoolStatusOut("other") // another pool: not part of the description
	_, _ = zpoolStatusOut("other")
	end()
	if runs["tank|"] != 1 || runs["tank|-P"] != 1 || runs["other|"] != 2 {
		t.Fatalf("runs %v", runs)
	}
	// after the description: fresh again
	_, _ = zpoolStatusOut("tank")
	if runs["tank|"] != 2 {
		t.Fatalf("served stale after the description: %v", runs)
	}
	zpoolStatusMemo.Lock()
	left := len(zpoolStatusMemo.pools)
	zpoolStatusMemo.Unlock()
	if left != 0 {
		t.Fatalf("memo not released: %d", left)
	}
}
