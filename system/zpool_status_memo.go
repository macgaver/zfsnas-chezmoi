package system

import (
	"os/exec"
	"strings"
	"sync"
)

// Describing a pool takes a dozen `zpool status` readings (members, spares,
// cache, vdev tree, errors, operation…), each a sudo + zpool process. While
// a pool is being described, each variant (plain, -P, -v) runs once and the
// helpers share its output; outside a description they run it fresh, so
// nothing is ever served stale after the description ends.

type zpoolStatusRun struct {
	once sync.Once
	out  []byte
	err  error
}

type zpoolStatusSet struct {
	users int
	runs  map[string]*zpoolStatusRun // flags → one run
}

var zpoolStatusMemo = struct {
	sync.Mutex
	pools map[string]*zpoolStatusSet
}{pools: map[string]*zpoolStatusSet{}}

// beginPoolStatus opens a description of pool; call the returned func when
// it is done.
func beginPoolStatus(pool string) (end func()) {
	zpoolStatusMemo.Lock()
	st := zpoolStatusMemo.pools[pool]
	if st == nil {
		st = &zpoolStatusSet{runs: map[string]*zpoolStatusRun{}}
		zpoolStatusMemo.pools[pool] = st
	}
	st.users++
	zpoolStatusMemo.Unlock()
	return func() {
		zpoolStatusMemo.Lock()
		if st.users--; st.users == 0 && zpoolStatusMemo.pools[pool] == st {
			delete(zpoolStatusMemo.pools, pool)
		}
		zpoolStatusMemo.Unlock()
	}
}

// zpoolStatusExec runs `sudo zpool status <flags> <pool>` (a var for tests).
var zpoolStatusExec = func(pool string, flags ...string) ([]byte, error) {
	args := append(append([]string{"zpool", "status"}, flags...), pool)
	return exec.Command("sudo", args...).Output()
}

// zpoolStatusOut is `zpool status <flags> <pool>`, shared within a
// description of that pool.
func zpoolStatusOut(pool string, flags ...string) ([]byte, error) {
	zpoolStatusMemo.Lock()
	st := zpoolStatusMemo.pools[pool]
	var run *zpoolStatusRun
	if st != nil {
		key := strings.Join(flags, " ")
		if run = st.runs[key]; run == nil {
			run = &zpoolStatusRun{}
			st.runs[key] = run
		}
	}
	zpoolStatusMemo.Unlock()
	if run == nil {
		return zpoolStatusExec(pool, flags...)
	}
	run.once.Do(func() { run.out, run.err = zpoolStatusExec(pool, flags...) })
	return run.out, run.err
}
