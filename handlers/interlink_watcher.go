package handlers

// Background connectivity watcher for InterLink peers. Every linked server is
// pinged every 5 minutes; the "interlink_unreachable" notification fires ONCE
// when a peer stops answering, then once more when it becomes reachable again —
// nothing in between, so a dead peer doesn't spam a notification per poll.
// State is in-memory: after a service restart a still-down peer is re-announced
// on the first check, which doubles as a "still down" reminder.

import (
	"fmt"
	"log"
	"time"

	"zfsnas/internal/alerts"
	"zfsnas/internal/config"
	"zfsnas/system"
)

const interlinkWatchInterval = 5 * time.Minute

// interlinkPeerState tracks the last observed reachability of one peer.
type interlinkPeerState struct {
	down      bool
	downSince time.Time
}

// StartInterlinkWatcher launches the 5-minute InterLink connectivity poller.
// Peers are always pinged and state always tracked (cheap — one HTTPS GET per
// peer); alerts.Send filters by subscription, so nothing is dispatched unless
// a target has interlink_unreachable enabled.
func StartInterlinkWatcher(appCfg *config.AppConfig) {
	go func() {
		state := map[string]*interlinkPeerState{}
		// Let the network stack and peers settle after boot before the first
		// probe, so a reboot of the whole rack doesn't announce every peer down.
		time.Sleep(1 * time.Minute)
		checkInterlinkPeers(appCfg, state)
		tick := time.NewTicker(interlinkWatchInterval)
		defer tick.Stop()
		for range tick.C {
			checkInterlinkPeers(appCfg, state)
		}
	}()
}

func checkInterlinkPeers(appCfg *config.AppConfig, state map[string]*interlinkPeerState) {
	interlinkMu.Lock()
	peers := append([]config.LinkedServer{}, appCfg.InterLink...)
	interlinkMu.Unlock()

	// Forget peers that were unlinked — no recovery alert for a removed link.
	current := map[string]bool{}
	for _, ls := range peers {
		current[ls.ID] = true
	}
	for id := range state {
		if !current[id] {
			delete(state, id)
		}
	}
	if len(peers) == 0 {
		return
	}

	type result struct {
		idx       int
		reachable bool
	}
	ch := make(chan result, len(peers))
	for i, ls := range peers {
		go func(i int, ls config.LinkedServer) {
			ch <- result{i, interlinkPeerReachable(ls)}
		}(i, ls)
	}

	for range peers {
		res := <-ch
		ls := peers[res.idx]
		st := state[ls.ID]
		if st == nil {
			st = &interlinkPeerState{}
			state[ls.ID] = st
		}
		name := ls.Hostname
		if name == "" {
			name = ls.URL
		}
		switch {
		case !res.reachable && !st.down:
			st.down = true
			st.downSince = time.Now()
			if err := alerts.Send(
				alerts.EventInterlinkUnreachable,
				"Interlink server unreachable: "+name,
				"Interlink Server Unreachable",
				fmt.Sprintf("Linked server '%s' (%s) did not answer the connectivity check. It will be re-checked every 5 minutes; a follow-up notification is sent when it is reachable again.", name, ls.URL),
			); err != nil {
				log.Printf("[alerts] interlink-unreachable send for %s: %v", name, err)
			}
		case res.reachable && st.down:
			outage := time.Since(st.downSince).Round(time.Minute)
			st.down = false
			st.downSince = time.Time{}
			if err := alerts.Send(
				alerts.EventInterlinkUnreachable,
				"Interlink server back online: "+name,
				"Interlink Server Reachable Again",
				fmt.Sprintf("Linked server '%s' (%s) is answering the connectivity check again after being unreachable for about %s.", name, ls.URL, outage),
			); err != nil {
				log.Printf("[alerts] interlink-recovered send for %s: %v", name, err)
			}
		}
	}
}

// interlinkPeerReachable pings the peer, retrying once after a short pause so a
// single transient blip (peer restarting, momentary network hiccup) doesn't
// raise an outage notification.
func interlinkPeerReachable(ls config.LinkedServer) bool {
	if _, _, err := system.PingServer(ls.URL, ls.TLSFingerprint); err == nil {
		return true
	}
	time.Sleep(15 * time.Second)
	_, _, err := system.PingServer(ls.URL, ls.TLSFingerprint)
	return err == nil
}
