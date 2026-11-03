package sdn

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Summarize describes what changed between two configs in one line, for the
// history list and the Apply dialog: interfaces, groups, rules, settings —
// joined with " · ". Returns "no changes" when they are equivalent.
func Summarize(prev, next *Config) string {
	var parts []string

	prevIf := map[string]Interface{}
	for _, in := range prev.Interfaces {
		prevIf[in.ID] = in
	}
	nextIf := map[string]bool{}
	for _, in := range next.Interfaces {
		nextIf[in.ID] = true
		old, ok := prevIf[in.ID]
		switch {
		case !ok:
			parts = append(parts, "interface "+in.Name+" added")
		case old.Disabled != in.Disabled:
			parts = append(parts, "interface "+in.Name+map[bool]string{true: " disabled", false: " enabled"}[in.Disabled])
		case !same(old, in):
			parts = append(parts, "interface "+in.Name+" edited")
		}
	}
	for _, in := range prev.Interfaces {
		if !nextIf[in.ID] {
			parts = append(parts, "interface "+in.Name+" removed")
		}
	}

	prevG := map[string]Group{}
	for _, g := range prev.Groups {
		prevG[g.ID] = g
	}
	nextG := map[string]bool{}
	for _, g := range next.Groups {
		nextG[g.ID] = true
		old, ok := prevG[g.ID]
		switch {
		case !ok:
			parts = append(parts, "group "+g.Name+" added")
		case !same(old, g):
			parts = append(parts, "group "+g.Name+" edited")
		}
	}
	for _, g := range prev.Groups {
		if !nextG[g.ID] {
			parts = append(parts, "group "+g.Name+" removed")
		}
	}

	ifName := func(c *Config, id string) string {
		if id == "" {
			return "Any interface"
		}
		if in := c.InterfaceByID(id); in != nil {
			return in.Name
		}
		return id
	}
	prevR := map[string]Rule{}
	for _, r := range prev.Rules {
		prevR[r.ID] = r
	}
	nextR := map[string]bool{}
	added := map[string]int{}
	var addedOrder []string
	edited := 0
	for _, r := range next.Rules {
		nextR[r.ID] = true
		old, ok := prevR[r.ID]
		if !ok {
			n := ifName(next, r.Interface)
			if added[n] == 0 {
				addedOrder = append(addedOrder, n)
			}
			added[n]++
		} else if !same(old, r) {
			edited++
		}
	}
	for _, n := range addedOrder {
		parts = append(parts, fmt.Sprintf("+%d %s on %s", added[n], plural(added[n], "rule"), n))
	}
	removed := map[string]int{}
	var removedOrder []string
	for _, r := range prev.Rules {
		if !nextR[r.ID] {
			n := ifName(prev, r.Interface)
			if removed[n] == 0 {
				removedOrder = append(removedOrder, n)
			}
			removed[n]++
		}
	}
	for _, n := range removedOrder {
		parts = append(parts, fmt.Sprintf("-%d %s on %s", removed[n], plural(removed[n], "rule"), n))
	}
	if edited > 0 {
		parts = append(parts, fmt.Sprintf("%d %s edited", edited, plural(edited, "rule")))
	}
	if len(addedOrder) == 0 && len(removedOrder) == 0 && edited == 0 && !sameOrder(prev.Rules, next.Rules) {
		parts = append(parts, "rules reordered")
	}

	prevGw := map[string]Gateway{}
	for _, g := range prev.Gateways {
		prevGw[g.ID] = g
	}
	nextGw := map[string]bool{}
	for _, g := range next.Gateways {
		nextGw[g.ID] = true
		old, ok := prevGw[g.ID]
		switch {
		case !ok:
			parts = append(parts, "gateway "+g.Name+" added")
		case !same(old, g):
			parts = append(parts, "gateway "+g.Name+" edited")
		}
	}
	for _, g := range prev.Gateways {
		if !nextGw[g.ID] {
			parts = append(parts, "gateway "+g.Name+" removed")
		}
	}
	prevRt := map[string]StaticRoute{}
	for _, r := range prev.Routes {
		prevRt[r.ID] = r
	}
	nextRt := map[string]bool{}
	for _, r := range next.Routes {
		nextRt[r.ID] = true
		old, ok := prevRt[r.ID]
		switch {
		case !ok:
			parts = append(parts, "route to "+r.Destination+" added")
		case !same(old, r):
			parts = append(parts, "route to "+r.Destination+" edited")
		}
	}
	for _, r := range prev.Routes {
		if !nextRt[r.ID] {
			parts = append(parts, "route to "+r.Destination+" removed")
		}
	}
	pf := func(c *Config) map[string]any {
		m := map[string]any{}
		for _, f := range c.PortForwards {
			m[f.ID] = f
		}
		return m
	}
	sn := func(c *Config) map[string]any {
		m := map[string]any{}
		for _, r := range c.SNATRules {
			m[r.ID] = r
		}
		return m
	}
	parts = append(parts, countChanges(pf(prev), pf(next), "port forward")...)
	snParts := countChanges(sn(prev), sn(next), "outbound NAT rule")
	parts = append(parts, snParts...)
	if len(snParts) == 0 {
		for i := range next.SNATRules { // same set, first match wins: order matters
			if next.SNATRules[i].ID != prev.SNATRules[i].ID {
				parts = append(parts, "outbound NAT rules reordered")
				break
			}
		}
	}
	if outbound(prev) != outbound(next) {
		parts = append(parts, "outbound NAT: "+outbound(next))
	}

	parts = append(parts, summarizeServices(prev, next)...)
	parts = append(parts, summarizeDDNS(prev, next)...)
	parts = append(parts, summarizeIDS(prev, next)...)

	if prev.Settings.Mode != next.Settings.Mode {
		parts = append(parts, "mode: "+next.Settings.Mode)
	}
	if prev.Settings.AntiLockout != next.Settings.AntiLockout {
		parts = append(parts, map[bool]string{true: "anti-lockout on", false: "anti-lockout off"}[next.Settings.AntiLockout])
	}
	if prev.Settings.MgmtInterface != next.Settings.MgmtInterface {
		parts = append(parts, "management: "+next.Settings.MgmtInterface)
	}

	if len(parts) == 0 {
		return "no changes"
	}
	return strings.Join(parts, " · ")
}

func same(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func sameOrder(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func outbound(c *Config) string {
	if c.Settings.OutboundNAT == "" {
		return "automatic"
	}
	return c.Settings.OutboundNAT
}

// countChanges: "+N x", "-N x", "N x edited" between two id → value maps.
func countChanges(prev, next map[string]any, word string) []string {
	add, del, ed := 0, 0, 0
	for id, v := range next {
		if old, ok := prev[id]; !ok {
			add++
		} else if !same(old, v) {
			ed++
		}
	}
	for id := range prev {
		if _, ok := next[id]; !ok {
			del++
		}
	}
	var out []string
	if add > 0 {
		out = append(out, fmt.Sprintf("+%d %s", add, plural(add, word)))
	}
	if del > 0 {
		out = append(out, fmt.Sprintf("-%d %s", del, plural(del, word)))
	}
	if ed > 0 {
		out = append(out, fmt.Sprintf("%d %s edited", ed, plural(ed, word)))
	}
	return out
}
