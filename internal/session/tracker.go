package session

import (
	"net/netip"

	"pingrank.gg/internal/flows"
)

// confirmPolls is the flap guard from the plan: a new endpoint must be the
// top candidate for this many consecutive discovery polls before the
// active segment rotates, so a momentary parallel flow (matchmaking
// handshake, voice burst) doesn't fragment the session.
const confirmPolls = 2

// Tracker decides which endpoint the session is currently bound to. Pure
// logic over per-poll top candidates, table-testable.
type Tracker struct {
	active       *flows.Candidate
	pendingKey   endpointKey
	pendingCount int
}

type endpointKey struct {
	proto  flows.Proto
	remote netip.AddrPort
}

func keyOf(c *flows.Candidate) endpointKey {
	return endpointKey{proto: c.Proto, remote: c.Remote}
}

// Active returns the currently bound endpoint, nil before first lock.
func (t *Tracker) Active() *flows.Candidate { return t.active }

// Observe processes the top-ranked candidate of one discovery poll and
// reports whether the active endpoint rotated (including the first lock).
//
// minConf is the lowest confidence eligible to become the active endpoint.
// The recorder starts strict (high) and relaxes it over time so a session
// that can't produce a high-confidence endpoint (no ETW, or a game whose
// only visible flows are TCP/443) still measures *something*, clearly
// labelled with its confidence.
func (t *Tracker) Observe(top *flows.Candidate, minConf flows.Confidence) bool {
	if top == nil || confRank(top.Confidence) < confRank(minConf) {
		t.pendingCount = 0
		return false
	}

	if t.active == nil {
		// First lock: no flap guard needed, nothing to protect yet.
		t.active = top
		t.pendingCount = 0
		return true
	}

	if keyOf(top) == keyOf(t.active) {
		// Same endpoint still on top; refresh metadata (confidence may
		// have improved) and clear any pending challenger.
		t.active = top
		t.pendingCount = 0
		return false
	}

	if sameServer(top, t.active) {
		// Same server IP on a different port: multi-socket games (e.g.
		// Rocket League's game socket on 7716 and voice on 7717) flip
		// which flow tops the ranking per window. That's not a server
		// change — keep the segment bound to the original endpoint, just
		// let its confidence improve.
		if confRank(top.Confidence) > confRank(t.active.Confidence) {
			refreshed := *t.active
			refreshed.Confidence = top.Confidence
			t.active = &refreshed
		}
		t.pendingCount = 0
		return false
	}

	if keyOf(top) == t.pendingKey {
		t.pendingCount++
	} else {
		t.pendingKey = keyOf(top)
		t.pendingCount = 1
	}
	if t.pendingCount >= confirmPolls {
		t.active = top
		t.pendingCount = 0
		return true
	}
	return false
}

// sameServer treats two endpoints as one server when the IP and protocol
// match, regardless of port.
func sameServer(a, b *flows.Candidate) bool {
	return a.Proto == b.Proto && a.Remote.Addr() == b.Remote.Addr()
}

func confRank(c flows.Confidence) int {
	switch c {
	case flows.ConfidenceHigh:
		return 3
	case flows.ConfidenceMedium:
		return 2
	case flows.ConfidenceLow:
		return 1
	default:
		return 0
	}
}
