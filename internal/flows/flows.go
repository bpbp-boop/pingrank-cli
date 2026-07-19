// Package flows turns raw socket-table entries and ETW flow samples into a
// ranked list of candidate game-server endpoints.
//
// Why this package exists: the Windows UDP socket table has no remote
// addresses, so UDP remote endpoints come from the ETW kernel-network
// observer (internal/etw) when running elevated. TCP remotes come straight
// from the socket table. This package is pure logic over those
// observations so the heuristics are table-testable.
package flows

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Proto is the transport protocol of an observed flow.
type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// Source says where an observation came from.
type Source string

const (
	SourceTCPTable Source = "tcp-table"
	SourceETW      Source = "etw"
)

// Confidence buckets for ranked candidates.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// Observation is one remote endpoint seen for the game during one poll.
type Observation struct {
	Proto  Proto
	Remote netip.AddrPort
	Source Source
	// Bidirectional: traffic seen in both directions (ETW), or an
	// established TCP connection.
	Bidirectional bool
	// Packets seen this poll (0 when the source has no packet counts).
	Packets     uint64
	SentPackets uint64
	RecvPackets uint64
	SentBytes   uint64
	RecvBytes   uint64
}

// Candidate is a ranked possible game-server endpoint.
type Candidate struct {
	Proto      Proto          `json:"proto"`
	Remote     netip.AddrPort `json:"remote"`
	Source     Source         `json:"source"`
	Confidence Confidence     `json:"confidence"`
	// Relay: the endpoint sits in a known relay fleet (e.g. Valve SDR).
	// The measurement is to the relay, not the game server behind it.
	Relay         bool     `json:"relay,omitempty"`
	RelayLabel    string   `json:"relayLabel,omitempty"`
	Reasons       []string `json:"reasons"`
	ObservedPolls int      `json:"observedPolls,omitempty"`
	SentPackets   uint64   `json:"sentPackets,omitempty"`
	RecvPackets   uint64   `json:"recvPackets,omitempty"`
	SentBytes     uint64   `json:"sentBytes,omitempty"`
	RecvBytes     uint64   `json:"recvBytes,omitempty"`
	Bidirectional bool     `json:"bidirectional,omitempty"`
	score         int
	packets       uint64
}

// GameHints is per-game knowledge (parsed from a detect signature) that
// sharpens ranking. Zero value changes nothing.
type GameHints struct {
	PortRanges []PortRange
	RelayNets  []netip.Prefix
	RelayLabel string
}

// PortRange is inclusive; a single port is Lo == Hi.
type PortRange struct{ Lo, Hi uint16 }

func (r PortRange) contains(p uint16) bool { return p >= r.Lo && p <= r.Hi }

// ParseHints converts signature hint strings ("7000-9000" ports,
// "155.133.0.0/16" CIDRs) into a GameHints. Malformed entries error rather
// than silently vanish — signatures are curated data and typos should be
// caught in tests.
func ParseHints(expectedPorts, relayCIDRs []string, relayLabel string) (GameHints, error) {
	var h GameHints
	for _, s := range expectedPorts {
		lo, hi, ok := strings.Cut(s, "-")
		if !ok {
			hi = lo
		}
		loN, err1 := strconv.ParseUint(strings.TrimSpace(lo), 10, 16)
		hiN, err2 := strconv.ParseUint(strings.TrimSpace(hi), 10, 16)
		if err1 != nil || err2 != nil || loN > hiN {
			return GameHints{}, fmt.Errorf("bad port range %q", s)
		}
		h.PortRanges = append(h.PortRanges, PortRange{Lo: uint16(loN), Hi: uint16(hiN)})
	}
	for _, s := range relayCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(s))
		if err != nil {
			return GameHints{}, fmt.Errorf("bad relay CIDR %q: %w", s, err)
		}
		h.RelayNets = append(h.RelayNets, p)
	}
	h.RelayLabel = relayLabel
	return h, nil
}

func (h *GameHints) portExpected(p uint16) bool {
	if h == nil {
		return false
	}
	for _, r := range h.PortRanges {
		if r.contains(p) {
			return true
		}
	}
	return false
}

// PortExpected reports whether p is in the game's curated server ranges.
func (h *GameHints) PortExpected(p uint16) bool { return h.portExpected(p) }

func (h *GameHints) relayNet(a netip.Addr) bool {
	if h == nil {
		return false
	}
	for _, p := range h.RelayNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// stablePolls is how many consecutive polls a flow must appear in to count
// as "stable" (plan: 3+ polls over ~10 seconds).
const stablePolls = 3

// Collector accumulates per-poll observations and ranks candidates.
type Collector struct {
	poll   int // current poll number, 1-based after first AddPoll
	tracks map[trackKey]*track
	hints  *GameHints
}

type trackKey struct {
	proto  Proto
	remote netip.AddrPort
}

type track struct {
	source                   Source
	bidirectional            bool // true if any poll saw it bidirectional
	packets                  uint64
	sentPackets, recvPackets uint64
	sentBytes, recvBytes     uint64
	lastPoll                 int
	consecutive              int
	maxConsecutive           int
}

// NewCollector creates a collector; hints may be nil (no game-specific
// knowledge).
func NewCollector(hints *GameHints) *Collector {
	return &Collector{tracks: make(map[trackKey]*track), hints: hints}
}

// AddPoll records one polling interval's observations.
func (c *Collector) AddPoll(obs []Observation) {
	c.poll++
	seen := make(map[trackKey]bool)
	for _, o := range obs {
		key := trackKey{proto: o.Proto, remote: o.Remote}
		if seen[key] {
			// merge duplicate observations within a poll
			t := c.tracks[key]
			t.bidirectional = t.bidirectional || o.Bidirectional
			t.packets += o.Packets
			t.sentPackets += o.SentPackets
			t.recvPackets += o.RecvPackets
			t.sentBytes += o.SentBytes
			t.recvBytes += o.RecvBytes
			continue
		}
		seen[key] = true
		t := c.tracks[key]
		if t == nil {
			t = &track{source: o.Source}
			c.tracks[key] = t
		}
		if t.lastPoll == c.poll-1 {
			t.consecutive++
		} else {
			t.consecutive = 1
		}
		t.lastPoll = c.poll
		if t.consecutive > t.maxConsecutive {
			t.maxConsecutive = t.consecutive
		}
		t.bidirectional = t.bidirectional || o.Bidirectional
		t.packets += o.Packets
		t.sentPackets += o.SentPackets
		t.recvPackets += o.RecvPackets
		t.sentBytes += o.SentBytes
		t.recvBytes += o.RecvBytes
	}
}

// Polls returns how many polls have been added.
func (c *Collector) Polls() int { return c.poll }

// Candidates ranks everything observed so far, applying the filtering
// heuristics in the plan's priority order:
//  1. remote must be public (RFC1918, loopback, link-local etc. excluded)
//  2. remote port 443 excluded unless nothing else remains
//  3. flows stable across 3+ consecutive polls preferred
//  4. UDP preferred over TCP
func (c *Collector) Candidates() []Candidate {
	var nonTLS, tlsOnly []Candidate
	for key, t := range c.tracks {
		// Historical polls establish stability, but only endpoints observed
		// in the latest poll are still candidates. Without this guard a
		// finished match can outrank its replacement until the entire
		// sliding window ages out.
		if t.lastPoll != c.poll {
			continue
		}
		if !IsPublic(key.remote.Addr()) {
			continue
		}
		cand := c.rank(key, t)
		if key.remote.Port() == 443 {
			tlsOnly = append(tlsOnly, cand)
		} else {
			nonTLS = append(nonTLS, cand)
		}
	}

	out := nonTLS
	if len(out) == 0 {
		// Heuristic 2: only fall back to port 443 when nothing else exists.
		for i := range tlsOnly {
			tlsOnly[i].Confidence = ConfidenceLow
			tlsOnly[i].Reasons = append(tlsOnly[i].Reasons,
				"remote port 443 (likely telemetry/CDN); kept only because no other candidate exists")
		}
		out = tlsOnly
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].score != out[j].score {
			return out[i].score > out[j].score
		}
		// Volume tiebreak: multi-flow games (game traffic vs voice on
		// the same server) rank the chattier flow first.
		if out[i].packets != out[j].packets {
			return out[i].packets > out[j].packets
		}
		return out[i].Remote.String() < out[j].Remote.String() // determinism
	})
	return out
}

// rank scores one track and assigns a confidence bucket with reasons.
func (c *Collector) rank(key trackKey, t *track) Candidate {
	stable := t.maxConsecutive >= stablePolls
	cand := Candidate{
		Proto:  key.proto,
		Remote: key.remote,
		Source: t.source,
	}

	if key.proto == ProtoUDP {
		cand.score += 40
		cand.Reasons = append(cand.Reasons, "UDP flow (game traffic is typically UDP)")
	} else {
		cand.Reasons = append(cand.Reasons, "TCP connection")
	}
	if stable {
		cand.score += 30
		cand.Reasons = append(cand.Reasons,
			fmt.Sprintf("stable: seen in %d consecutive polls", t.maxConsecutive))
	} else {
		cand.Reasons = append(cand.Reasons,
			fmt.Sprintf("not yet stable: seen in %d consecutive polls (want %d+)", t.maxConsecutive, stablePolls))
	}
	if t.bidirectional {
		cand.score += 20
		cand.Reasons = append(cand.Reasons, "bidirectional traffic")
	}
	// Tiebreak on traffic volume without letting it outweigh the
	// structural signals above.
	if t.packets > 0 {
		cand.score += min(int(t.packets), 10)
	}
	cand.packets = t.packets
	cand.ObservedPolls = t.maxConsecutive
	cand.SentPackets, cand.RecvPackets = t.sentPackets, t.recvPackets
	cand.SentBytes, cand.RecvBytes = t.sentBytes, t.recvBytes
	cand.Bidirectional = t.bidirectional

	if c.hints.portExpected(key.remote.Port()) {
		cand.score += 15
		cand.Reasons = append(cand.Reasons, "remote port is in this game's expected server port range")
	}
	if c.hints.relayNet(key.remote.Addr()) {
		cand.Relay = true
		cand.RelayLabel = c.hints.RelayLabel
		cand.Reasons = append(cand.Reasons, fmt.Sprintf(
			"endpoint is in the %s relay network — measurement is to the relay, not the game server", c.hints.RelayLabel))
	}

	switch {
	case key.proto == ProtoUDP && stable && t.bidirectional:
		cand.Confidence = ConfidenceHigh
	case (key.proto == ProtoUDP && (stable || t.bidirectional)) ||
		(key.proto == ProtoTCP && stable && t.bidirectional):
		cand.Confidence = ConfidenceMedium
	default:
		cand.Confidence = ConfidenceLow
	}
	return cand
}

// IsPublic reports whether addr is a public, routable unicast address —
// the only kind that can be an internet game server. Excludes RFC1918,
// loopback, link-local, CGNAT (RFC 6598), multicast, unspecified, and
// broadcast.
func IsPublic(addr netip.Addr) bool {
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() ||
		addr.IsPrivate() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() {
		return false
	}
	if addr.Is4() {
		b := addr.As4()
		if b == [4]byte{255, 255, 255, 255} {
			return false
		}
		// RFC 6598 carrier-grade NAT: 100.64.0.0/10
		if b[0] == 100 && b[1] >= 64 && b[1] <= 127 {
			return false
		}
	}
	return true
}
