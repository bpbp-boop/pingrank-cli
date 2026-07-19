package probe

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"time"

	"pingrank.gg/internal/flows"
)

// a2sInfoQuery is the Valve A2S_INFO request: 0xFFFFFFFF header, 'T', and
// the literal "Source Engine Query\0" payload. Any reply — an info
// response (0x49) or a challenge (0x41) — proves the server processed our
// datagram on the real game port, so its round trip is a valid latency
// sample either way.
var a2sInfoQuery = append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x54}, "Source Engine Query\x00"...)

const maxProtocolProbeBurst = 5

// GameProtocolAllowed reports whether PingRank is allowed to send this active
// game-protocol probe for a detected game. The allowlist is deliberately
// compiled in rather than trusting the data-only signature file, so adding
// active traffic for another game or protocol requires an explicit code review.
func GameProtocolAllowed(gameID, method string) bool {
	switch gameID {
	case "cs2", "dota2":
		return method == "a2s"
	default:
		return false
	}
}

// Protocol sends count game-protocol probes to the endpoint and aggregates
// stats. Unlike ICMP this measures the actual UDP path and port the game
// uses, so it is preferred when the game's signature declares a method.
// Currently supported methods: "a2s" (Source-lineage servers).
func (IcmpProber) Protocol(method string, ep netip.AddrPort, count int) (Stats, error) {
	if method != "a2s" {
		return Stats{}, fmt.Errorf("probe: unknown protocol method %q", method)
	}
	if count < 1 || count > maxProtocolProbeBurst {
		return Stats{}, fmt.Errorf("probe: protocol burst must contain 1-%d packets, got %d", maxProtocolProbeBurst, count)
	}
	addr := ep.Addr()
	if !flows.IsPublic(addr) || ep.Port() == 0 {
		return Stats{}, fmt.Errorf("probe: refusing non-public game endpoint %s", ep)
	}
	// A2S works identically over IPv6; pick the socket family from the endpoint.
	network := "udp4"
	if addr.Is6() {
		network = "udp6"
	}
	// Use a separate UDP socket owned by PingRank. We never inject into the
	// game, reuse its socket/source port, or write to game process memory.
	conn, err := net.Dial(network, ep.String())
	if err != nil {
		return Stats{}, fmt.Errorf("probe: a2s dial %s: %w", ep, err)
	}
	defer conn.Close()

	s := Stats{Sent: count}
	buf := make([]byte, 2048)
	var sum float64
	for range count {
		start := time.Now()
		conn.SetDeadline(start.Add(pingTimeout))
		if _, err := conn.Write(a2sInfoQuery); err != nil {
			continue
		}
		n, err := conn.Read(buf)
		if err != nil || !validA2SResponse(buf[:n]) {
			continue
		}
		ms := float64(time.Since(start)) / float64(time.Millisecond)
		rtt := uint32(math.Round(ms))
		if s.Received == 0 {
			s.MinMs, s.MaxMs = rtt, rtt
		} else {
			s.MinMs = min(s.MinMs, rtt)
			s.MaxMs = max(s.MaxMs, rtt)
		}
		s.Received++
		sum += ms
	}
	if s.Received > 0 {
		s.AvgMs = sum / float64(s.Received)
	}
	s.LossPct = float64(s.Sent-s.Received) / float64(s.Sent) * 100
	return s, nil
}

func validA2SResponse(buf []byte) bool {
	if len(buf) < 5 || buf[0] != 0xff || buf[1] != 0xff || buf[2] != 0xff || buf[3] != 0xff {
		return false
	}
	// A2S_INFO or S2C_CHALLENGE. Other datagrams received on the connected
	// socket do not count as a successful game-protocol measurement.
	return buf[4] == 0x49 || buf[4] == 0x41
}
