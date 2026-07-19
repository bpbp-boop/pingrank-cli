package gamelog

import (
	"net/netip"
	"regexp"
	"strings"
)

// RocketLeagueParser extracts only endpoints tied to an actual server
// reservation/connection. In particular, it does not parse RegionPinger
// records: those are regional test hosts, not the current match server.
type RocketLeagueParser struct{}

var (
	rlGameURL = regexp.MustCompile(`GameURL="([^"]+)"`)
	rlPingURL = regexp.MustCompile(`PingURL="([^"]+)"`)
	rlBrowse  = regexp.MustCompile(`DevNet: Browse: (\[[0-9a-fA-F:]+\]|[0-9.]+):([0-9]+)(?:/|\s|$)`)
)

func (RocketLeagueParser) GameID() string      { return "rocketleague" }
func (RocketLeagueParser) DisplayName() string { return "Rocket League" }

func (RocketLeagueParser) ParseLine(line string) []Candidate {
	var result []Candidate
	if match := rlGameURL.FindStringSubmatch(line); match != nil {
		if endpoint, ok := parsePublicEndpoint(match[1]); ok {
			result = append(result, Candidate{Endpoint: endpoint, Role: "game", Protocol: "udp", Source: "reservation GameURL"})
		}
	}
	if match := rlPingURL.FindStringSubmatch(line); match != nil {
		if endpoint, ok := parsePublicEndpoint(match[1]); ok {
			result = append(result, Candidate{Endpoint: endpoint, Role: "ping", Protocol: "udp", Source: "reservation PingURL"})
		}
	}
	// Browse is a useful fallback in logs that do not include reservation
	// detail, and corroborates GameURL when both are present.
	if match := rlBrowse.FindStringSubmatch(line); match != nil {
		if endpoint, ok := parsePublicEndpoint(match[1] + ":" + match[2]); ok {
			result = append(result, Candidate{Endpoint: endpoint, Role: "game", Protocol: "udp", Source: "network Browse"})
		}
	}
	return result
}

func parsePublicEndpoint(value string) (netip.AddrPort, bool) {
	endpoint, err := netip.ParseAddrPort(strings.TrimSpace(value))
	if err != nil || endpoint.Port() == 0 {
		return netip.AddrPort{}, false
	}
	addr := endpoint.Addr().Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, endpoint.Port()), true
}
