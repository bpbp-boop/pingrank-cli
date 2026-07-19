// Package gamelog extracts game-server endpoints from game-owned log files.
//
// Parsing is split into a generic scanner and per-game line parsers. A new
// game therefore adds a Parser implementation without changing the scanner or
// the CLI command.
package gamelog

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"sort"
)

// Candidate is one endpoint observation produced by a game-specific parser.
type Candidate struct {
	Endpoint netip.AddrPort
	Role     string // "game", "ping", etc.
	Protocol string // "udp", "tcp", or "unknown"
	Source   string // stable description of the log record that supplied it
}

// Parser recognizes endpoint-bearing lines for one game.
type Parser interface {
	GameID() string
	DisplayName() string
	DefaultLogPath() (string, error)
	ParseLine(line string) []Candidate
}

// Endpoint is one de-duplicated endpoint found in a log.
type Endpoint struct {
	Address     string   `json:"address"`
	IP          string   `json:"ip"`
	Port        uint16   `json:"port"`
	Role        string   `json:"role"`
	Protocol    string   `json:"protocol"`
	Sources     []string `json:"sources"`
	FirstLine   int      `json:"firstLine"`
	LastLine    int      `json:"lastLine"`
	Occurrences int      `json:"occurrences"`
}

// Server groups the service endpoints that belong to one host. Games often
// advertise separate gameplay, ping, beacon, or voice ports on the same IP.
type Server struct {
	IP        string     `json:"ip"`
	Endpoints []Endpoint `json:"endpoints"`
}

// GroupServers groups endpoints by IP while preserving endpoint order within
// each server and first-seen order between servers.
func GroupServers(endpoints []Endpoint) []Server {
	servers := make([]Server, 0)
	byIP := make(map[string]int)
	for _, endpoint := range endpoints {
		index, ok := byIP[endpoint.IP]
		if !ok {
			index = len(servers)
			byIP[endpoint.IP] = index
			servers = append(servers, Server{IP: endpoint.IP})
		}
		servers[index].Endpoints = append(servers[index].Endpoints, endpoint)
	}
	return servers
}

// Parse scans r with parser and returns de-duplicated endpoint observations.
// Lines may be large (Rocket League reservation records contain tokens), so
// the scanner limit is raised above bufio.Scanner's small default.
func Parse(r io.Reader, parser Parser) ([]Endpoint, error) {
	type found struct {
		endpoint Endpoint
		sources  map[string]bool
	}
	byKey := make(map[string]*found)

	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNumber := 0
	for s.Scan() {
		lineNumber++
		for _, candidate := range parser.ParseLine(s.Text()) {
			if !candidate.Endpoint.IsValid() {
				continue
			}
			key := candidate.Role + "|" + candidate.Protocol + "|" + candidate.Endpoint.String()
			item := byKey[key]
			if item == nil {
				item = &found{
					endpoint: Endpoint{
						Address: candidate.Endpoint.String(),
						IP:      candidate.Endpoint.Addr().String(),
						Port:    candidate.Endpoint.Port(),
						Role:    candidate.Role, Protocol: candidate.Protocol,
						FirstLine: lineNumber,
					},
					sources: make(map[string]bool),
				}
				byKey[key] = item
			}
			item.endpoint.LastLine = lineNumber
			item.endpoint.Occurrences++
			if candidate.Source != "" {
				item.sources[candidate.Source] = true
			}
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("scanning %s log: %w", parser.DisplayName(), err)
	}

	result := make([]Endpoint, 0, len(byKey))
	for _, item := range byKey {
		for source := range item.sources {
			item.endpoint.Sources = append(item.endpoint.Sources, source)
		}
		sort.Strings(item.endpoint.Sources)
		result = append(result, item.endpoint)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].FirstLine != result[j].FirstLine {
			return result[i].FirstLine < result[j].FirstLine
		}
		return result[i].Address < result[j].Address
	})
	return result, nil
}
