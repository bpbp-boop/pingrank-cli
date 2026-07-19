package flows

import (
	"net/netip"
	"testing"
)

func ap(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

func TestIsPublic(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"8.8.8.8", true},
		{"155.133.252.1", true},    // a Valve relay, typical game server
		{"10.0.0.1", false},        // RFC1918
		{"172.16.5.9", false},      // RFC1918
		{"192.168.1.1", false},     // RFC1918
		{"127.0.0.1", false},       // loopback
		{"169.254.10.10", false},   // link-local
		{"100.64.0.1", false},      // CGNAT low edge
		{"100.127.255.255", false}, // CGNAT high edge
		{"100.63.255.255", true},   // just below CGNAT
		{"100.128.0.0", true},      // just above CGNAT
		{"224.0.0.5", false},       // multicast
		{"255.255.255.255", false}, // broadcast
		{"0.0.0.0", false},         // unspecified
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := IsPublic(netip.MustParseAddr(tt.addr)); got != tt.want {
				t.Errorf("IsPublic(%s) = %v, want %v", tt.addr, got, tt.want)
			}
		})
	}
}

// obsPoll builds one poll's observation list.
func udpObs(remote string, bidi bool, pkts uint64) Observation {
	return Observation{Proto: ProtoUDP, Remote: ap(remote), Source: SourceETW, Bidirectional: bidi, Packets: pkts}
}

func tcpObs(remote string) Observation {
	return Observation{Proto: ProtoTCP, Remote: ap(remote), Source: SourceTCPTable, Bidirectional: true}
}

func collect(polls ...[]Observation) []Candidate {
	return collectHinted(nil, polls...)
}

func collectHinted(hints *GameHints, polls ...[]Observation) []Candidate {
	c := NewCollector(hints)
	for _, p := range polls {
		c.AddPoll(p)
	}
	return c.Candidates()
}

func TestPrivateRemotesFiltered(t *testing.T) {
	cands := collect(
		[]Observation{udpObs("192.168.1.50:27015", true, 100), tcpObs("127.0.0.1:9100")},
	)
	if len(cands) != 0 {
		t.Fatalf("expected no candidates for private/loopback remotes, got %v", cands)
	}
}

func TestPort443ExcludedWhenAlternativesExist(t *testing.T) {
	poll := []Observation{
		tcpObs("34.120.10.10:443"),
		udpObs("155.133.252.1:27015", true, 50),
	}
	cands := collect(poll, poll, poll)
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d: %v", len(cands), cands)
	}
	if cands[0].Remote.Port() != 27015 {
		t.Errorf("expected the non-443 endpoint to survive, got %v", cands[0].Remote)
	}
}

func TestPort443KeptWhenNothingElse(t *testing.T) {
	poll := []Observation{tcpObs("34.120.10.10:443")}
	cands := collect(poll, poll, poll)
	if len(cands) != 1 {
		t.Fatalf("expected the 443 fallback candidate, got %d", len(cands))
	}
	if cands[0].Confidence != ConfidenceLow {
		t.Errorf("443 fallback must be low confidence, got %s", cands[0].Confidence)
	}
}

func TestStableBidirectionalUDPIsHighConfidence(t *testing.T) {
	poll := []Observation{udpObs("155.133.252.1:27015", true, 200)}
	cands := collect(poll, poll, poll)
	if len(cands) != 1 || cands[0].Confidence != ConfidenceHigh {
		t.Fatalf("expected high confidence, got %v", cands)
	}
}

func TestCandidateCarriesTrafficEvidence(t *testing.T) {
	o := Observation{Proto: ProtoUDP, Remote: ap("3.25.156.96:8172"), Source: SourceETW,
		Bidirectional: true, Packets: 7, SentPackets: 3, RecvPackets: 4, SentBytes: 300, RecvBytes: 800}
	c := collect([]Observation{o}, []Observation{o}, []Observation{o})[0]
	if c.ObservedPolls != 3 || c.SentPackets != 9 || c.RecvPackets != 12 ||
		c.SentBytes != 900 || c.RecvBytes != 2400 || !c.Bidirectional {
		t.Fatalf("traffic evidence lost: %+v", c)
	}
}

func TestUnstableUDPIsNotHigh(t *testing.T) {
	// Seen in polls 1 and 3 only — never 3 consecutive.
	target := "155.133.252.1:27015"
	cands := collect(
		[]Observation{udpObs(target, true, 10)},
		nil,
		[]Observation{udpObs(target, true, 10)},
	)
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}
	if cands[0].Confidence == ConfidenceHigh {
		t.Errorf("non-consecutive flow must not be high confidence")
	}
}

func TestUDPRankedAboveTCP(t *testing.T) {
	poll := []Observation{
		tcpObs("104.16.0.9:8080"),
		udpObs("155.133.252.1:27015", true, 100),
	}
	cands := collect(poll, poll, poll)
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(cands))
	}
	if cands[0].Proto != ProtoUDP {
		t.Errorf("UDP must outrank TCP, got %s first", cands[0].Proto)
	}
}

func TestCandidatesExcludeEndpointsAbsentFromLatestPoll(t *testing.T) {
	old := "1.1.1.1:7000"
	newEndpoint := "2.2.2.2:8000"
	cands := collect(
		[]Observation{udpObs(old, true, 1000)},
		[]Observation{udpObs(old, true, 1000)},
		[]Observation{udpObs(old, true, 1000)},
		[]Observation{udpObs(newEndpoint, true, 10)},
	)
	if len(cands) != 1 || cands[0].Remote != ap(newEndpoint) {
		t.Fatalf("stale endpoint remained eligible: %+v", cands)
	}
}

func TestConfidenceBuckets(t *testing.T) {
	udpTarget := "155.133.252.1:27015"
	tests := []struct {
		name  string
		polls [][]Observation
		proto Proto
		want  Confidence
	}{
		{
			name:  "udp stable unidirectional is medium",
			polls: [][]Observation{{udpObs(udpTarget, false, 5)}, {udpObs(udpTarget, false, 5)}, {udpObs(udpTarget, false, 5)}},
			proto: ProtoUDP,
			want:  ConfidenceMedium,
		},
		{
			name:  "udp bidirectional single poll is medium",
			polls: [][]Observation{{udpObs(udpTarget, true, 5)}},
			proto: ProtoUDP,
			want:  ConfidenceMedium,
		},
		{
			name:  "udp unidirectional single poll is low",
			polls: [][]Observation{{udpObs(udpTarget, false, 5)}},
			proto: ProtoUDP,
			want:  ConfidenceLow,
		},
		{
			name:  "tcp established stable is medium",
			polls: [][]Observation{{tcpObs("104.16.0.9:8080")}, {tcpObs("104.16.0.9:8080")}, {tcpObs("104.16.0.9:8080")}},
			proto: ProtoTCP,
			want:  ConfidenceMedium,
		},
		{
			name:  "tcp single poll is low",
			polls: [][]Observation{{tcpObs("104.16.0.9:8080")}},
			proto: ProtoTCP,
			want:  ConfidenceLow,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cands := collect(tt.polls...)
			if len(cands) != 1 {
				t.Fatalf("expected 1 candidate, got %d", len(cands))
			}
			if cands[0].Confidence != tt.want {
				t.Errorf("confidence = %s, want %s (reasons: %v)", cands[0].Confidence, tt.want, cands[0].Reasons)
			}
		})
	}
}

func TestParseHints(t *testing.T) {
	h, err := ParseHints([]string{"7000-9000", "27015"}, []string{"155.133.0.0/16"}, "valve-sdr")
	if err != nil {
		t.Fatal(err)
	}
	if !h.portExpected(8000) || !h.portExpected(27015) || h.portExpected(6999) || h.portExpected(27016) {
		t.Errorf("port ranges wrong: %+v", h.PortRanges)
	}
	if !h.relayNet(netip.MustParseAddr("155.133.252.1")) || h.relayNet(netip.MustParseAddr("8.8.8.8")) {
		t.Error("relay prefix matching wrong")
	}

	for _, bad := range [][]string{{"9000-7000"}, {"abc"}, {"70000"}} {
		if _, err := ParseHints(bad, nil, ""); err == nil {
			t.Errorf("ParseHints(%v) did not error", bad)
		}
	}
	if _, err := ParseHints(nil, []string{"not-a-cidr"}, ""); err == nil {
		t.Error("bad CIDR did not error")
	}
}

func TestSignatureHintsAllParse(t *testing.T) {
	// nil hints must be safe everywhere.
	var h *GameHints
	if h.portExpected(80) || h.relayNet(netip.MustParseAddr("1.1.1.1")) {
		t.Error("nil hints matched something")
	}
}

func TestExpectedPortBoostsRanking(t *testing.T) {
	hints, err := ParseHints([]string{"7000-9000"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	// Two otherwise-identical UDP flows; only one is in the expected range.
	poll := []Observation{
		udpObs("52.10.10.10:30000", true, 50),
		udpObs("3.26.118.225:7832", true, 50),
	}
	cands := collectHinted(&hints, poll, poll, poll)
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(cands))
	}
	if cands[0].Remote.Port() != 7832 {
		t.Errorf("expected-port endpoint did not rank first: %v", cands[0].Remote)
	}
}

func TestRelayTagging(t *testing.T) {
	hints, err := ParseHints(nil, []string{"155.133.0.0/16"}, "valve-sdr")
	if err != nil {
		t.Fatal(err)
	}
	poll := []Observation{udpObs("155.133.252.1:27015", true, 50)}
	cands := collectHinted(&hints, poll, poll, poll)
	if len(cands) != 1 {
		t.Fatalf("expected 1 candidate, got %d", len(cands))
	}
	if !cands[0].Relay || cands[0].RelayLabel != "valve-sdr" {
		t.Errorf("relay endpoint not tagged: %+v", cands[0])
	}
	// Relay tagging must not change confidence — it's still the right
	// thing to measure, just labelled.
	if cands[0].Confidence != ConfidenceHigh {
		t.Errorf("relay tag changed confidence: %s", cands[0].Confidence)
	}
}

func TestVolumeTiebreak(t *testing.T) {
	// Same server, two flows (game + voice): identical structural score,
	// the chattier flow must rank first.
	poll := []Observation{
		udpObs("3.26.118.225:7833", true, 40),  // voice
		udpObs("3.26.118.225:7832", true, 900), // game traffic
	}
	cands := collect(poll, poll, poll)
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(cands))
	}
	if cands[0].Remote.Port() != 7832 {
		t.Errorf("high-volume flow did not rank first: %v", cands[0].Remote)
	}
}

func TestDuplicateObservationsWithinPollMerge(t *testing.T) {
	target := "155.133.252.1:27015"
	// Same endpoint reported twice in one poll (e.g. two local sockets):
	// must count as one poll for stability, but merge bidirectionality.
	poll := []Observation{udpObs(target, false, 5), udpObs(target, true, 5)}
	cands := collect(poll)
	if len(cands) != 1 {
		t.Fatalf("expected 1 merged candidate, got %d", len(cands))
	}
	if cands[0].Confidence != ConfidenceMedium {
		t.Errorf("merged observation should be bidirectional (medium), got %s", cands[0].Confidence)
	}
}
