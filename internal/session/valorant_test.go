package session

import (
	"net/netip"
	"testing"

	"pingrank.gg/internal/flows"
)

func TestValorantRequiresGamePortAndTraffic(t *testing.T) {
	for _, tc := range []struct{ endpoint, role, eligibility string }{
		{"151.106.248.1:7484", "game", EligibilityProbable},
		{"151.106.248.1:8181", "game", EligibilityProbable},
		{"20.157.218.16:54000", "voice", EligibilityDiagnostic},
		{"20.153.140.130:54018", "unknown", EligibilityDiagnostic},
		{"151.106.248.1:8088", "spectator", EligibilityDiagnostic},
	} {
		seg := &segment{cand: flows.Candidate{Proto: flows.ProtoUDP, Source: flows.SourceETW,
			Remote: netip.MustParseAddrPort(tc.endpoint)}, traffic: &TrafficEvidence{
			Bidirectional: true, SentPackets: 100, RecvPackets: 100, PacketsPerSecond: 200}}
		classifySegment(seg, &game{id: "valorant"}, nil)
		if seg.role != tc.role || seg.eligibility != tc.eligibility {
			t.Fatalf("%s: %+v", tc.endpoint, seg)
		}
		seg.traffic = nil
		classifySegment(seg, &game{id: "valorant"}, nil)
		if seg.eligibility != EligibilityDiagnostic {
			t.Fatal("missing traffic admitted")
		}
	}
}
