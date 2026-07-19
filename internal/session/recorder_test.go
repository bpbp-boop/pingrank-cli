package session

import (
	"net/netip"
	"testing"
	"time"

	"pingrank.gg/internal/detect"
	"pingrank.gg/internal/flows"
	"pingrank.gg/internal/gamelog"
)

type staticLister struct {
	processes []detect.Process
}

func TestRocketLeagueEligibilityAndLogPromotion(t *testing.T) {
	hints, err := flows.ParseHints([]string{"7000-9000"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	g := &game{id: "rocketleague", hints: &hints}
	platform := &segment{cand: flows.Candidate{Proto: flows.ProtoUDP, Remote: netip.MustParseAddrPort("155.133.238.178:27043")}}
	classifySegment(platform, g, nil)
	if platform.eligibility != EligibilityDiagnostic {
		t.Fatalf("platform flow = %q, want diagnostic", platform.eligibility)
	}
	match := &segment{cand: flows.Candidate{Proto: flows.ProtoUDP, Remote: netip.MustParseAddrPort("3.25.156.96:8172")}}
	classifySegment(match, g, nil)
	if match.eligibility != EligibilityProbable {
		t.Fatalf("expected-port flow = %q, want probable", match.eligibility)
	}
	logs := map[netip.AddrPort]gamelog.Candidate{match.cand.Remote: {Endpoint: match.cand.Remote, Role: "game", Source: "reservation GameURL"}}
	classifySegment(match, g, logs)
	if match.eligibility != EligibilityConfirmed || match.role != "game" || match.corroboratedBy == "" {
		t.Fatalf("log corroboration not applied: %+v", match)
	}
}

func TestPUBGEligibilityUsesSustainedUDPTraffic(t *testing.T) {
	g := &game{id: "pubg"}
	tcp := &segment{cand: flows.Candidate{Proto: flows.ProtoTCP, Source: flows.SourceTCPTable,
		Remote: netip.MustParseAddrPort("52.223.4.221:40002")}, traffic: &TrafficEvidence{Bidirectional: true}}
	quietUDP := &segment{cand: flows.Candidate{Proto: flows.ProtoUDP, Source: flows.SourceETW,
		Remote: netip.MustParseAddrPort("20.201.72.108:8081")}, traffic: &TrafficEvidence{
		PacketsPerSecond: .9, SentPackets: 27, RecvPackets: 27, Bidirectional: true}}
	matchUDP := &segment{cand: flows.Candidate{Proto: flows.ProtoUDP, Source: flows.SourceETW,
		Remote: netip.MustParseAddrPort("172.188.122.246:29685")}, traffic: &TrafficEvidence{
		PacketsPerSecond: 143, SentPackets: 5402, RecvPackets: 3176, Bidirectional: true}}

	for _, seg := range []*segment{tcp, quietUDP, matchUDP} {
		classifySegment(seg, g, nil)
	}
	if tcp.eligibility != EligibilityDiagnostic || tcp.eligibilityReason != "pubg_unconfirmed_tcp_flow" {
		t.Fatalf("TCP flow classification = %q (%q)", tcp.eligibility, tcp.eligibilityReason)
	}
	if quietUDP.eligibility != EligibilityDiagnostic || quietUDP.eligibilityReason != "pubg_insufficient_udp_traffic" {
		t.Fatalf("quiet UDP classification = %q (%q)", quietUDP.eligibility, quietUDP.eligibilityReason)
	}
	if matchUDP.eligibility != EligibilityProbable || matchUDP.eligibilityReason != "pubg_sustained_udp_traffic" {
		t.Fatalf("match UDP classification = %q (%q)", matchUDP.eligibility, matchUDP.eligibilityReason)
	}
}

func TestTrafficEvidenceRates(t *testing.T) {
	c := flows.Candidate{ObservedPolls: 3, SentPackets: 30, RecvPackets: 70,
		SentBytes: 3000, RecvBytes: 7000, Bidirectional: true}
	got := trafficEvidence(c, 10*time.Second)
	if got.PacketsPerSecond != 10 || got.BytesPerSecond != 1000 || got.ReceivePacketPct != 70 || !got.Bidirectional {
		t.Fatalf("traffic rates = %+v", got)
	}
}

func (l staticLister) Processes() ([]detect.Process, error) { return l.processes, nil }

func TestCurrentPIDsKeepsRecordedGameWhenEarlierSignatureAlsoRuns(t *testing.T) {
	sigs := []detect.Signature{
		{GameID: "first", DisplayName: "First", ExeNames: []string{"first.exe"}},
		{GameID: "recorded", DisplayName: "Recorded", ExeNames: []string{"recorded.exe"}},
	}
	r := NewRecorder(Config{Signatures: sigs}, Deps{Lister: staticLister{processes: []detect.Process{
		{PID: 10, ExeName: "first.exe"},
		{PID: 20, ExeName: "recorded.exe"},
	}}})

	got := r.currentPIDs(&game{id: "recorded", pids: map[uint32]bool{20: true}})
	if len(got) != 1 || !got[20] {
		t.Fatalf("currentPIDs = %v, want recorded game's PID 20", got)
	}
}

func TestCurrentPIDsCustomGame(t *testing.T) {
	r := NewRecorder(Config{GameExe: "custom.exe"}, Deps{Lister: staticLister{processes: []detect.Process{
		{PID: 42, ExeName: "CUSTOM.EXE"},
	}}})
	got := r.currentPIDs(&game{id: "custom", pids: map[uint32]bool{1: true}})
	if len(got) != 1 || !got[42] {
		t.Fatalf("currentPIDs = %v, want custom game's PID 42", got)
	}
}

func TestHealthDegraded(t *testing.T) {
	base := FlowHealth{EventsLost: 1, BuffersLost: 2, SchemaErrors: 3}
	if healthDegraded(base, base) {
		t.Fatal("unchanged health reported degraded")
	}
	for _, current := range []FlowHealth{
		{EventsLost: 2, BuffersLost: 2, SchemaErrors: 3},
		{EventsLost: 1, BuffersLost: 3, SchemaErrors: 3},
		{EventsLost: 1, BuffersLost: 2, SchemaErrors: 4},
	} {
		if !healthDegraded(base, current) {
			t.Errorf("health delta %+v was not reported degraded", current)
		}
	}
}
