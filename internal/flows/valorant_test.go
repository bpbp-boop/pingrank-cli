package flows

import (
	"net/netip"
	"testing"
)

func TestValorantPrefersGameOverBusyVoice(t *testing.T) {
	c := NewCollector(&GameHints{GameID: "valorant"})
	voice := Observation{Proto: ProtoUDP, Remote: netip.MustParseAddrPort("20.157.218.16:54000"), Source: SourceETW, Bidirectional: true, Packets: 10000}
	for range 3 {
		c.AddPoll([]Observation{voice})
	}
	game := Observation{Proto: ProtoUDP, Remote: netip.MustParseAddrPort("151.106.248.1:7484"), Source: SourceETW, Bidirectional: true, Packets: 100}
	c.AddPoll([]Observation{voice, game})
	got := c.Candidates()
	if len(got) != 2 || got[0].Remote != game.Remote || got[1].Confidence != ConfidenceLow {
		t.Fatalf("ranking = %+v", got)
	}
	c.AddPoll([]Observation{voice})
	if got := c.Candidates(); len(got) != 1 || got[0].Confidence != ConfidenceLow {
		t.Fatalf("voice fallback = %+v", got)
	}
}
