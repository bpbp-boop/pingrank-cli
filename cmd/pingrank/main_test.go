package main

import (
	"net/netip"
	"testing"

	"pingrank.gg/internal/etw"
	"pingrank.gg/internal/flows"
	"pingrank.gg/internal/probe"
)

type fakeEndpointProber struct {
	protocol probe.Stats
	probed   bool
}

func (p *fakeEndpointProber) Probe(target netip.Addr) (probe.Result, error) {
	p.probed = true
	return probe.Result{Target: target, Probed: target, Method: "direct", Stats: probe.Stats{Sent: 5, Received: 5}}, nil
}

func (p *fakeEndpointProber) Protocol(_ string, _ netip.AddrPort, _ int) (probe.Stats, error) {
	return p.protocol, nil
}

func TestMeasureCandidatePrefersProtocol(t *testing.T) {
	p := &fakeEndpointProber{protocol: probe.Stats{Sent: 5, Received: 5, AvgMs: 12}}
	res, err := measureCandidate(p, flows.Candidate{
		Proto: flows.ProtoUDP, Remote: netip.MustParseAddrPort("1.2.3.4:27015"),
	}, "a2s")
	if err != nil || res.Method != "protocol" || p.probed {
		t.Fatalf("result=%+v fallback=%v err=%v", res, p.probed, err)
	}
}

func TestMeasureCandidateFallsBackWhenProtocolDoesNotAnswer(t *testing.T) {
	p := &fakeEndpointProber{protocol: probe.Stats{Sent: 5}}
	res, err := measureCandidate(p, flows.Candidate{
		Proto: flows.ProtoUDP, Remote: netip.MustParseAddrPort("1.2.3.4:27015"),
	}, "a2s")
	if err != nil || res.Method != "direct" || !p.probed {
		t.Fatalf("result=%+v fallback=%v err=%v", res, p.probed, err)
	}
}

func TestETWHealthDegraded(t *testing.T) {
	base := etw.Health{EventsLost: 1, BuffersLost: 2, SchemaErrors: 3}
	if etwHealthDegraded(base, base) {
		t.Fatal("unchanged health reported degraded")
	}
	for _, current := range []etw.Health{
		{EventsLost: 2, BuffersLost: 2, SchemaErrors: 3},
		{EventsLost: 1, BuffersLost: 3, SchemaErrors: 3},
		{EventsLost: 1, BuffersLost: 2, SchemaErrors: 4},
	} {
		if !etwHealthDegraded(base, current) {
			t.Errorf("health delta %+v was not reported degraded", current)
		}
	}
}
