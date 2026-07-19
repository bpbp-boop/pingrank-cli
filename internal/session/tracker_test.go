package session

import (
	"net/netip"
	"testing"
	"time"

	"pingrank.gg/internal/flows"
)

func cand(remote string, conf flows.Confidence) *flows.Candidate {
	return &flows.Candidate{
		Proto:      flows.ProtoUDP,
		Remote:     netip.MustParseAddrPort(remote),
		Source:     flows.SourceETW,
		Confidence: conf,
	}
}

func TestTrackerLockRespectsConfidenceFloor(t *testing.T) {
	var tr Tracker
	if tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceMedium), flows.ConfidenceHigh) {
		t.Fatal("medium candidate locked past a high floor")
	}
	if tr.Active() != nil {
		t.Fatal("active set without lock")
	}
	if !tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceHigh), flows.ConfidenceHigh) {
		t.Fatal("high candidate did not lock immediately")
	}
	if tr.Active() == nil || tr.Active().Remote.Port() != 7000 {
		t.Fatalf("wrong active: %+v", tr.Active())
	}
}

func TestTrackerRelaxedFloors(t *testing.T) {
	var tr Tracker
	if !tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceMedium), flows.ConfidenceMedium) {
		t.Fatal("medium candidate did not lock at medium floor")
	}
	var tr2 Tracker
	if !tr2.Observe(cand("1.1.1.1:443", flows.ConfidenceLow), flows.ConfidenceLow) {
		t.Fatal("low candidate did not lock at low floor")
	}
	var tr3 Tracker
	if tr3.Observe(cand("1.1.1.1:443", flows.ConfidenceLow), flows.ConfidenceMedium) {
		t.Fatal("low candidate locked past a medium floor")
	}
}

func TestTrackerFlapGuard(t *testing.T) {
	var tr Tracker
	tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceHigh), flows.ConfidenceHigh)

	// One poll of a challenger must NOT rotate (matchmaking handshake).
	if tr.Observe(cand("2.2.2.2:8000", flows.ConfidenceHigh), flows.ConfidenceHigh) {
		t.Fatal("rotated after a single challenger poll")
	}
	if tr.Active().Remote.Port() != 7000 {
		t.Fatal("active changed without rotation")
	}
	// Second consecutive poll rotates.
	if !tr.Observe(cand("2.2.2.2:8000", flows.ConfidenceHigh), flows.ConfidenceHigh) {
		t.Fatal("did not rotate after 2 consecutive challenger polls")
	}
	if tr.Active().Remote.Port() != 8000 {
		t.Fatalf("active = %v, want 2.2.2.2:8000", tr.Active().Remote)
	}
}

func TestTrackerFlapGuardResetsOnOriginal(t *testing.T) {
	var tr Tracker
	tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceHigh), flows.ConfidenceHigh)
	tr.Observe(cand("2.2.2.2:8000", flows.ConfidenceHigh), flows.ConfidenceHigh) // challenger poll 1
	tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceHigh), flows.ConfidenceHigh) // original back on top
	// Challenger again: this is poll 1 of a fresh streak, must not rotate.
	if tr.Observe(cand("2.2.2.2:8000", flows.ConfidenceHigh), flows.ConfidenceHigh) {
		t.Fatal("flap guard streak was not reset by the original endpoint")
	}
}

func TestTrackerFlapGuardResetsOnDifferentChallenger(t *testing.T) {
	var tr Tracker
	tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceHigh), flows.ConfidenceHigh)
	tr.Observe(cand("2.2.2.2:8000", flows.ConfidenceHigh), flows.ConfidenceHigh)
	// A different challenger restarts the count.
	if tr.Observe(cand("3.3.3.3:9000", flows.ConfidenceHigh), flows.ConfidenceHigh) {
		t.Fatal("rotated on first poll of a new challenger")
	}
	if !tr.Observe(cand("3.3.3.3:9000", flows.ConfidenceHigh), flows.ConfidenceHigh) {
		t.Fatal("did not rotate after new challenger's second poll")
	}
}

func TestTrackerNilAndIneligibleResetPending(t *testing.T) {
	var tr Tracker
	tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceHigh), flows.ConfidenceHigh)
	tr.Observe(cand("2.2.2.2:8000", flows.ConfidenceHigh), flows.ConfidenceHigh) // challenger poll 1
	tr.Observe(nil, flows.ConfidenceHigh)                                        // quiet poll resets streak
	if tr.Observe(cand("2.2.2.2:8000", flows.ConfidenceHigh), flows.ConfidenceHigh) {
		t.Fatal("pending streak survived a nil poll")
	}
}

func TestTrackerSameServerDifferentPortNeverRotates(t *testing.T) {
	// Regression: Rocket League runs its game socket on :7716 and a
	// second socket on :7717 of the same server. The top-ranked flow
	// flips between them, which must not fragment the session.
	var tr Tracker
	tr.Observe(cand("3.26.125.197:7716", flows.ConfidenceMedium), flows.ConfidenceMedium)
	for range 5 {
		if tr.Observe(cand("3.26.125.197:7717", flows.ConfidenceHigh), flows.ConfidenceMedium) {
			t.Fatal("rotated between ports on the same server")
		}
	}
	if tr.Active().Remote.Port() != 7716 {
		t.Fatalf("active endpoint drifted to %v", tr.Active().Remote)
	}
	if tr.Active().Confidence != flows.ConfidenceHigh {
		t.Error("confidence not refreshed from same-server sibling flow")
	}
	// The sibling flow must not have primed the flap guard: a genuinely
	// new server still needs 2 consecutive polls.
	if tr.Observe(cand("52.63.10.10:7716", flows.ConfidenceHigh), flows.ConfidenceMedium) {
		t.Fatal("rotated to a new server after a single poll")
	}
	if !tr.Observe(cand("52.63.10.10:7716", flows.ConfidenceHigh), flows.ConfidenceMedium) {
		t.Fatal("did not rotate to a genuinely new server after 2 polls")
	}
}

func TestTrackerConfidenceRefreshWithoutRotation(t *testing.T) {
	var tr Tracker
	tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceMedium), flows.ConfidenceMedium)
	if tr.Observe(cand("1.1.1.1:7000", flows.ConfidenceHigh), flows.ConfidenceMedium) {
		t.Fatal("same endpoint reported as rotation")
	}
	if tr.Active().Confidence != flows.ConfidenceHigh {
		t.Fatal("confidence not refreshed on active endpoint")
	}
}

func TestMinConfidenceSchedule(t *testing.T) {
	tests := []struct {
		name     string
		degraded bool
		elapsed  time.Duration
		want     flows.Confidence
	}{
		{"full mode starts strict", false, 10 * time.Second, flows.ConfidenceHigh},
		{"full mode relaxes to medium", false, mediumLockAfter + time.Second, flows.ConfidenceMedium},
		{"full mode eventually accepts low", false, lowLockAfter + time.Second, flows.ConfidenceLow},
		{"degraded starts at medium (high unreachable)", true, 0, flows.ConfidenceMedium},
		{"degraded relaxes to low quickly", true, lowLockAfterDegraded + time.Second, flows.ConfidenceLow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := minConfidence(tt.degraded, tt.elapsed); got != tt.want {
				t.Errorf("minConfidence(%v, %v) = %s, want %s", tt.degraded, tt.elapsed, got, tt.want)
			}
		})
	}
}
