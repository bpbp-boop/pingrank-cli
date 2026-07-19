package session

import (
	"math"
	"testing"
	"time"

	"pingrank.gg/internal/cgnat"
)

func sample(avg float64, sent, received int) Sample {
	return Sample{
		RTTAvgMs: avg, RTTMinMs: uint32(avg), RTTMaxMs: uint32(avg),
		Sent: sent, Received: received, Method: "direct",
	}
}

func approx(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 0.001 {
		t.Errorf("%s = %v, want %v", name, got, want)
	}
}

func TestComputeStatsBasic(t *testing.T) {
	samples := []Sample{
		sample(10, 3, 3),
		sample(20, 3, 3),
		sample(30, 3, 3),
		sample(40, 3, 3),
	}
	s := ComputeStats(samples, 30*time.Second)
	if s.Samples != 4 {
		t.Errorf("Samples = %d, want 4", s.Samples)
	}
	approx(t, "DurationSec", s.DurationSec, 30)
	approx(t, "MinMs", s.MinMs, 10)
	approx(t, "MaxMs", s.MaxMs, 40)
	approx(t, "P50Ms", s.P50Ms, 20) // nearest-rank: ceil(0.5*4)=2nd value
	approx(t, "P95Ms", s.P95Ms, 40) // ceil(0.95*4)=4th value
	approx(t, "JitterMs", s.JitterMs, 10)
	approx(t, "LossPct", s.LossPct, 0)
}

func TestComputeStatsLossAndAllLossSamples(t *testing.T) {
	samples := []Sample{
		sample(10, 3, 3),
		{Sent: 3, Received: 0, LossPct: 100, Method: "direct"}, // dropped burst
		sample(14, 3, 2),
	}
	s := ComputeStats(samples, time.Minute)
	// 9 sent, 5 received → 44.4% loss
	approx(t, "LossPct", s.LossPct, 4.0/9.0*100)
	// latency stats over received samples only: 10, 14
	approx(t, "MinMs", s.MinMs, 10)
	approx(t, "MaxMs", s.MaxMs, 14)
	approx(t, "JitterMs", s.JitterMs, 4)
}

func TestComputeStatsNoData(t *testing.T) {
	s := ComputeStats(nil, time.Minute)
	if s.Samples != 0 || s.P50Ms != 0 || s.LossPct != 0 {
		t.Errorf("empty stats not zeroed: %+v", s)
	}
	s = ComputeStats([]Sample{{Sent: 3, Received: 0, LossPct: 100}}, time.Minute)
	approx(t, "LossPct", s.LossPct, 100)
	approx(t, "P50Ms", s.P50Ms, 0)
}

func TestPercentileNearestRank(t *testing.T) {
	sorted := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	approx(t, "p50", percentile(sorted, 50), 5)
	approx(t, "p95", percentile(sorted, 95), 10)
	approx(t, "p100", percentile(sorted, 100), 10)
	approx(t, "p1", percentile(sorted, 1), 1)
	approx(t, "single", percentile([]float64{7}, 95), 7)
}

func mkTime(sec int) time.Time {
	return time.Date(2026, 7, 13, 20, 0, sec, 0, time.UTC)
}

func TestSummarizeFullSession(t *testing.T) {
	s1 := sample(10, 3, 3)
	s2 := sample(20, 3, 3)
	st := ComputeStats([]Sample{s1, s2}, 20*time.Second)
	recs := []Record{
		{V: 1, T: RecSessionStart, Time: mkTime(0), GameID: "rl", DisplayName: "Rocket League", UDPDiscovery: "etw",
			CGNAT: cgnat.StatusConfirmed, CGNATEvidence: &cgnat.Evidence{Hop: 2, Range: "100.64.0.0/10"}, LocalAddressClass: cgnat.LocalPrivate},
		{V: 1, T: RecSegmentStart, Time: mkTime(5), Seq: 1, Proto: "udp", Endpoint: "1.2.3.4:7000", Confidence: "high", Source: "etw"},
		{V: 1, T: RecSample, Time: mkTime(10), Seq: 1, Sample: &s1},
		{V: 1, T: RecSample, Time: mkTime(20), Seq: 1, Sample: &s2},
		{V: 1, T: RecSegmentEnd, Time: mkTime(25), Seq: 1, Endpoint: "1.2.3.4:7000", Stats: &st},
		{V: 1, T: RecSessionEnd, Time: mkTime(30), Reason: "game-exit"},
	}
	sum := Summarize(recs)
	if sum.GameID != "rl" || sum.DisplayName != "Rocket League" || sum.UDPDiscovery != "etw" {
		t.Errorf("identity wrong: %+v", sum)
	}
	if sum.CGNAT != cgnat.StatusConfirmed || sum.CGNATEvidence == nil || sum.CGNATEvidence.Hop != 2 || sum.LocalAddressClass != cgnat.LocalPrivate {
		t.Errorf("CGNAT metadata wrong: %+v", sum)
	}
	if sum.Truncated {
		t.Error("complete session marked truncated")
	}
	if sum.EndReason != "game-exit" {
		t.Errorf("EndReason = %q", sum.EndReason)
	}
	if len(sum.Segments) != 1 {
		t.Fatalf("segments = %d, want 1", len(sum.Segments))
	}
	if sum.Segments[0].Stats.Samples != 2 {
		t.Errorf("segment stats not taken from segment_end record: %+v", sum.Segments[0].Stats)
	}
	if sum.TotalSamples != 2 {
		t.Errorf("TotalSamples = %d", sum.TotalSamples)
	}
	approx(t, "OverallP50Ms", sum.OverallP50Ms, 10)
}

func TestSummarizeTruncatedSessionRecomputes(t *testing.T) {
	s1 := sample(10, 3, 3)
	s2 := sample(30, 3, 3)
	// Crash: no segment_end, no session_end.
	recs := []Record{
		{V: 1, T: RecSessionStart, Time: mkTime(0), GameID: "rl", DisplayName: "Rocket League"},
		{V: 1, T: RecSegmentStart, Time: mkTime(5), Seq: 1, Proto: "udp", Endpoint: "1.2.3.4:7000"},
		{V: 1, T: RecSample, Time: mkTime(10), Seq: 1, Sample: &s1},
		{V: 1, T: RecSample, Time: mkTime(20), Seq: 1, Sample: &s2},
	}
	sum := Summarize(recs)
	if !sum.Truncated {
		t.Error("expected Truncated")
	}
	if len(sum.Segments) != 1 {
		t.Fatalf("segments = %d, want 1", len(sum.Segments))
	}
	st := sum.Segments[0].Stats
	if st.Samples != 2 {
		t.Errorf("recomputed samples = %d, want 2", st.Samples)
	}
	approx(t, "recomputed P50", st.P50Ms, 10)
	// End falls back to the last record's time; segment duration follows.
	if !sum.End.Equal(mkTime(20)) {
		t.Errorf("End = %v, want %v", sum.End, mkTime(20))
	}
	approx(t, "recomputed DurationSec", st.DurationSec, 15)
}

func TestSummarizeMultiSegment(t *testing.T) {
	s1 := sample(10, 3, 3)
	recs := []Record{
		{V: 1, T: RecSessionStart, Time: mkTime(0), GameID: "rl"},
		{V: 1, T: RecSegmentStart, Time: mkTime(1), Seq: 1, Endpoint: "1.1.1.1:7000"},
		{V: 1, T: RecSample, Time: mkTime(2), Seq: 1, Sample: &s1},
		// Rotation without an explicit segment_end (defensive: Summarize
		// must close the open segment on the next segment_start).
		{V: 1, T: RecSegmentStart, Time: mkTime(10), Seq: 2, Endpoint: "2.2.2.2:7000"},
		{V: 1, T: RecSample, Time: mkTime(12), Seq: 2, Sample: &s1},
		{V: 1, T: RecSessionEnd, Time: mkTime(20), Reason: "interrupt"},
	}
	sum := Summarize(recs)
	if len(sum.Segments) != 2 {
		t.Fatalf("segments = %d, want 2", len(sum.Segments))
	}
	if sum.Segments[0].Endpoint != "1.1.1.1:7000" || sum.Segments[1].Endpoint != "2.2.2.2:7000" {
		t.Errorf("segment endpoints wrong: %+v", sum.Segments)
	}
}
