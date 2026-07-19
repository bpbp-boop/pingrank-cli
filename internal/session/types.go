// Package session implements continuous session measurement (milestone 2):
// a session spans one game process's lifetime and is an ordered list of
// segments, each bound to one server endpoint. Records are the schema that
// milestone 3 persists and a future backend ingests, so they carry a schema
// version on every line.
package session

import (
	"math"
	"sort"
	"time"

	"pingrank.gg/internal/accesspath"
	"pingrank.gg/internal/cgnat"
)

// SchemaVersion is stamped on every record ("v"). Bump on breaking changes.
const SchemaVersion = 1

// Record types ("t" field).
const (
	RecSessionStart          = "session_start"
	RecSegmentStart          = "segment_start"
	RecSample                = "sample"
	RecSegmentEnd            = "segment_end"
	RecSegmentClassification = "segment_classification"
	RecSessionEnd            = "session_end"
)

// Record is one line of a session log. A single struct with omitempty
// fields rather than per-type structs so JSONL lines stay self-describing
// and the reader needs no type registry.
type Record struct {
	V    int       `json:"v"`
	T    string    `json:"t"`
	Time time.Time `json:"time"`

	// session_start
	GameID        string `json:"gameId,omitempty"`
	DisplayName   string `json:"displayName,omitempty"`
	ClientVersion string `json:"clientVersion,omitempty"`
	// UDPDiscovery is "etw" or "unavailable" (degraded, socket-table only).
	UDPDiscovery      string             `json:"udpDiscovery,omitempty"`
	CGNAT             string             `json:"cgnat,omitempty"`
	CGNATEvidence     *cgnat.Evidence    `json:"cgnatEvidence,omitempty"`
	LocalAddressClass string             `json:"localAddressClass,omitempty"`
	AgentID           string             `json:"agentId,omitempty"`
	AccessPath        *accesspath.Result `json:"accessPath,omitempty"`

	// segment_start / segment_end / sample: 1-based segment sequence
	Seq int `json:"seq,omitempty"`

	// segment_start (discovery metadata)
	Proto             string           `json:"proto,omitempty"`
	Endpoint          string           `json:"endpoint,omitempty"`
	Confidence        string           `json:"confidence,omitempty"`
	Source            string           `json:"source,omitempty"`
	Relay             bool             `json:"relay,omitempty"`
	RelayLabel        string           `json:"relayLabel,omitempty"`
	Reasons           []string         `json:"reasons,omitempty"`
	Role              string           `json:"role,omitempty"`
	Eligibility       string           `json:"eligibility,omitempty"`
	EligibilityReason string           `json:"eligibilityReason,omitempty"`
	CorroboratedBy    string           `json:"corroboratedBy,omitempty"`
	Traffic           *TrafficEvidence `json:"traffic,omitempty"`

	// sample
	Sample *Sample `json:"sample,omitempty"`

	// segment_end
	Stats *SegmentStats `json:"stats,omitempty"`

	// session_end: "game-exit", "interrupt", "duration-limit"
	Reason string `json:"reason,omitempty"`
}

const (
	EligibilityConfirmed    = "confirmed"
	EligibilityProbable     = "probable"
	EligibilityDiagnostic   = "diagnostic-only"
	pubgMinPacketsPerSecond = 5
)

type TrafficEvidence struct {
	ObservedPolls    int     `json:"observedPolls,omitempty"`
	WindowSeconds    float64 `json:"windowSeconds,omitempty"`
	PacketsPerSecond float64 `json:"packetsPerSecond,omitempty"`
	BytesPerSecond   float64 `json:"bytesPerSecond,omitempty"`
	ReceivePacketPct float64 `json:"receivePacketPct,omitempty"`
	SentPackets      uint64  `json:"sentPackets,omitempty"`
	RecvPackets      uint64  `json:"recvPackets,omitempty"`
	SentBytes        uint64  `json:"sentBytes,omitempty"`
	RecvBytes        uint64  `json:"recvBytes,omitempty"`
	Bidirectional    bool    `json:"bidirectional,omitempty"`
}

// Sample is one probe burst against the active segment's endpoint.
type Sample struct {
	RTTMinMs uint32  `json:"rttMinMs"`
	RTTAvgMs float64 `json:"rttAvgMs"`
	RTTMaxMs uint32  `json:"rttMaxMs"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"lossPct"`
	// Method is "direct" or "last-hop"; Probed differs from the segment
	// endpoint for last-hop samples.
	Method string `json:"method"`
	Probed string `json:"probed"`
}

// SegmentStats are derived at segment close from that segment's samples.
type SegmentStats struct {
	Samples     int     `json:"samples"`
	DurationSec float64 `json:"durationSec"`
	// Latency percentiles over per-sample averages (received samples only).
	MinMs float64 `json:"minMs"`
	P50Ms float64 `json:"p50Ms"`
	P95Ms float64 `json:"p95Ms"`
	MaxMs float64 `json:"maxMs"`
	// JitterMs is the mean absolute difference between consecutive
	// per-sample averages.
	JitterMs float64 `json:"jitterMs"`
	// LossPct aggregates lost/sent over all samples in the segment.
	LossPct float64 `json:"lossPct"`
	// Method is the uniform sample method ("protocol", "direct",
	// "last-hop"), or "mixed" if the method changed mid-segment — mixed
	// stats must never be averaged with clean ones downstream.
	Method string `json:"method,omitempty"`
}

// ComputeStats derives segment statistics from its samples. Samples with
// zero received pings contribute to loss but not to latency/jitter.
func ComputeStats(samples []Sample, duration time.Duration) SegmentStats {
	s := SegmentStats{
		Samples:     len(samples),
		DurationSec: duration.Seconds(),
		Method:      methodOf(samples),
	}

	var avgs []float64
	var sent, received int
	for _, sm := range samples {
		sent += sm.Sent
		received += sm.Received
		if sm.Received > 0 {
			avgs = append(avgs, sm.RTTAvgMs)
		}
	}
	if sent > 0 {
		s.LossPct = float64(sent-received) / float64(sent) * 100
	}
	if len(avgs) == 0 {
		return s
	}

	// Jitter over consecutive received samples, in original order.
	if len(avgs) >= 2 {
		var sum float64
		for i := 1; i < len(avgs); i++ {
			sum += math.Abs(avgs[i] - avgs[i-1])
		}
		s.JitterMs = sum / float64(len(avgs)-1)
	}

	sorted := append([]float64(nil), avgs...)
	sort.Float64s(sorted)
	s.MinMs = sorted[0]
	s.MaxMs = sorted[len(sorted)-1]
	s.P50Ms = percentile(sorted, 50)
	s.P95Ms = percentile(sorted, 95)
	return s
}

// methodOf reduces samples to their uniform method, "mixed" on change,
// mirroring ComputeStats.
func methodOf(samples []Sample) string {
	method := ""
	for _, sm := range samples {
		switch {
		case sm.Method == "":
		case method == "":
			method = sm.Method
		case method != sm.Method:
			return "mixed"
		}
	}
	return method
}

// percentile is nearest-rank over an ascending-sorted slice.
func percentile(sorted []float64, p int) float64 {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(float64(p) / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	return sorted[rank-1]
}

// Summary is a whole session, reconstructed from its records. Used both by
// `record` for its exit report and by `show`/`sessions` when replaying
// stored logs.
type Summary struct {
	GameID            string
	DisplayName       string
	UDPDiscovery      string
	CGNAT             string
	CGNATEvidence     *cgnat.Evidence
	LocalAddressClass string
	AgentID           string
	AccessPath        *accesspath.Result
	Start, End        time.Time
	EndReason         string
	Segments          []SegmentSummary
	TotalSamples      int
	OverallP50Ms      float64
	OverallLoss       float64
	Truncated         bool // no session_end record (crash / power loss)
}

// SegmentSummary is one segment's identity plus its derived stats.
type SegmentSummary struct {
	Seq               int
	Proto             string
	Endpoint          string
	Confidence        string
	Source            string
	Relay             bool
	RelayLabel        string
	Role              string
	Eligibility       string
	EligibilityReason string
	CorroboratedBy    string
	Traffic           *TrafficEvidence
	Start             time.Time
	Stats             SegmentStats
}

// Summarize reconstructs a Summary from an ordered record stream. Segments
// missing their segment_end (truncated log) get stats recomputed from their
// samples so a crashed session is still reportable.
func Summarize(recs []Record) Summary {
	var sum Summary
	var open *SegmentSummary
	var openSamples []Sample
	var allAvgs []float64
	var sentTotal, recvTotal int
	var lastTime time.Time

	closeOpen := func(end time.Time, stats *SegmentStats) {
		if open == nil {
			return
		}
		if stats != nil {
			open.Stats = *stats
			// Logs written before method tagging existed have samples
			// with methods but stats without one; backfill so replay and
			// submission see the same discipline as fresh recordings.
			if open.Stats.Method == "" {
				open.Stats.Method = methodOf(openSamples)
			}
		} else {
			open.Stats = ComputeStats(openSamples, end.Sub(open.Start))
		}
		sum.Segments = append(sum.Segments, *open)
		open = nil
		openSamples = nil
	}

	for _, r := range recs {
		if r.Time.After(lastTime) {
			lastTime = r.Time
		}
		switch r.T {
		case RecSessionStart:
			sum.GameID = r.GameID
			sum.DisplayName = r.DisplayName
			sum.UDPDiscovery = r.UDPDiscovery
			sum.CGNAT = r.CGNAT
			sum.CGNATEvidence = r.CGNATEvidence
			sum.LocalAddressClass = r.LocalAddressClass
			sum.AgentID = r.AgentID
			sum.AccessPath = r.AccessPath
			sum.Start = r.Time
		case RecSegmentStart:
			closeOpen(r.Time, nil)
			open = &SegmentSummary{
				Seq:        r.Seq,
				Proto:      r.Proto,
				Endpoint:   r.Endpoint,
				Confidence: r.Confidence,
				Source:     r.Source,
				Relay:      r.Relay,
				RelayLabel: r.RelayLabel,
				Role:       r.Role, Eligibility: r.Eligibility,
				EligibilityReason: r.EligibilityReason, CorroboratedBy: r.CorroboratedBy,
				Traffic: r.Traffic,
				Start:   r.Time,
			}
		case RecSegmentClassification:
			if open != nil && open.Seq == r.Seq {
				open.Role, open.Eligibility = r.Role, r.Eligibility
				open.EligibilityReason, open.CorroboratedBy = r.EligibilityReason, r.CorroboratedBy
			}
		case RecSample:
			if r.Sample == nil {
				continue
			}
			sum.TotalSamples++
			sentTotal += r.Sample.Sent
			recvTotal += r.Sample.Received
			if r.Sample.Received > 0 {
				allAvgs = append(allAvgs, r.Sample.RTTAvgMs)
			}
			if open != nil {
				openSamples = append(openSamples, *r.Sample)
			}
		case RecSegmentEnd:
			closeOpen(r.Time, r.Stats)
		case RecSessionEnd:
			sum.End = r.Time
			sum.EndReason = r.Reason
		}
	}

	if sum.End.IsZero() {
		sum.Truncated = true
		sum.End = lastTime
	}
	closeOpen(sum.End, nil)

	if sentTotal > 0 {
		sum.OverallLoss = float64(sentTotal-recvTotal) / float64(sentTotal) * 100
	}
	if len(allAvgs) > 0 {
		sorted := append([]float64(nil), allAvgs...)
		sort.Float64s(sorted)
		sum.OverallP50Ms = percentile(sorted, 50)
	}
	return sum
}
