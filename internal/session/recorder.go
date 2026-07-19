package session

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"pingrank.gg/internal/accesspath"
	"pingrank.gg/internal/cgnat"
	"pingrank.gg/internal/detect"
	"pingrank.gg/internal/flows"
	"pingrank.gg/internal/gamelog"
	"pingrank.gg/internal/probe"
	"pingrank.gg/internal/sockets"
)

const (
	detectInterval = 3 * time.Second
	alivePoll      = 3 * time.Second

	// Discovery polls run fast until the first endpoint locks, then drop
	// to a slow passive cadence to catch server changes.
	fastDiscovery = 3 * time.Second
	slowDiscovery = 30 * time.Second

	// windowPolls is the sliding window of discovery polls the ranking
	// sees. Old endpoints age out of the window, so a finished match's
	// server stops outranking the new one.
	windowPolls = 6

	// Lock-on relaxation: if nothing meets the current confidence floor
	// this long after session start, lower the floor one step so the
	// session measures *something*, labelled with its real confidence.
	// Degraded (no-ETW) mode relaxes faster since high is unreachable and
	// a game's only visible flows may all be TCP/443 (ranked low).
	mediumLockAfter      = 45 * time.Second
	lowLockAfter         = 2 * mediumLockAfter
	lowLockAfterDegraded = 30 * time.Second

	// DefaultGrace keeps a session open across a brief game crash or
	// relaunch (plan: default 30 s).
	DefaultGrace = 30 * time.Second

	// DefaultInterval / MinInterval bound the sampling cadence.
	DefaultInterval = 10 * time.Second
	MinInterval     = 5 * time.Second

	// sampleBurst pings per sample; a fresh endpoint resolve uses the
	// same burst. Budget discipline: 3 small ICMP echoes per interval.
	sampleBurst = 3

	// After this many consecutive all-loss samples, re-resolve the probe
	// method (path change, ICMP newly blocked, last-hop router changed).
	reResolveAfterLoss = 3
)

// Prober is what sampling needs; satisfied by probe.IcmpProber.
type Prober interface {
	Resolve(target netip.Addr, count int) (probe.Result, error)
	Ping(addr netip.Addr, count int) (probe.Stats, error)
	Protocol(method string, ep netip.AddrPort, count int) (probe.Stats, error)
}

// FlowSource is the adapter-neutral UDP flow observer.
type FlowSource interface {
	TakeFlows() []Flow
	SetTargetPIDs([]uint32)
	Health() (FlowHealth, error)
	Close() error
}

// FlowHealth is a cumulative snapshot of the underlying ETW session. A
// positive delta means the current discovery window may be incomplete.
type FlowHealth struct {
	EventsLost   uint64
	BuffersLost  uint64
	SchemaErrors uint64
}

type CGNATDetector interface {
	Detect() cgnat.Result
}

type AccessPathDetector interface {
	Detect(context.Context) (accesspath.Result, error)
}

type GameLogSource interface {
	TakeCandidates() []gamelog.Candidate
	Close() error
}

// Flow mirrors etw.Flow's shape so this package doesn't import etw
// directly (keeps the recorder testable without a live trace session).
type Flow struct {
	PID           uint32
	Remote        netip.AddrPort
	Bidirectional bool
	Packets       uint64
	SentPackets   uint64
	RecvPackets   uint64
	SentBytes     uint64
	RecvBytes     uint64
}

// Config parameterizes a recording run.
type Config struct {
	Signatures []detect.Signature
	GameExe    string // non-empty: bypass signatures, match this exe
	Interval   time.Duration
	Grace      time.Duration
	// MaxDuration ends the session after a fixed time (0 = until game
	// exit or ctx cancellation).
	MaxDuration   time.Duration
	ClientVersion string

	// Emit receives every record in order (JSONL sinks, storage, the
	// summary). Called from the recorder goroutine only.
	Emit func(Record)
	// Status receives one-line live progress strings; may be nil.
	Status func(string)
}

// Deps are the OS-facing dependencies, injectable for tests.
type Deps struct {
	Lister  detect.Lister
	Querier sockets.Querier
	Prober  Prober
	// OpenFlows starts the UDP flow observer; return etw.ErrAccessDenied
	// (or any error) to record in degraded mode.
	OpenFlows   func(targetPIDs []uint32) (FlowSource, error)
	OpenGameLog func(gameID string) (GameLogSource, error)
	CGNAT       CGNATDetector
	AccessPath  AccessPathDetector
	AgentID     string
}

// Recorder runs one session: wait for game → measure until it exits (or
// ctx cancels / MaxDuration elapses) → emit session_end.
type Recorder struct {
	cfg  Config
	deps Deps
}

func NewRecorder(cfg Config, deps Deps) *Recorder {
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Interval < MinInterval {
		cfg.Interval = MinInterval
	}
	if cfg.Grace <= 0 {
		cfg.Grace = DefaultGrace
	}
	if cfg.Emit == nil {
		cfg.Emit = func(Record) {}
	}
	if cfg.Status == nil {
		cfg.Status = func(string) {}
	}
	return &Recorder{cfg: cfg, deps: deps}
}

// game is the detected target: identity, current PIDs, and per-game hints
// from its signature.
type game struct {
	id          string
	display     string
	pids        map[uint32]bool
	hints       *flows.GameHints
	probeMethod string
}

// segment is the currently active endpoint binding.
type segment struct {
	seq                                                  int
	cand                                                 flows.Candidate
	traffic                                              *TrafficEvidence
	start                                                time.Time
	samples                                              []Sample
	probed                                               netip.Addr // resolved probe address (zero until first sample)
	method                                               string
	useProtocol                                          bool // sampling via game-protocol probe, not ICMP
	lossRun                                              int  // consecutive all-loss samples
	role, eligibility, eligibilityReason, corroboratedBy string
}

// Run blocks until the session ends. Returns an error only for
// environmental failures; "no game appeared before ctx cancelled" is nil.
func (r *Recorder) Run(ctx context.Context) error {
	g, err := r.waitForGame(ctx)
	if err != nil || g == nil {
		return err
	}

	start := time.Now()
	var src FlowSource
	udpDiscovery := "unavailable"
	if s, err := r.deps.OpenFlows(pidSlice(g.pids)); err == nil && s != nil {
		src = s
		udpDiscovery = "etw"
		defer src.Close()
	}
	var gameLog GameLogSource
	if r.deps.OpenGameLog != nil {
		if source, err := r.deps.OpenGameLog(g.id); err == nil && source != nil {
			gameLog = source
			defer gameLog.Close()
		}
	}
	nat := cgnat.Result{Status: cgnat.StatusNone, LocalAddressClass: cgnat.LocalUnknown}
	if r.deps.CGNAT != nil {
		r.status("classifying CGNAT path...")
		nat = r.deps.CGNAT.Detect()
	}
	var access *accesspath.Result
	if r.deps.AccessPath != nil {
		r.status("classifying Internet access path...")
		if measured, err := r.deps.AccessPath.Detect(ctx); err == nil {
			access = &measured
		} else {
			r.status("Internet access classification unavailable: " + err.Error())
		}
	}

	r.cfg.Emit(Record{
		V: SchemaVersion, T: RecSessionStart, Time: start,
		GameID: g.id, DisplayName: g.display,
		ClientVersion:     r.cfg.ClientVersion,
		UDPDiscovery:      udpDiscovery,
		CGNAT:             nat.Status,
		CGNATEvidence:     nat.Evidence,
		LocalAddressClass: nat.LocalAddressClass,
		AgentID:           r.deps.AgentID,
		AccessPath:        access,
	})
	r.status(fmt.Sprintf("%s detected — discovering server (udp discovery: %s)", g.display, udpDiscovery))

	var (
		tracker      Tracker
		window       [][]flows.Observation
		seg          *segment
		nextSeq      = 1
		graceEnds    time.Time // zero while the game is alive
		endReason    string
		logEndpoints = map[netip.AddrPort]gamelog.Candidate{}
		flowHealth   FlowHealth
	)
	if src != nil {
		if health, err := src.Health(); err == nil {
			flowHealth = health
		} else {
			r.status("UDP discovery degraded: ETW health unavailable: " + err.Error())
		}
	}

	discovery := time.NewTimer(fastDiscovery)
	defer discovery.Stop()
	sampler := time.NewTicker(r.cfg.Interval)
	defer sampler.Stop()
	alive := time.NewTicker(alivePoll)
	defer alive.Stop()
	var deadline <-chan time.Time
	if r.cfg.MaxDuration > 0 {
		deadline = time.After(r.cfg.MaxDuration)
	}

loop:
	for {
		select {
		case <-ctx.Done():
			endReason = "interrupt"
			break loop

		case <-deadline:
			endReason = "duration-limit"
			break loop

		case <-alive.C:
			pids := r.currentPIDs(g)
			switch {
			case len(pids) > 0:
				g.pids = pids
				if src != nil {
					src.SetTargetPIDs(pidSlice(pids))
				}
				if !graceEnds.IsZero() {
					graceEnds = time.Time{}
					r.status(g.display + " is back — session continues")
				}
			case graceEnds.IsZero():
				if src != nil {
					src.SetTargetPIDs(nil)
				}
				g.pids = nil
				graceEnds = time.Now().Add(r.cfg.Grace)
				r.status(fmt.Sprintf("%s exited — waiting %s before closing the session",
					g.display, r.cfg.Grace))
			case time.Now().After(graceEnds):
				endReason = "game-exit"
				break loop
			}

		case <-discovery.C:
			if gameLog != nil {
				for _, candidate := range gameLog.TakeCandidates() {
					logEndpoints[candidate.Endpoint] = candidate
				}
			}
			obs := r.discoveryPoll(g, src, &flowHealth)
			window = append(window, obs)
			if len(window) > windowPolls {
				window = window[1:]
			}
			col := flows.NewCollector(g.hints)
			for _, p := range window {
				col.AddPoll(p)
			}
			var top *flows.Candidate
			if cands := col.Candidates(); len(cands) > 0 {
				top = &cands[0]
			}
			if tracker.Observe(top, minConfidence(src == nil, time.Since(start))) {
				pollInterval := slowDiscovery
				if seg == nil {
					pollInterval = fastDiscovery
				}
				observedFor := time.Duration(tracker.Active().ObservedPolls) * pollInterval
				seg = r.rotateSegment(seg, *tracker.Active(), &nextSeq, g, logEndpoints, observedFor)
			}
			r.refreshClassification(seg, g, logEndpoints)
			if tracker.Active() == nil {
				discovery.Reset(fastDiscovery)
			} else {
				discovery.Reset(slowDiscovery)
			}

		case <-sampler.C:
			if seg == nil {
				continue
			}
			r.sample(seg, g)
		}
	}

	now := time.Now()
	if seg != nil {
		r.closeSegment(seg, now)
	}
	r.cfg.Emit(Record{V: SchemaVersion, T: RecSessionEnd, Time: now, Reason: endReason})
	return nil
}

// waitForGame polls the process list until the target appears or ctx ends.
func (r *Recorder) waitForGame(ctx context.Context) (*game, error) {
	r.status("waiting for a game to start...")
	for {
		procs, err := r.deps.Lister.Processes()
		if err != nil {
			return nil, err
		}
		if g := r.matchGame(procs); g != nil {
			return g, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-time.After(detectInterval):
		}
	}
}

func (r *Recorder) matchGame(procs []detect.Process) *game {
	if r.cfg.GameExe != "" {
		pids := detect.MatchExe(procs, r.cfg.GameExe)
		if len(pids) == 0 {
			return nil
		}
		return &game{id: "custom", display: r.cfg.GameExe, pids: pidSet(pids)}
	}
	matches := detect.MatchProcesses(procs, r.cfg.Signatures)
	if len(matches) == 0 {
		return nil
	}
	m := matches[0]
	g := &game{id: m.Signature.GameID, display: m.Signature.DisplayName, pids: pidSet(m.PIDs)}
	h := m.Signature.Hints
	if parsed, err := flows.ParseHints(h.ExpectedPorts, h.RelayCIDRs, h.RelayLabel); err == nil {
		g.hints = &parsed
		if probe.GameProtocolAllowed(g.id, h.ProbeMethod) {
			g.probeMethod = h.ProbeMethod
		}
	}
	return g
}

// currentPIDs re-resolves the game's PIDs (they change across relaunches).
func (r *Recorder) currentPIDs(g *game) map[uint32]bool {
	procs, err := r.deps.Lister.Processes()
	if err != nil {
		return g.pids // transient failure: assume unchanged
	}
	if r.cfg.GameExe != "" {
		return pidSet(detect.MatchExe(procs, r.cfg.GameExe))
	}
	// MatchProcesses preserves signature order, which is useful for the
	// initial selection but must not affect an already-recording game. Find
	// that game's match explicitly when multiple known games are running.
	for _, match := range detect.MatchProcesses(procs, r.cfg.Signatures) {
		if match.Signature.GameID == g.id {
			return pidSet(match.PIDs)
		}
	}
	return nil
}

// discoveryPoll gathers one poll of observations for the ranking window.
func (r *Recorder) discoveryPoll(g *game, src FlowSource, previousHealth *FlowHealth) []flows.Observation {
	var obs []flows.Observation
	if entries, err := r.deps.Querier.Snapshot(); err == nil {
		for _, e := range entries {
			if !g.pids[e.PID] || e.Proto != sockets.ProtoTCP ||
				e.TCPState != sockets.TCPStateEstablished {
				continue
			}
			obs = append(obs, flows.Observation{
				Proto:         flows.ProtoTCP,
				Remote:        e.Remote,
				Source:        flows.SourceTCPTable,
				Bidirectional: true,
			})
		}
	}
	if src != nil {
		batch := src.TakeFlows()
		health, err := src.Health()
		if err != nil {
			r.status("UDP discovery degraded: ETW health unavailable: " + err.Error())
			return obs // keep TCP observations; do not rank an unverified UDP batch
		}
		if healthDegraded(*previousHealth, health) {
			r.status(fmt.Sprintf("UDP discovery degraded: ETW lost events/buffers or rejected an unknown schema (events=%d buffers=%d schema=%d)",
				health.EventsLost, health.BuffersLost, health.SchemaErrors))
			*previousHealth = health
			return obs // keep TCP observations; do not rank an incomplete UDP batch
		}
		*previousHealth = health
		for _, f := range batch {
			if !g.pids[f.PID] {
				continue
			}
			obs = append(obs, flows.Observation{
				Proto:         flows.ProtoUDP,
				Remote:        f.Remote,
				Source:        flows.SourceETW,
				Bidirectional: f.Bidirectional,
				Packets:       f.Packets,
				SentPackets:   f.SentPackets,
				RecvPackets:   f.RecvPackets,
				SentBytes:     f.SentBytes,
				RecvBytes:     f.RecvBytes,
			})
		}
	}
	return obs
}

func healthDegraded(previous, current FlowHealth) bool {
	return current.EventsLost > previous.EventsLost ||
		current.BuffersLost > previous.BuffersLost ||
		current.SchemaErrors > previous.SchemaErrors
}

func pidSlice(pids map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(pids))
	for pid := range pids {
		out = append(out, pid)
	}
	return out
}

func (r *Recorder) rotateSegment(old *segment, cand flows.Candidate, nextSeq *int, g *game, logs map[netip.AddrPort]gamelog.Candidate, observedFor time.Duration) *segment {
	now := time.Now()
	if old != nil {
		r.closeSegment(old, now)
	}
	seg := &segment{seq: *nextSeq, cand: cand, traffic: trafficEvidence(cand, observedFor), start: now}
	classifySegment(seg, g, logs)
	*nextSeq++
	r.cfg.Emit(Record{
		V: SchemaVersion, T: RecSegmentStart, Time: now, Seq: seg.seq,
		Proto:      string(cand.Proto),
		Endpoint:   cand.Remote.String(),
		Confidence: string(cand.Confidence),
		Source:     string(cand.Source),
		Relay:      cand.Relay,
		RelayLabel: cand.RelayLabel,
		Role:       seg.role, Eligibility: seg.eligibility,
		EligibilityReason: seg.eligibilityReason, CorroboratedBy: seg.corroboratedBy,
		Traffic: seg.traffic,
		Reasons: cand.Reasons,
	})
	r.status(fmt.Sprintf("segment %d: %s %s (%s confidence)",
		seg.seq, cand.Proto, cand.Remote, cand.Confidence))
	return seg
}

func trafficEvidence(c flows.Candidate, observedFor time.Duration) *TrafficEvidence {
	t := &TrafficEvidence{ObservedPolls: c.ObservedPolls, WindowSeconds: observedFor.Seconds(), SentPackets: c.SentPackets,
		RecvPackets: c.RecvPackets, SentBytes: c.SentBytes, RecvBytes: c.RecvBytes,
		Bidirectional: c.Bidirectional}
	if t.WindowSeconds > 0 {
		t.PacketsPerSecond = float64(t.SentPackets+t.RecvPackets) / t.WindowSeconds
		t.BytesPerSecond = float64(t.SentBytes+t.RecvBytes) / t.WindowSeconds
	}
	if total := t.SentPackets + t.RecvPackets; total > 0 {
		t.ReceivePacketPct = 100 * float64(t.RecvPackets) / float64(total)
	}
	return t
}

func classifySegment(seg *segment, g *game, logs map[netip.AddrPort]gamelog.Candidate) {
	seg.role, seg.corroboratedBy = "unknown", ""
	if found, ok := logs[seg.cand.Remote]; ok {
		seg.role, seg.corroboratedBy = found.Role, found.Source
		seg.eligibility, seg.eligibilityReason = EligibilityConfirmed, "game_log_"+found.Role
		return
	}
	if g.id == "pubg" {
		traffic := seg.traffic
		if seg.cand.Proto == flows.ProtoUDP && seg.cand.Source == flows.SourceETW && traffic != nil &&
			traffic.Bidirectional && traffic.SentPackets > 0 && traffic.RecvPackets > 0 &&
			traffic.PacketsPerSecond >= pubgMinPacketsPerSecond {
			seg.eligibility, seg.eligibilityReason = EligibilityProbable, "pubg_sustained_udp_traffic"
		} else if seg.cand.Proto == flows.ProtoTCP {
			seg.eligibility, seg.eligibilityReason = EligibilityDiagnostic, "pubg_unconfirmed_tcp_flow"
		} else {
			seg.eligibility, seg.eligibilityReason = EligibilityDiagnostic, "pubg_insufficient_udp_traffic"
		}
		return
	}
	if g.id == "rocketleague" {
		if seg.cand.Proto == flows.ProtoUDP && g.hints != nil && g.hints.PortExpected(seg.cand.Remote.Port()) {
			seg.eligibility, seg.eligibilityReason = EligibilityProbable, "rocketleague_expected_udp_port"
		} else {
			seg.eligibility, seg.eligibilityReason = EligibilityDiagnostic, "rocketleague_unconfirmed_outside_expected_udp_ports"
		}
		return
	}
	if seg.cand.Proto == flows.ProtoTCP && seg.cand.Remote.Port() == 443 && seg.cand.Confidence == flows.ConfidenceLow {
		seg.eligibility, seg.eligibilityReason = EligibilityDiagnostic, "low_confidence_tls_fallback"
		return
	}
	seg.eligibility, seg.eligibilityReason = EligibilityProbable, "flow_heuristic"
}

func (r *Recorder) refreshClassification(seg *segment, g *game, logs map[netip.AddrPort]gamelog.Candidate) {
	if seg == nil {
		return
	}
	role, eligibility, reason, corroborated := seg.role, seg.eligibility, seg.eligibilityReason, seg.corroboratedBy
	classifySegment(seg, g, logs)
	if role == seg.role && eligibility == seg.eligibility && reason == seg.eligibilityReason && corroborated == seg.corroboratedBy {
		return
	}
	r.cfg.Emit(Record{V: SchemaVersion, T: RecSegmentClassification, Time: time.Now(), Seq: seg.seq,
		Role: seg.role, Eligibility: seg.eligibility, EligibilityReason: seg.eligibilityReason,
		CorroboratedBy: seg.corroboratedBy})
}

func (r *Recorder) closeSegment(seg *segment, now time.Time) {
	stats := ComputeStats(seg.samples, now.Sub(seg.start))
	r.cfg.Emit(Record{
		V: SchemaVersion, T: RecSegmentEnd, Time: now, Seq: seg.seq,
		Endpoint: seg.cand.Remote.String(),
		Stats:    &stats,
	})
}

// sample measures the active segment once. The first sample (and any
// re-resolve after sustained loss) establishes the method: a game-protocol
// probe when the signature declares one (measures the real UDP path and
// port — preferred over ICMP even when ICMP works), else ICMP with
// last-hop fallback. Steady-state samples reuse the established method.
func (r *Recorder) sample(seg *segment, g *game) {
	var s Sample
	switch {
	case !seg.probed.IsValid():
		if g.probeMethod != "" && seg.cand.Proto == flows.ProtoUDP {
			if stats, err := r.deps.Prober.Protocol(g.probeMethod, seg.cand.Remote, sampleBurst); err == nil && stats.Received > 0 {
				seg.method = "protocol"
				seg.probed = seg.cand.Remote.Addr()
				seg.useProtocol = true
				s = statsToSample(stats, seg.method, seg.probed)
				break
			}
			// Server doesn't answer the game protocol (relay, or a
			// non-Source-lineage host) — fall through to ICMP.
		}
		res, err := r.deps.Prober.Resolve(seg.cand.Remote.Addr(), sampleBurst)
		if err != nil {
			return
		}
		seg.method = res.Method
		seg.useProtocol = false
		if res.Stats.Received > 0 {
			seg.probed = res.Probed
		}
		s = statsToSample(res.Stats, res.Method, res.Probed)
	case seg.useProtocol:
		stats, err := r.deps.Prober.Protocol(g.probeMethod, seg.cand.Remote, sampleBurst)
		if err != nil {
			return
		}
		s = statsToSample(stats, seg.method, seg.probed)
	default:
		stats, err := r.deps.Prober.Ping(seg.probed, sampleBurst)
		if err != nil {
			return
		}
		s = statsToSample(stats, seg.method, seg.probed)
	}

	if s.Received == 0 {
		seg.lossRun++
		if seg.lossRun >= reResolveAfterLoss {
			seg.probed = netip.Addr{} // force re-resolve next sample
			seg.lossRun = 0
		}
	} else {
		seg.lossRun = 0
	}

	seg.samples = append(seg.samples, s)
	r.cfg.Emit(Record{
		V: SchemaVersion, T: RecSample, Time: time.Now(), Seq: seg.seq, Sample: &s,
	})
	last := "lost"
	if s.Received > 0 {
		last = fmt.Sprintf("%.1fms", s.RTTAvgMs)
	}
	r.status(fmt.Sprintf("%s | %s %s | last %s | %d samples",
		g.display, seg.cand.Proto, seg.cand.Remote, last, len(seg.samples)))
}

func statsToSample(st probe.Stats, method string, probed netip.Addr) Sample {
	s := Sample{
		RTTMinMs: st.MinMs,
		RTTAvgMs: st.AvgMs,
		RTTMaxMs: st.MaxMs,
		Sent:     st.Sent,
		Received: st.Received,
		LossPct:  st.LossPct,
		Method:   method,
	}
	if probed.IsValid() {
		s.Probed = probed.String()
	}
	return s
}

// minConfidence is the lock-on floor for the endpoint tracker at a given
// point in the session. Pure, table-testable.
func minConfidence(degraded bool, elapsed time.Duration) flows.Confidence {
	switch {
	case degraded && elapsed > lowLockAfterDegraded,
		!degraded && elapsed > lowLockAfter:
		return flows.ConfidenceLow
	case degraded, elapsed > mediumLockAfter:
		return flows.ConfidenceMedium
	default:
		return flows.ConfidenceHigh
	}
}

func (r *Recorder) status(line string) { r.cfg.Status(line) }

func pidSet(pids []uint32) map[uint32]bool {
	m := make(map[uint32]bool, len(pids))
	for _, p := range pids {
		m[p] = true
	}
	return m
}
