// Command pingrank detects a running game, discovers the game server's
// IP endpoint, measures latency to it, and prints the results.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"pingrank.gg/internal/detect"
	"pingrank.gg/internal/etw"
	"pingrank.gg/internal/flows"
	"pingrank.gg/internal/probe"
	"pingrank.gg/internal/sockets"
)

const (
	pollInterval = 3 * time.Second
	pollsPerRun  = 4 // ~12s window; stability heuristic wants 3+ polls
	maxProbes    = 3
)

type options struct {
	jsonOut bool
	watch   bool
	gameExe string
	noEtw   bool
}

// report is the full output of one measurement cycle.
type report struct {
	Game         gameInfo          `json:"game"`
	Elevated     bool              `json:"elevated"`
	UDPDiscovery string            `json:"udpDiscovery"` // "etw", "etw-degraded", or "unavailable"
	Candidates   []candidateReport `json:"candidates"`
}

type gameInfo struct {
	GameID      string   `json:"gameId"`
	DisplayName string   `json:"displayName"`
	Exe         string   `json:"exe,omitempty"`
	PIDs        []uint32 `json:"pids"`
}

type candidateReport struct {
	flows.Candidate
	Probe *probe.Result `json:"probe,omitempty"`
}

type endpointProber interface {
	probe.Prober
	Protocol(method string, ep netip.AddrPort, count int) (probe.Stats, error)
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "record":
			os.Exit(cmdRecord(os.Args[2:]))
		case "sessions":
			os.Exit(cmdSessions(os.Args[2:]))
		case "show":
			os.Exit(cmdShow(os.Args[2:]))
		case "submit":
			os.Exit(cmdSubmit(os.Args[2:]))
		case "access":
			os.Exit(cmdAccess(os.Args[2:]))
		case "parse-log":
			os.Exit(cmdParseLog(os.Args[2:]))
		case "help", "-h", "--help":
			printUsage()
			os.Exit(0)
		}
	}

	var opts options
	flag.BoolVar(&opts.jsonOut, "json", false, "emit structured JSON instead of a human-readable report")
	flag.BoolVar(&opts.watch, "watch", false, "keep running; re-report when the endpoint set changes")
	flag.StringVar(&opts.gameExe, "game", "", "skip signature matching and target this exe name (e.g. cs2.exe)")
	flag.BoolVar(&opts.noEtw, "no-etw", false, "skip the ETW observer: socket-table-only discovery (degraded)")
	flag.Parse()

	if err := run(opts); err != nil {
		if err.Error() != "" {
			fmt.Fprintln(os.Stderr, "pingrank:", err)
		}
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  pingrank [flags]            single-shot: detect game, find server, measure once
  pingrank record [flags]     record a whole gaming session (M2); stores it locally
  pingrank sessions [flags]   list stored sessions
  pingrank show <session>     re-render a stored session
  pingrank submit <session>   share a stored session with the ingest backend (opt-in)
  pingrank access             test and explain the current Internet access path
  pingrank parse-log [file]   extract server endpoints from a game log

single-shot flags: -json -watch -game <exe> -no-etw
record flags:      -json -game <exe> -interval <dur> -for <dur> -dir <dir> -no-etw
                   -no-share (local only) -server <url>
sessions/show:     -dir <dir>; show also takes -json
submit flags:      -dry-run (print exact payload, send nothing) -flush -server <url> -dir <dir>
parse-log flags:   -game <id> (default rocketleague) -json

recordings are shared by default; use 'record -no-share' for local-only mode.`)
}

type exitCode1 struct{ msg string }

func (e exitCode1) Error() string { return e.msg }

func run(opts options) error {
	sigs, err := detect.LoadSignatures()
	if err != nil {
		return err
	}
	lister := detect.ToolhelpLister{}
	querier := sockets.SystemQuerier{}
	prober := probe.IcmpProber{}

	// Create one empty ETW session before a protected game can start. The
	// provider remains disabled while idle and is enabled with a target-PID
	// allowlist only for each measurement cycle.
	elevated := etw.IsElevated()
	var sess *etw.Session
	if !opts.noEtw {
		if sess, err = etw.StartDormantSession(); err != nil {
			if err != etw.ErrAccessDenied {
				return fmt.Errorf("starting ETW session: %w", err)
			}
			sess = nil
		}
	}
	if sess != nil {
		// The session name is system-global and outlives a killed
		// process, so stop it on Ctrl+C too.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt)
		go func() {
			<-sigCh
			sess.Close()
			os.Exit(130)
		}()
		defer sess.Close()
	}

	if !opts.watch {
		return runOnce(opts, sigs, lister, querier, prober, sess, elevated, nil)
	}

	// Watch mode: run measurement cycles forever, printing a report only
	// when the candidate endpoint set changes (or a game appears/goes away).
	var lastKey string
	sawGame := false
	fmt.Println("watching for a known game (ctrl+c to stop)...")
	for {
		key, err := runOnceKeyed(opts, sigs, lister, querier, prober, sess, elevated, lastKey)
		switch {
		case err == nil:
			sawGame = true
			lastKey = key
		case errIsNoGame(err):
			if sawGame {
				fmt.Println("game exited; waiting for a known game...")
			}
			sawGame = false
			lastKey = ""
			time.Sleep(pollInterval)
		default:
			return err
		}
	}
}

func errIsNoGame(err error) bool {
	_, ok := err.(exitCode1)
	return ok
}

// runOnceKeyed is runOnce for watch mode: it returns a key describing the
// candidate endpoint set and suppresses output when the key is unchanged.
func runOnceKeyed(opts options, sigs []detect.Signature, lister detect.Lister,
	querier sockets.Querier, prober endpointProber, sess *etw.Session,
	elevated bool, lastKey string) (string, error) {
	var key string
	err := runOnce(opts, sigs, lister, querier, prober, sess, elevated, func(r report) bool {
		remotes := make([]string, 0, len(r.Candidates))
		for _, c := range r.Candidates {
			remotes = append(remotes, string(c.Proto)+"/"+c.Remote.String())
		}
		sort.Strings(remotes)
		key = r.Game.GameID + "|" + strings.Join(remotes, ",")
		return key != lastKey
	})
	return key, err
}

// runOnce performs one detect→sample→rank→probe→report cycle.
// shouldReport, if non-nil, is consulted before probing/printing (watch
// mode uses it to skip unchanged endpoint sets); nil means always report.
func runOnce(opts options, sigs []detect.Signature, lister detect.Lister,
	querier sockets.Querier, prober endpointProber, sess *etw.Session,
	elevated bool, shouldReport func(report) bool) error {

	procs, err := lister.Processes()
	if err != nil {
		return err
	}

	var game gameInfo
	var hints *flows.GameHints
	var protocolMethod string
	if opts.gameExe != "" {
		pids := detect.MatchExe(procs, opts.gameExe)
		if len(pids) == 0 {
			return exitCode1{fmt.Sprintf("no running process named %q", opts.gameExe)}
		}
		game = gameInfo{GameID: "custom", DisplayName: opts.gameExe, Exe: opts.gameExe, PIDs: pids}
	} else {
		matches := detect.MatchProcesses(procs, sigs)
		if len(matches) == 0 {
			if !opts.watch {
				printNoGameHint(procs, querier)
				return exitCode1{""} // hint already printed the message
			}
			return exitCode1{"no known game is running"}
		}
		m := matches[0]
		if len(matches) > 1 && !opts.jsonOut {
			var others []string
			for _, o := range matches[1:] {
				others = append(others, o.Signature.DisplayName)
			}
			fmt.Fprintf(os.Stderr, "multiple games running; measuring %s (also saw: %s)\n",
				m.Signature.DisplayName, strings.Join(others, ", "))
		}
		game = gameInfo{
			GameID:      m.Signature.GameID,
			DisplayName: m.Signature.DisplayName,
			PIDs:        m.PIDs,
		}
		h := m.Signature.Hints
		if probe.GameProtocolAllowed(m.Signature.GameID, h.ProbeMethod) {
			protocolMethod = h.ProbeMethod
		}
		if parsed, err := flows.ParseHints(h.ExpectedPorts, h.RelayCIDRs, h.RelayLabel); err == nil {
			hints = &parsed
		}
	}

	pidSet := make(map[uint32]bool, len(game.PIDs))
	for _, pid := range game.PIDs {
		pidSet[pid] = true
	}

	etwActive := false
	if sess != nil {
		if err := sess.Enable(game.PIDs); err != nil {
			if !errors.Is(err, etw.ErrAccessDenied) {
				return fmt.Errorf("enabling ETW provider: %w", err)
			}
		} else {
			etwActive = true
			defer sess.Disable()
		}
	}

	if !opts.jsonOut && shouldReport == nil {
		fmt.Printf("detected: %s (pid %v) — sampling flows for ~%ds...\n",
			game.DisplayName, game.PIDs, int((pollsPerRun * pollInterval).Seconds()))
	}

	// Sample: poll the socket tables (TCP remotes) and drain the ETW
	// accumulator (UDP remotes) every interval.
	collector := flows.NewCollector(hints)
	var flowHealth etw.Health
	etwDegraded := false
	if etwActive {
		if health, err := sess.Health(); err == nil {
			flowHealth = health
		} else {
			etwDegraded = true
		}
	}
	for range pollsPerRun {
		time.Sleep(pollInterval)
		entries, err := querier.Snapshot()
		if err != nil {
			return err
		}
		var obs []flows.Observation
		for _, e := range entries {
			if !pidSet[e.PID] || e.Proto != sockets.ProtoTCP {
				continue
			}
			if e.TCPState != sockets.TCPStateEstablished {
				continue
			}
			obs = append(obs, flows.Observation{
				Proto:         flows.ProtoTCP,
				Remote:        e.Remote,
				Source:        flows.SourceTCPTable,
				Bidirectional: true, // established implies the handshake completed
			})
		}
		if etwActive {
			batch := sess.TakeFlows()
			health, healthErr := sess.Health()
			if healthErr != nil || etwHealthDegraded(flowHealth, health) {
				etwDegraded = true
				if healthErr == nil {
					flowHealth = health
				}
				collector.AddPoll(obs) // omit the potentially incomplete UDP batch
				continue
			}
			flowHealth = health
			for _, f := range batch {
				obs = append(obs, flows.Observation{
					Proto:         flows.ProtoUDP,
					Remote:        f.Remote,
					Source:        flows.SourceETW,
					Bidirectional: f.Bidirectional(),
					Packets:       f.SentPkts + f.RecvPkts,
				})
			}
		}
		collector.AddPoll(obs)
	}

	rep := report{Game: game, Elevated: elevated}
	if etwActive && etwDegraded {
		rep.UDPDiscovery = "etw-degraded"
	} else if etwActive {
		rep.UDPDiscovery = "etw"
	} else {
		rep.UDPDiscovery = "unavailable"
	}
	rep.Candidates = wrapCandidates(collector.Candidates())

	if shouldReport != nil && !shouldReport(rep) {
		return nil
	}

	// Probe the top candidates.
	for i := range rep.Candidates {
		if i >= maxProbes {
			break
		}
		res, err := measureCandidate(prober, rep.Candidates[i].Candidate, protocolMethod)
		if err != nil {
			note := err.Error()
			rep.Candidates[i].Probe = &probe.Result{Note: note}
			continue
		}
		rep.Candidates[i].Probe = &res
	}

	if opts.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	printHuman(rep, etwActive, elevated, opts.noEtw)
	return nil
}

func etwHealthDegraded(previous, current etw.Health) bool {
	return current.EventsLost > previous.EventsLost ||
		current.BuffersLost > previous.BuffersLost ||
		current.SchemaErrors > previous.SchemaErrors
}

const oneShotProbeCount = 5

// measureCandidate prefers a declared game-protocol probe for UDP endpoints,
// falling back to the established ICMP/last-hop path when it is unsupported
// or the endpoint does not answer it.
func measureCandidate(p endpointProber, cand flows.Candidate, protocolMethod string) (probe.Result, error) {
	if protocolMethod != "" && cand.Proto == flows.ProtoUDP {
		if stats, err := p.Protocol(protocolMethod, cand.Remote, oneShotProbeCount); err == nil && stats.Received > 0 {
			return probe.Result{
				Target: cand.Remote.Addr(), Method: "protocol", Probed: cand.Remote.Addr(), Stats: stats,
			}, nil
		}
	}
	return p.Probe(cand.Remote.Addr())
}

func wrapCandidates(cands []flows.Candidate) []candidateReport {
	out := make([]candidateReport, len(cands))
	for i, c := range cands {
		out[i] = candidateReport{Candidate: c}
	}
	return out
}

func printHuman(rep report, etwActive, elevated, disabled bool) {
	fmt.Println()
	fmt.Printf("game: %s (pid %v)\n", rep.Game.DisplayName, rep.Game.PIDs)
	switch {
	case rep.UDPDiscovery == "etw-degraded":
		fmt.Println("udp discovery: ETW observer degraded — incomplete UDP windows were discarded")
	case etwActive:
		fmt.Println("udp discovery: ETW kernel-network observer (elevated)")
	case disabled:
		fmt.Println("udp discovery: disabled (-no-etw) — socket-table only, degraded confidence")
	case elevated:
		fmt.Println("udp discovery: unavailable (ETW session failed)")
	default:
		fmt.Println("udp discovery: unavailable — not elevated. UDP remote endpoints cannot")
		fmt.Println("               be discovered; run as administrator for full results.")
	}

	if len(rep.Candidates) == 0 {
		fmt.Println("no candidate server endpoints found.")
		if !etwActive {
			fmt.Println("(the game likely uses UDP, which needs the elevated ETW path)")
		}
		return
	}

	fmt.Printf("candidate endpoints (%d):\n", len(rep.Candidates))
	for i, c := range rep.Candidates {
		fmt.Printf(" %d. %s %s  confidence: %-6s  source: %s\n",
			i+1, c.Proto, c.Remote, c.Confidence, c.Source)
		for _, r := range c.Reasons {
			fmt.Printf("      - %s\n", r)
		}
		if p := c.Probe; p != nil {
			if p.Stats.Received > 0 {
				fmt.Printf("      latency: %d/%.1f/%d ms min/avg/max, %.0f%% loss  (method: %s",
					p.Stats.MinMs, p.Stats.AvgMs, p.Stats.MaxMs, p.Stats.LossPct, p.Method)
				if p.Method == "last-hop" {
					fmt.Printf(", probed %s", p.Probed)
				}
				fmt.Println(")")
			} else {
				fmt.Printf("      latency: unmeasurable — %s\n", p.Note)
			}
		}
	}
}

// printNoGameHint lists running executables that have active sockets with
// public remote endpoints — the most likely candidates for a game we
// don't have a signature for.
func printNoGameHint(procs []detect.Process, querier sockets.Querier) {
	entries, err := querier.Snapshot()
	if err != nil {
		return
	}
	name := make(map[uint32]string, len(procs))
	for _, p := range procs {
		name[p.PID] = p.ExeName
	}
	seen := make(map[string]bool)
	var exes []string
	for _, e := range entries {
		if e.Proto != sockets.ProtoTCP || !flows.IsPublic(e.Remote.Addr()) {
			continue
		}
		exe := name[e.PID]
		if exe == "" || seen[exe] {
			continue
		}
		seen[exe] = true
		exes = append(exes, exe)
	}
	sort.Strings(exes)
	fmt.Fprintln(os.Stderr, "no known game is running.")
	if len(exes) > 0 {
		fmt.Fprintln(os.Stderr, "processes with active public-remote sockets (try --game <exe>):")
		for _, exe := range exes {
			fmt.Fprintf(os.Stderr, "  %s\n", exe)
		}
	}
}
