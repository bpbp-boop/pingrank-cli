package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"pingrank.gg/internal/accesspath"
	"pingrank.gg/internal/cgnat"
	"pingrank.gg/internal/detect"
	"pingrank.gg/internal/etw"
	"pingrank.gg/internal/identity"
	"pingrank.gg/internal/probe"
	"pingrank.gg/internal/session"
	"pingrank.gg/internal/sockets"
	"pingrank.gg/internal/store"
	"pingrank.gg/internal/submit"
)

// clientVersion is stamped by the release workflow via
// -ldflags "-X main.clientVersion=<tag>"; dev builds keep this default.
var clientVersion = "0.7.5-dev"

// etwAdapter bridges *etw.Session to session.FlowSource.
type etwAdapter struct{ s *etw.Session }

func (a etwAdapter) TakeFlows() []session.Flow {
	fl := a.s.TakeFlows()
	out := make([]session.Flow, 0, len(fl))
	for _, f := range fl {
		out = append(out, session.Flow{
			PID:           f.PID,
			Remote:        f.Remote,
			Bidirectional: f.Bidirectional(),
			Packets:       f.SentPkts + f.RecvPkts,
		})
	}
	return out
}

func (a etwAdapter) SetTargetPIDs(pids []uint32) { a.s.SetTargetPIDs(pids) }

func (a etwAdapter) Health() (session.FlowHealth, error) {
	health, err := a.s.Health()
	return session.FlowHealth{
		EventsLost: health.EventsLost, BuffersLost: health.BuffersLost,
		SchemaErrors: health.SchemaErrors,
	}, err
}

func (a etwAdapter) Close() error { return a.s.Disable() }

func storeDirFlag(fs *flag.FlagSet) *string {
	return fs.String("dir", "", `session store directory (default %LOCALAPPDATA%\PingRank\sessions)`)
}

func resolveStoreDir(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	return store.DefaultDir()
}

// cmdRecord implements `pingrank record`: run until Ctrl+C, game exit, or
// -for elapses; live status line; stores the session; summary on exit.
func cmdRecord(args []string) int {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "stream session records as JSONL to stdout")
	gameExe := fs.String("game", "", "skip signature matching and target this exe name")
	interval := fs.Duration("interval", session.DefaultInterval,
		fmt.Sprintf("sampling cadence (floor %s)", session.MinInterval))
	forDur := fs.Duration("for", 0, "stop after this duration (0 = until game exit or ctrl+c)")
	noEtw := fs.Bool("no-etw", false, "skip the ETW observer: socket-table-only discovery (degraded)")
	share := fs.Bool("share", true, "share a verified live recording (default; retained for compatibility)")
	noShare := fs.Bool("no-share", false, "record locally without sending measurements")
	server := fs.String("server", "", "ingest server URL (default $PINGRANK_SERVER or "+submit.DefaultServerURL+")")
	dir := storeDirFlag(fs)
	fs.Parse(args)

	// Create the trace before waiting for the game. Some anti-cheat software
	// denies StartTraceW after a protected game starts, but still permits
	// enabling a provider on a session that already exists.
	var flowSession *etw.Session
	var flowErr error
	if !*noEtw {
		flowSession, flowErr = etw.StartDormantSession()
		if flowSession != nil {
			defer flowSession.Close()
		}
	}

	sigs, err := detect.LoadSignatures()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	storeDir, err := resolveStoreDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	identityPath, err := identity.DefaultPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	creds, err := identity.LoadOrCreateCredentials(identityPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	var records []session.Record
	var live *submit.LiveRecording
	sharing := *share && !*noShare
	if sharing {
		live = submit.NewLiveRecording(resolveServer(*server), clientVersion, creds)
	}
	var w *store.Writer
	var enc *json.Encoder
	if *jsonOut {
		enc = json.NewEncoder(os.Stdout)
	}
	emit := func(rec session.Record) {
		records = append(records, rec)
		if live != nil {
			live.Push(rec)
		}
		if rec.T == session.RecSessionStart && w == nil {
			var werr error
			w, werr = store.NewWriter(storeDir, rec.Time, rec.GameID, store.DefaultRetain)
			if werr != nil {
				fmt.Fprintln(os.Stderr, "pingrank: session storage disabled:", werr)
			}
		}
		if w != nil {
			if werr := w.Append(rec); werr != nil {
				fmt.Fprintln(os.Stderr, "pingrank: writing session log:", werr)
			}
		}
		if enc != nil {
			enc.Encode(rec)
		}
	}

	// Human status goes to stdout normally, stderr when stdout carries
	// JSONL. One rewritten line, so recording doesn't scroll the console.
	statusOut := io.Writer(os.Stdout)
	if *jsonOut {
		statusOut = os.Stderr
	}
	status := func(line string) {
		if len(line) > 78 {
			line = line[:78]
		}
		fmt.Fprintf(statusOut, "\r%-78s", line)
	}

	rec := session.NewRecorder(session.Config{
		Signatures:    sigs,
		GameExe:       *gameExe,
		Interval:      *interval,
		MaxDuration:   *forDur,
		ClientVersion: clientVersion,
		Emit:          emit,
		Status:        status,
	}, session.Deps{
		Lister:  detect.ToolhelpLister{},
		Querier: sockets.SystemQuerier{},
		Prober:  probe.IcmpProber{},
		OpenFlows: func(targetPIDs []uint32) (session.FlowSource, error) {
			if *noEtw {
				return nil, nil
			}
			if flowSession == nil {
				return nil, flowErr
			}
			if err := flowSession.Enable(targetPIDs); err != nil {
				return nil, err
			}
			return etwAdapter{s: flowSession}, nil
		},
		CGNAT:      cgnat.SystemDetector{Tracer: probe.IcmpProber{}},
		AccessPath: accesspath.CachedDetector{Reflectors: accesspath.ReflectorsFromEnv()},
		AgentID:    creds.AgentID,
	})

	runErr := rec.Run(ctx)
	if w != nil {
		w.Close()
	}
	fmt.Fprintln(statusOut) // terminate the status line
	if runErr != nil {
		if live != nil {
			_, _ = live.Close()
		}
		fmt.Fprintln(os.Stderr, "pingrank:", runErr)
		return 1
	}
	if len(records) == 0 {
		fmt.Fprintln(statusOut, "no session recorded")
		return 0
	}
	sum := session.Summarize(records)
	printSummary(statusOut, sum)
	if w != nil {
		fmt.Fprintf(statusOut, "stored: %s\n", w.Path())
	}
	if sharing {
		res, liveErr := live.Close()
		if liveErr == nil {
			where := ""
			if res.Region != "" {
				where = " · region " + res.Region
				if res.City != "" {
					where += " (" + res.City + ")"
				}
			}
			fmt.Fprintf(statusOut, "submitted verified: %s%s\n", sum.GameID, where)
		} else {
			fmt.Fprintf(statusOut, "live verification unavailable (%v); submitting as unverified\n", liveErr)
			shareSession(sum, resolveServer(*server), statusOut)
		}
	}
	return 0
}

// shareSession implements `record -share`: flush earlier queued payloads,
// then submit this session, queueing it if the backend is unreachable.
// Never fails the record command — the session is already stored locally.
func shareSession(sum session.Summary, url string, out io.Writer) {
	payload := submit.Build(sum, clientVersion)
	if len(payload.Session.Segments) == 0 {
		fmt.Fprintln(out, "share: session has no segments; nothing to submit")
		return
	}
	flushOutbox(url, out)
	deliver(url, payload, payload.Session.GameID, out)
}

// cmdSessions implements `pingrank sessions`: list stored sessions.
func cmdSessions(args []string) int {
	fs := flag.NewFlagSet("sessions", flag.ExitOnError)
	dir := storeDirFlag(fs)
	fs.Parse(args)

	storeDir, err := resolveStoreDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	entries, err := store.List(storeDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	if len(entries) == 0 {
		fmt.Printf("no stored sessions in %s\n", storeDir)
		return 0
	}
	fmt.Printf("%-34s %-18s %-16s %-8s %4s %8s %9s %6s\n",
		"SESSION", "GAME", "START", "DURATION", "SEG", "SAMPLES", "P50", "LOSS")
	for _, e := range entries {
		s := e.Summary
		name := e.Name
		if len(name) > 34 {
			name = name[:34]
		}
		fmt.Printf("%-34s %-18s %-16s %-8s %4d %8d %8.1fms %5.1f%%\n",
			name, s.DisplayName, s.Start.Format("2006-01-02 15:04"),
			fmtDuration(s.End.Sub(s.Start)), len(s.Segments), s.TotalSamples,
			s.OverallP50Ms, s.OverallLoss)
	}
	return 0
}

// cmdShow implements `pingrank show <session>`: re-render a stored session.
func cmdShow(args []string) int {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "dump the raw records as JSONL")
	dir := storeDirFlag(fs)
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pingrank show [-json] [-dir <dir>] <session-name-or-prefix>")
		return 2
	}

	storeDir, err := resolveStoreDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	recs, name, err := store.Load(storeDir, fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		for _, r := range recs {
			enc.Encode(r)
		}
		return 0
	}
	fmt.Printf("session file: %s\n", name)
	printSummary(os.Stdout, session.Summarize(recs))
	return 0
}

func printSummary(out io.Writer, s session.Summary) {
	fmt.Fprintf(out, "\nsession: %s (%s)  %s → %s (%s)",
		s.DisplayName, s.GameID,
		s.Start.Format("2006-01-02 15:04:05"), s.End.Format("15:04:05"),
		fmtDuration(s.End.Sub(s.Start)))
	switch {
	case s.Truncated:
		fmt.Fprintf(out, "  [truncated log]\n")
	case s.EndReason != "":
		fmt.Fprintf(out, "  [%s]\n", s.EndReason)
	default:
		fmt.Fprintln(out)
	}
	fmt.Fprintf(out, "udp discovery: %s\n", s.UDPDiscovery)
	cgnatStatus, localClass := s.CGNAT, s.LocalAddressClass
	if cgnatStatus == "" {
		cgnatStatus = "unknown"
	}
	if localClass == "" {
		localClass = "unknown"
	}
	fmt.Fprintf(out, "cgnat: %s (local address: %s)", cgnatStatus, localClass)
	if s.CGNATEvidence != nil {
		fmt.Fprintf(out, " - hop %d in %s", s.CGNATEvidence.Hop, s.CGNATEvidence.Range)
	}
	fmt.Fprintln(out)
	if s.AccessPath != nil {
		fmt.Fprintf(out, "internet access: %s (%s confidence)\n", s.AccessPath.Classification, s.AccessPath.Confidence)
		fmt.Fprintln(out, accesspath.Explanation(*s.AccessPath))
	}
	fmt.Fprintf(out, "segments: %d, samples: %d, overall p50 %.1fms, loss %.1f%%\n",
		len(s.Segments), s.TotalSamples, s.OverallP50Ms, s.OverallLoss)
	for _, seg := range s.Segments {
		tags := fmt.Sprintf("%s confidence, %s", seg.Confidence, seg.Source)
		if seg.Relay {
			tags += ", RELAY " + seg.RelayLabel + " — latency is to the relay"
		}
		fmt.Fprintf(out, " %d. %s %s  from %s (%s)  %d samples  [%s]\n",
			seg.Seq, seg.Proto, seg.Endpoint,
			seg.Start.Format("15:04:05"), fmtDuration(time.Duration(seg.Stats.DurationSec*float64(time.Second))),
			seg.Stats.Samples, tags)
		if seg.Stats.Samples > 0 {
			method := seg.Stats.Method
			if method == "" {
				method = "unknown"
			}
			fmt.Fprintf(out, "      p50 %.1fms  p95 %.1fms  min %.1f  max %.1f  jitter %.1fms  loss %.1f%%  (method: %s)\n",
				seg.Stats.P50Ms, seg.Stats.P95Ms, seg.Stats.MinMs, seg.Stats.MaxMs,
				seg.Stats.JitterMs, seg.Stats.LossPct, method)
		}
	}
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	if d < time.Minute {
		return d.String()
	}
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	s := (d % time.Minute) / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%02dm", h, m)
	}
	return fmt.Sprintf("%dm%02ds", m, s)
}
