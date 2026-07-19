package agent

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"pingrank.gg/internal/accesspath"
	"pingrank.gg/internal/cgnat"
	"pingrank.gg/internal/detect"
	"pingrank.gg/internal/etw"
	"pingrank.gg/internal/gamelog"
	"pingrank.gg/internal/identity"
	"pingrank.gg/internal/probe"
	"pingrank.gg/internal/session"
	"pingrank.gg/internal/sockets"
	"pingrank.gg/internal/store"
	"pingrank.gg/internal/submit"
)

// Config controls a background recorder.
type Config struct {
	DataDir       string
	ClientVersion string
	Interval      time.Duration
	Status        func(Status)
	ServerURL     string
}

// Runner continuously records sessions, returning to the waiting state after
// each game exits.
type Runner struct {
	cfg Config
}

func NewRunner(cfg Config) *Runner {
	if cfg.Interval == 0 {
		cfg.Interval = session.DefaultInterval
	}
	if cfg.Status == nil {
		cfg.Status = func(Status) {}
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = submit.DefaultServerURL
	}
	return &Runner{cfg: cfg}
}

type etwController interface {
	Enable([]uint32) error
	Disable() error
	SetTargetPIDs([]uint32)
	TakeFlows() []etw.Flow
	Health() (etw.Health, error)
	Close() error
}

var startPersistentETW = func() (etwController, error) {
	return etw.StartPersistentSession()
}

type etwSource struct{ session etwController }

func (s etwSource) TakeFlows() []session.Flow {
	flows := s.session.TakeFlows()
	out := make([]session.Flow, 0, len(flows))
	for _, flow := range flows {
		out = append(out, session.Flow{
			PID: flow.PID, Remote: flow.Remote, Bidirectional: flow.Bidirectional(),
			Packets: flow.SentPkts + flow.RecvPkts, SentPackets: flow.SentPkts,
			RecvPackets: flow.RecvPkts, SentBytes: flow.SentBytes, RecvBytes: flow.RecvBytes,
		})
	}
	return out
}

func (s etwSource) SetTargetPIDs(pids []uint32) { s.session.SetTargetPIDs(pids) }

func (s etwSource) Health() (session.FlowHealth, error) {
	health, err := s.session.Health()
	return session.FlowHealth{
		EventsLost: health.EventsLost, BuffersLost: health.BuffersLost,
		SchemaErrors: health.SchemaErrors,
	}, err
}

func (s etwSource) Close() error { return s.session.Disable() }

func openETWSource(controller etwController, startErr error, targetPIDs []uint32) (session.FlowSource, error) {
	if controller == nil {
		return nil, startErr
	}
	if err := controller.Enable(targetPIDs); err != nil {
		return nil, err
	}
	return etwSource{session: controller}, nil
}

func (r *Runner) Run(ctx context.Context) error {
	if r.cfg.DataDir == "" {
		return fmt.Errorf("agent: data directory is required")
	}
	// Create the ETW trace before waiting for a game. EA AntiCheat can deny
	// StartTraceW after it starts, while still allowing providers to be enabled
	// on an existing session. Keep this empty session for the service lifetime
	// and enable its provider only while a recording is active.
	flowSession, flowErr := startPersistentETW()
	if flowSession != nil {
		defer flowSession.Close()
	}
	signatures, err := detect.LoadSignatures()
	if err != nil {
		return err
	}
	creds, err := identity.LoadOrCreateCredentials(filepath.Join(r.cfg.DataDir, "install.json"))
	if err != nil {
		return err
	}

	for ctx.Err() == nil {
		if err := r.runSession(ctx, signatures, creds, flowSession, flowErr); err != nil {
			r.publish(Status{State: StateError, Message: err.Error()})
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(5 * time.Second):
			}
		}
	}
	return nil
}

func (r *Runner) runSession(ctx context.Context, signatures []detect.Signature, creds identity.Credentials, flowSession etwController, flowErr error) error {
	var mu sync.Mutex
	status := Status{State: StateWaiting, Message: "Waiting for a supported game", Version: r.cfg.ClientVersion}
	r.publish(status)
	update := func(fn func(*Status)) {
		mu.Lock()
		fn(&status)
		status.Version = r.cfg.ClientVersion
		r.publish(status)
		mu.Unlock()
	}

	var writer *store.Writer
	live := submit.NewLiveRecording(r.cfg.ServerURL, r.cfg.ClientVersion, creds)
	emit := func(record session.Record) {
		live.Push(record)
		switch record.T {
		case session.RecSessionStart:
			var err error
			writer, err = store.NewWriter(filepath.Join(r.cfg.DataDir, "sessions"), record.Time, record.GameID, store.DefaultRetain)
			if err != nil {
				update(func(s *Status) { s.State, s.Message = StateError, "Session storage unavailable: "+err.Error() })
			}
			update(func(s *Status) {
				s.State, s.Message = StateRecording, record.DisplayName+" detected"
				s.GameID, s.Game, s.Endpoint = record.GameID, record.DisplayName, ""
			})
		case session.RecSegmentStart:
			update(func(s *Status) {
				s.State, s.Message, s.Endpoint = StateRecording, "Measuring "+record.Endpoint, record.Endpoint
			})
		case session.RecSessionEnd:
			update(func(s *Status) {
				s.State, s.Message = StateWaiting, "Waiting for a supported game"
				s.GameID, s.Game, s.Endpoint = "", "", ""
			})
		}
		if writer != nil {
			_ = writer.Append(record)
		}
		if record.T == session.RecSessionEnd && writer != nil {
			_ = writer.Close()
			writer = nil
		}
	}
	defer func() {
		if writer != nil {
			_ = writer.Close()
		}
	}()

	recorder := session.NewRecorder(session.Config{
		Signatures: signatures, Interval: r.cfg.Interval, ClientVersion: r.cfg.ClientVersion,
		Emit: emit,
		Status: func(message string) {
			update(func(s *Status) { s.Message = message })
		},
	}, session.Deps{
		Lister: detect.ToolhelpLister{}, Querier: sockets.SystemQuerier{}, Prober: probe.IcmpProber{},
		OpenFlows: func(targetPIDs []uint32) (session.FlowSource, error) {
			return openETWSource(flowSession, flowErr, targetPIDs)
		},
		OpenGameLog: func(gameID string) (session.GameLogSource, error) { return gamelog.OpenLive(gameID) },
		CGNAT:       cgnat.SystemDetector{Tracer: probe.IcmpProber{}},
		AccessPath: accesspath.CachedDetector{
			Reflectors: accesspath.ReflectorsFromEnv(), Path: filepath.Join(r.cfg.DataDir, "access-path.json"),
		},
		AgentID: creds.AgentID,
	})
	err := recorder.Run(ctx)
	_, liveErr := live.Close()
	if liveErr != nil && ctx.Err() == nil {
		update(func(s *Status) { s.Message = "Recorded locally; verification unavailable: " + liveErr.Error() })
	}
	return err
}

func (r *Runner) publish(status Status) {
	status.Version = r.cfg.ClientVersion
	r.cfg.Status(status)
}
