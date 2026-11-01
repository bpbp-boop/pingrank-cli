// Command pingrank-service hosts the recorder under the Windows Service
// Control Manager. When launched interactively it runs in console mode for
// diagnostics and development.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"

	"pingrank.gg/internal/agent"
	"pingrank.gg/internal/detect"
	"pingrank.gg/internal/submit"
	"pingrank.gg/internal/update"
)

const serviceName = "PingRank"

var clientVersion = "0.7.12-dev"

func main() {
	dataDir, err := agent.DefaultDataDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank-service:", err)
		os.Exit(1)
	}
	isService, err := svc.IsWindowsService()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank-service:", err)
		os.Exit(1)
	}
	if !isService {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if err := newService(dataDir).runAgent(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "pingrank-service:", err)
			os.Exit(1)
		}
		return
	}
	if err := svc.Run(serviceName, serviceHandler{s: newService(dataDir)}); err != nil {
		os.Exit(1)
	}
}

// service tracks the recorder's state so the updater installs only
// between games, and holds the tray's status while an update runs.
type service struct {
	dataDir string

	mu       sync.Mutex
	state    string
	last     agent.Status
	updating bool
}

func newService(dataDir string) *service { return &service{dataDir: dataDir} }

func (s *service) runAgent(ctx context.Context) error {
	runner := agent.NewRunner(agent.Config{
		DataDir: s.dataDir, ClientVersion: clientVersion,
		Status: s.publish,
	})
	return runner.Run(ctx)
}

func (s *service) publish(status agent.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.last = status.State, status
	if !s.updating {
		_ = agent.WriteStatus(agent.StatusPath(s.dataDir), status)
	}
}

// idle reports whether an update may stop the recorder now. The recorder
// still reports "waiting" while it sets up a session for a game it just
// found, so idle also looks for supported games in the process list.
func (s *service) idle() bool {
	s.mu.Lock()
	state := s.state
	s.mu.Unlock()
	if state != agent.StateWaiting && state != agent.StateError {
		return false
	}
	return !gameRunning()
}

// gameRunning reports whether any supported game is running. When it
// cannot tell, it says yes, so the update waits.
func gameRunning() bool {
	signatures, err := detect.LoadSignatures()
	if err != nil {
		return true
	}
	procs, err := detect.ToolhelpLister{}.Processes()
	if err != nil {
		return true
	}
	return len(detect.MatchProcesses(procs, signatures)) > 0
}

// setUpdating shows the updating state to the tray, or restores the
// recorder's latest status.
func (s *service) setUpdating(on bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updating = on
	status := s.last
	if on {
		status = agent.Status{State: agent.StateUpdating, Message: "Installing an update", Version: clientVersion}
	}
	_ = agent.WriteStatus(agent.StatusPath(s.dataDir), status)
}

func (s *service) log(message string) {
	path := filepath.Join(s.dataDir, "update.log")
	if info, err := os.Stat(path); err == nil && info.Size() > 256<<10 {
		_ = os.Remove(path)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s %s\n", time.Now().UTC().Format(time.RFC3339), clientVersion, message)
}

func trayExe() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Join(filepath.Dir(exe), "pingrank-tray.exe")
}

// relaunchTray starts the tray again if it closed for an update.
func (s *service) relaunchTray() {
	if !update.TakeTrayRelaunch() {
		return
	}
	if err := update.LaunchTray(trayExe()); err != nil {
		s.log("tray relaunch: " + err.Error())
	}
}

// runUpdates checks for new releases until ctx ends. Windows Installer
// stops this service during an upgrade; if that has not happened after
// installTimeout, the install failed and the service carries on.
func (s *service) runUpdates(ctx context.Context) {
	const installTimeout = 30 * time.Minute
	update.CleanStaged()
	// After an upgrade, start the tray again for players who are signed in.
	time.AfterFunc(5*time.Second, s.relaunchTray)

	u := update.New(update.Config{
		ServerURL: submit.DefaultServerURL, CurrentVersion: clientVersion,
		Enabled: update.Enabled, Idle: s.idle,
		Stage: update.Stage, Verify: update.Verify,
		Install: func(msi, dir string) error {
			s.setUpdating(true)
			_ = update.MarkTrayRelaunch()
			time.Sleep(5 * time.Second) // the tray polls every 2 s
			if !s.idle() {
				s.setUpdating(false)
				s.relaunchTray()
				return errors.New("a game started")
			}
			if err := update.Install(msi, dir); err != nil {
				s.setUpdating(false)
				s.relaunchTray()
				return err
			}
			return nil
		},
		Log: s.log,
	})
	for {
		if !u.Run(ctx) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(installTimeout):
		}
		s.log("update did not complete; see install.log in the staging folder")
		s.setUpdating(false)
		s.relaunchTray()
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

type serviceHandler struct{ s *service }

func (h serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.s.runAgent(ctx) }()
	go h.s.runUpdates(ctx)

	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- current
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Interrogate:
				changes <- current
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(20 * time.Second):
				}
				h.s.writeFinal(agent.Status{
					State: agent.StateStopped, Message: "PingRank.gg service is stopped", Version: clientVersion,
				})
				return false, 0
			}
		case err := <-done:
			cancel()
			if err != nil {
				h.s.writeFinal(agent.Status{
					State: agent.StateError, Message: err.Error(), Version: clientVersion,
				})
				return true, 1
			}
			return false, 0
		}
	}
}

// writeFinal records the stopped or failed state, unless an update is
// running: then the tray must keep seeing "updating" and stay closed.
func (s *service) writeFinal(status agent.Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.updating {
		_ = agent.WriteStatus(agent.StatusPath(s.dataDir), status)
	}
}
