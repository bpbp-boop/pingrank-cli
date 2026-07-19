// Command pingrank-service hosts the recorder under the Windows Service
// Control Manager. When launched interactively it runs in console mode for
// diagnostics and development.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows/svc"

	"pingrank.gg/internal/agent"
)

const serviceName = "PingRank"

var clientVersion = "0.7.5-dev"

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
		if err := runAgent(ctx, dataDir); err != nil {
			fmt.Fprintln(os.Stderr, "pingrank-service:", err)
			os.Exit(1)
		}
		return
	}
	if err := svc.Run(serviceName, serviceHandler{dataDir: dataDir}); err != nil {
		os.Exit(1)
	}
}

func runAgent(ctx context.Context, dataDir string) error {
	runner := agent.NewRunner(agent.Config{
		DataDir: dataDir, ClientVersion: clientVersion,
		Status: func(status agent.Status) {
			_ = agent.WriteStatus(agent.StatusPath(dataDir), status)
		},
	})
	return runner.Run(ctx)
}

type serviceHandler struct{ dataDir string }

func (h serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runAgent(ctx, h.dataDir) }()

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
				_ = agent.WriteStatus(agent.StatusPath(h.dataDir), agent.Status{
					State: agent.StateStopped, Message: "PingRank.gg service is stopped", Version: clientVersion,
				})
				return false, 0
			}
		case err := <-done:
			cancel()
			if err != nil {
				_ = agent.WriteStatus(agent.StatusPath(h.dataDir), agent.Status{
					State: agent.StateError, Message: err.Error(), Version: clientVersion,
				})
				return true, 1
			}
			return false, 0
		}
	}
}
