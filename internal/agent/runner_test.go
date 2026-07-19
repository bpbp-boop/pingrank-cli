package agent

import (
	"context"
	"errors"
	"testing"

	"pingrank.gg/internal/etw"
)

type fakeETWController struct {
	enables  int
	disables int
	closes   int
	targets  []uint32
}

func (f *fakeETWController) Enable(pids []uint32) error {
	f.enables++
	f.targets = append([]uint32(nil), pids...)
	return nil
}

func (f *fakeETWController) Disable() error {
	f.disables++
	return nil
}

func (f *fakeETWController) TakeFlows() []etw.Flow { return nil }
func (f *fakeETWController) SetTargetPIDs(pids []uint32) {
	f.targets = append([]uint32(nil), pids...)
}
func (f *fakeETWController) Health() (etw.Health, error) { return etw.Health{}, nil }

func (f *fakeETWController) Close() error {
	f.closes++
	return nil
}

func TestOpenETWSourceEnablesAndDisablesPersistentSession(t *testing.T) {
	controller := &fakeETWController{}
	source, err := openETWSource(controller, nil, []uint32{42})
	if err != nil {
		t.Fatal(err)
	}
	if controller.enables != 1 {
		t.Fatalf("Enable calls = %d, want 1", controller.enables)
	}
	if len(controller.targets) != 1 || controller.targets[0] != 42 {
		t.Fatalf("target PIDs = %v, want [42]", controller.targets)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if controller.disables != 1 || controller.closes != 0 {
		t.Fatalf("after recording close: disables=%d closes=%d, want 1 and 0", controller.disables, controller.closes)
	}
}

func TestOpenETWSourcePreservesStartupFailure(t *testing.T) {
	want := errors.New("StartTraceW denied")
	source, err := openETWSource(nil, want, []uint32{42})
	if source != nil || !errors.Is(err, want) {
		t.Fatalf("openETWSource() = (%v, %v), want (nil, %v)", source, err, want)
	}
}

func TestRunnerStartsAndOwnsPersistentETWSession(t *testing.T) {
	controller := &fakeETWController{}
	original := startPersistentETW
	startPersistentETW = func() (etwController, error) { return controller, nil }
	t.Cleanup(func() { startPersistentETW = original })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := NewRunner(Config{DataDir: t.TempDir()})
	if err := runner.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if controller.enables != 0 {
		t.Fatalf("provider enabled while waiting: %d calls", controller.enables)
	}
	if controller.closes != 1 {
		t.Fatalf("service shutdown close calls = %d, want 1", controller.closes)
	}
}
