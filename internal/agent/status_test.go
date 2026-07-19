package agent

import (
	"path/filepath"
	"testing"
)

func TestStatusRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "status.json")
	want := Status{State: StateRecording, Message: "Measuring", Game: "Rocket League", Endpoint: "1.2.3.4:7716", Version: "test"}
	if err := WriteStatus(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := ReadStatus(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != want.State || got.Game != want.Game || got.Endpoint != want.Endpoint || got.UpdatedAt.IsZero() {
		t.Fatalf("status = %+v", got)
	}
}
