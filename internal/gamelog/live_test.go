package gamelog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLiveSourceSkipsHistoryAndParsesAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Launch.log")
	old := `Party: GameURL="1.2.3.4:7001"` + "\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	l := &LiveSource{path: path, parser: RocketLeagueParser{}, offset: st.Size()}
	if got := l.TakeCandidates(); len(got) != 0 {
		t.Fatalf("historical endpoint leaked: %+v", got)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`Party: PingURL="3.25.156.96:8173",GameURL="3.25.156.96:8172"` + "\n")
	_ = f.Close()
	got := l.TakeCandidates()
	if len(got) != 2 || got[0].Role != "game" || got[1].Role != "ping" {
		t.Fatalf("appended reservation not parsed: %+v", got)
	}
}
