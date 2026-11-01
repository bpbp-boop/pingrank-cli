package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		latest, current string
		want            bool
	}{
		{"0.7.16", "0.7.15", true},
		{"0.8.0", "0.7.99", true},
		{"0.7.10", "0.7.9", true}, // numeric, not string, order
		{"0.7.15", "0.7.15", false},
		{"0.7.14", "0.7.15", false},
		{"0.8.0", "0.7.12-dev", false}, // dev builds never update
		{"v0.8.0", "0.7.12", false},
		{"", "0.7.12", false},
	} {
		if got := Newer(c.latest, c.current); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.latest, c.current, got)
		}
	}
}

type fakeRelease struct {
	srv       *httptest.Server
	msi       []byte
	answer    string
	downloads int
}

func newFakeRelease(t *testing.T, version string) *fakeRelease {
	f := &fakeRelease{msi: []byte("not really an msi " + version)}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/client/latest":
			if f.answer != "" {
				fmt.Fprint(w, f.answer)
				return
			}
			sum := sha256.Sum256(f.msi)
			fmt.Fprintf(w, `{"version":%q,"msiUrl":%q,"sha256":%q}`, version, f.srv.URL+"/a.msi", hex.EncodeToString(sum[:]))
		case "/a.msi":
			f.downloads++
			w.Write(f.msi)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

type recorder struct {
	verified, installed string
	idle                bool
	verifyErr           error
}

func (f *fakeRelease) updater(t *testing.T, current string, rec *recorder) *Updater {
	return New(Config{
		ServerURL: f.srv.URL, CurrentVersion: current, Client: f.srv.Client(),
		Idle:  func() bool { return rec.idle },
		Stage: func() (string, error) { return t.TempDir(), nil },
		Verify: func(path string) error {
			rec.verified = path
			return rec.verifyErr
		},
		Install: func(path, dir string) error {
			rec.installed = path
			return nil
		},
		IdlePoll: time.Millisecond,
	})
}

func TestCheckInstallsNewerRelease(t *testing.T) {
	f := newFakeRelease(t, "0.8.0")
	rec := &recorder{idle: true}
	installed, err := f.updater(t, "0.7.16", rec).Check(context.Background())
	if err != nil || !installed {
		t.Fatalf("installed=%v err=%v", installed, err)
	}
	if !strings.HasSuffix(rec.installed, "pingrank.gg-0.8.0-x64.msi") || rec.verified != rec.installed {
		t.Fatalf("verified %q, installed %q", rec.verified, rec.installed)
	}
	got, err := os.ReadFile(rec.installed)
	if err != nil || string(got) != string(f.msi) {
		t.Fatalf("staged file wrong: %q %v", got, err)
	}
}

func TestCheckSkipsSameVersion(t *testing.T) {
	f := newFakeRelease(t, "0.7.16")
	rec := &recorder{idle: true}
	installed, err := f.updater(t, "0.7.16", rec).Check(context.Background())
	if err != nil || installed || f.downloads != 0 {
		t.Fatalf("installed=%v err=%v downloads=%d", installed, err, f.downloads)
	}
}

func TestCheckRejectsBadChecksum(t *testing.T) {
	f := newFakeRelease(t, "0.8.0")
	f.answer = fmt.Sprintf(`{"version":"0.8.0","msiUrl":%q,"sha256":%q}`, f.srv.URL+"/a.msi", strings.Repeat("0", 64))
	rec := &recorder{idle: true}
	installed, err := f.updater(t, "0.7.16", rec).Check(context.Background())
	if installed || err == nil || !strings.Contains(err.Error(), "checksum") || rec.verified != "" {
		t.Fatalf("installed=%v err=%v verified=%q", installed, err, rec.verified)
	}
}

func TestCheckRejectsBadSignature(t *testing.T) {
	f := newFakeRelease(t, "0.8.0")
	rec := &recorder{idle: true, verifyErr: errors.New("signed by someone else")}
	installed, err := f.updater(t, "0.7.16", rec).Check(context.Background())
	if installed || err == nil || rec.installed != "" {
		t.Fatalf("installed=%v err=%v", installed, err)
	}
}

func TestCheckRejectsMalformedAnswers(t *testing.T) {
	sum := strings.Repeat("a", 64)
	for _, answer := range []string{
		`{"version":"0.8.0-beta","msiUrl":"https://x/a.msi","sha256":"` + sum + `"}`,
		`{"version":"0.8.0","msiUrl":"http://x/a.msi","sha256":"` + sum + `"}`,
		`{"version":"0.8.0","msiUrl":"https://x/a.msi","sha256":"abc"}`,
	} {
		f := newFakeRelease(t, "0.8.0")
		f.answer = answer
		rec := &recorder{idle: true}
		if installed, err := f.updater(t, "0.7.16", rec).Check(context.Background()); installed || err == nil {
			t.Errorf("%s: installed=%v err=%v", answer, installed, err)
		}
	}
}

func TestCheckWaitsForIdle(t *testing.T) {
	f := newFakeRelease(t, "0.8.0")
	rec := &recorder{}
	u := f.updater(t, "0.7.16", rec)
	polls := 0
	u.cfg.Idle = func() bool { polls++; return polls > 3 }
	installed, err := u.Check(context.Background())
	if err != nil || !installed || polls != 4 {
		t.Fatalf("installed=%v err=%v polls=%d", installed, err, polls)
	}
}

func TestCheckRespectsDisabled(t *testing.T) {
	f := newFakeRelease(t, "0.8.0")
	rec := &recorder{idle: true}
	u := f.updater(t, "0.7.16", rec)
	u.cfg.Enabled = func() bool { return false }
	if installed, err := u.Check(context.Background()); installed || err != nil || f.downloads != 0 {
		t.Fatalf("installed=%v err=%v downloads=%d", installed, err, f.downloads)
	}
}

func TestRunSkipsDevBuilds(t *testing.T) {
	f := newFakeRelease(t, "0.8.0")
	u := f.updater(t, "0.7.12-dev", &recorder{idle: true})
	u.cfg.FirstCheck = time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if u.Run(ctx) || f.downloads != 0 {
		t.Fatal("a dev build must not update")
	}
}
