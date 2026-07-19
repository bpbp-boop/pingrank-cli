package submit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pingrank.gg/internal/accesspath"
	"pingrank.gg/internal/cgnat"
	"pingrank.gg/internal/session"
)

func testSummary() session.Summary {
	start := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	return session.Summary{
		GameID:            "rocketleague",
		DisplayName:       "Rocket League",
		UDPDiscovery:      "etw",
		CGNAT:             cgnat.StatusLikely,
		CGNATEvidence:     &cgnat.Evidence{Hop: 2, Range: "10.0.0.0/8"},
		LocalAddressClass: cgnat.LocalPrivate,
		AgentID:           "00112233445566778899aabbccddeeff",
		AccessPath: &accesspath.Result{
			Classification: accesspath.UpstreamNAT44, Confidence: accesspath.ConfidenceStrong,
			Evidence: []accesspath.EvidenceItem{{Type: accesspath.EvidenceRouterSharedUse}},
			TestedAt: start, ClassifierVersion: accesspath.ClassifierVersion,
		},
		Start:     start,
		End:       start.Add(45 * time.Minute),
		EndReason: "game-exit",
		Segments: []session.SegmentSummary{{
			Seq: 1, Proto: "udp", Endpoint: "3.25.100.7:7832",
			Confidence: "high", Source: "etw", Start: start,
			Stats: session.SegmentStats{
				Samples: 90, DurationSec: 900, MinMs: 20, P50Ms: 24,
				P95Ms: 31, MaxMs: 40, JitterMs: 2.1, LossPct: 0.4,
				Method: "direct",
			},
		}},
	}
}

func TestBuildPayloadShape(t *testing.T) {
	p := Build(testSummary(), "0.5.0-dev")
	if p.V != 1 || p.ClientVersion != "0.5.0-dev" {
		t.Fatalf("envelope wrong: %+v", p)
	}
	if p.Session.GameID != "rocketleague" || len(p.Session.Segments) != 1 {
		t.Fatalf("session wrong: %+v", p.Session)
	}
	if p.Session.Segments[0].Stats.P50Ms != 24 {
		t.Fatalf("stats not carried over: %+v", p.Session.Segments[0])
	}
	if p.Session.CGNAT != cgnat.StatusLikely || p.Session.CGNATEvidence == nil || p.Session.CGNATEvidence.Hop != 2 || p.Session.LocalAddressClass != cgnat.LocalPrivate {
		t.Fatalf("CGNAT metadata not carried over: %+v", p.Session)
	}
	if p.Session.AgentID == "" || p.Session.AccessPath == nil || p.Session.AccessPath.Classification != accesspath.UpstreamNAT44 {
		t.Fatalf("M8 access metadata not carried over: %+v", p.Session)
	}

	// Privacy: the serialized payload must not contain anything beyond
	// the documented fields — spot-check the display name stays out.
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "Rocket League") {
		t.Fatal("payload leaked display name")
	}
}

func TestBuildTruncated(t *testing.T) {
	sum := testSummary()
	sum.EndReason = ""
	sum.Truncated = true
	if got := Build(sum, "x").Session.EndReason; got != "truncated" {
		t.Fatalf("endReason = %q, want truncated", got)
	}
}

func TestSubmitClassification(t *testing.T) {
	cases := []struct {
		status    int
		body      string
		wantErr   bool
		retryable bool
		duplicate bool
	}{
		{200, `{"accepted":true}`, false, false, false},
		{200, `{"accepted":true,"duplicate":true}`, false, false, true},
		{200, `{"accepted":false}`, true, true, false},
		{200, `<html>proxy error</html>`, true, true, false},
		{400, `{"error":"bad payload"}`, true, false, false},
		{426, `{"error":"gated"}`, true, false, false},
		{429, `{"error":"slow down"}`, true, true, false},
		{500, `{"error":"boom"}`, true, true, false},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sessions" || r.Method != "POST" {
				t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			}
			w.WriteHeader(tc.status)
			w.Write([]byte(tc.body))
		}))
		c := NewClient(srv.URL)
		res, err := c.Submit(context.Background(), Build(testSummary(), "t"))
		srv.Close()
		if (err != nil) != tc.wantErr {
			t.Fatalf("status %d: err = %v", tc.status, err)
		}
		if err != nil && IsRetryable(err) != tc.retryable {
			t.Fatalf("status %d: retryable = %v, want %v", tc.status, IsRetryable(err), tc.retryable)
		}
		if err == nil && res.Duplicate != tc.duplicate {
			t.Fatalf("status %d: duplicate = %v", tc.status, res.Duplicate)
		}
	}
}

func TestSubmitNetworkErrorRetryable(t *testing.T) {
	c := NewClient("http://127.0.0.1:1") // nothing listens there
	c.HTTP.Timeout = time.Second
	_, err := c.Submit(context.Background(), Build(testSummary(), "t"))
	if err == nil || !IsRetryable(err) {
		t.Fatalf("network failure should be retryable, got %v", err)
	}
}

func TestOutboxFlow(t *testing.T) {
	dir := t.TempDir()
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(500)
			w.Write([]byte(`{"error":"down"}`))
			return
		}
		w.Write([]byte(`{"accepted":true}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL)

	if _, err := Enqueue(dir, Build(testSummary(), "t")); err != nil {
		t.Fatal(err)
	}
	if Pending(dir) != 1 {
		t.Fatal("enqueue did not persist")
	}

	// Server down: entry is rescheduled, not lost, not spun on.
	st, err := Flush(context.Background(), dir, c)
	if err != nil || st.Deferred != 1 || st.Sent != 0 {
		t.Fatalf("flush while down: %+v, %v", st, err)
	}
	// Immediately flushing again must respect the backoff window.
	st, _ = Flush(context.Background(), dir, c)
	if st.Deferred != 1 {
		t.Fatalf("backoff not respected: %+v", st)
	}

	// Force the entry due, bring the server up: it drains.
	rewriteDue(t, dir)
	fail.Store(false)
	st, err = Flush(context.Background(), dir, c)
	if err != nil || st.Sent != 1 || Pending(dir) != 0 {
		t.Fatalf("flush after recovery: %+v, %v", st, err)
	}
}

func TestOutboxDropsPermanentRejection(t *testing.T) {
	dir := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(426)
		w.Write([]byte(`{"error":"gated"}`))
	}))
	defer srv.Close()
	if _, err := Enqueue(dir, Build(testSummary(), "bad-version")); err != nil {
		t.Fatal(err)
	}
	st, err := Flush(context.Background(), dir, NewClient(srv.URL))
	if err != nil || st.Dropped != 1 || Pending(dir) != 0 {
		t.Fatalf("gated payload should be dropped: %+v, %v", st, err)
	}
}

// rewriteDue clears every queued entry's NextAttempt so Flush tries it now.
func rewriteDue(t *testing.T, dir string) {
	t.Helper()
	names, err := outboxFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var e entry
		if err := json.Unmarshal(data, &e); err != nil {
			t.Fatal(err)
		}
		e.NextAttempt = time.Time{}
		out, _ := json.Marshal(e)
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
