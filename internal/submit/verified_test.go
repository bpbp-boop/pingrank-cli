package submit

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pingrank.gg/internal/accesspath"
	"pingrank.gg/internal/identity"
	"pingrank.gg/internal/session"
)

func TestLiveRecordingBatchesRetriesAndMinimizesAccessPath(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	creds := identity.Credentials{AgentID: "00112233445566778899aabbccddeeff", PublicKey: pub, PrivateKey: priv}

	var eventCalls atomic.Int32
	var sawSecret atomic.Bool
	var sawPublicIPv4 atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/recordings":
			_ = json.NewEncoder(w).Encode(liveReply{RecordingID: "rec-1", Challenge: "ch-1"})
		case strings.HasSuffix(r.URL.Path, "/events"):
			n := eventCalls.Add(1)
			if n == 1 {
				// Simulate a single transient 503; client must retry and succeed.
				http.Error(w, "restarting", http.StatusServiceUnavailable)
				return
			}
			var body liveEvents
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			raw, _ := json.Marshal(body)
			if strings.Contains(string(raw), "198.51.100.77") || strings.Contains(string(raw), "2407:aaaa::99") || strings.Contains(string(raw), "54321") {
				sawSecret.Store(true)
			}
			if strings.Contains(string(raw), "203.0.113.5") {
				sawPublicIPv4.Store(true)
			}
			_ = json.NewEncoder(w).Encode(liveReply{Challenge: "ch-2"})
		case strings.HasSuffix(r.URL.Path, "/finalize"):
			_ = json.NewEncoder(w).Encode(liveReply{Accepted: true, Region: "AU", City: "Sydney"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	live := NewLiveRecording(srv.URL, "0.8.2-test", creds)
	now := time.Now().UTC()
	live.Push(session.Record{
		V: 1, T: session.RecSessionStart, Time: now, GameID: "rocketleague", AgentID: creds.AgentID,
		AccessPath: &accesspath.Result{
			Classification:     accesspath.HomeNATOnly,
			Confidence:         accesspath.ConfidenceSuggestive,
			RouterExternalIPv4: "198.51.100.77",
			ObservedPublicIPv4: "203.0.113.5",
			ObservedPublicIPv6: "2407:aaaa::99",
			Observations:       []accesspath.Observation{{PublicIPv4: "203.0.113.5", PublicPort: 54321, Transport: "udp"}},
		},
	})
	live.Push(session.Record{V: 1, T: session.RecSessionEnd, Time: now.Add(time.Second), Reason: "process-exit"})

	res, err := live.Close()
	if err != nil {
		t.Fatalf("live.Close: %v", err)
	}
	if res.Region != "AU" || res.City != "Sydney" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if eventCalls.Load() < 2 {
		t.Fatalf("expected retry after 503, got %d event calls", eventCalls.Load())
	}
	if sawSecret.Load() {
		t.Fatal("client leaked client-only RouterExternalIPv4/ObservedPublicIPv6/Observations")
	}
	if !sawPublicIPv4.Load() {
		t.Fatal("client dropped ObservedPublicIPv4 needed for server CGNAT correlation")
	}
}
