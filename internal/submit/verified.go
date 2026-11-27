package submit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"pingrank.gg/internal/identity"
	"pingrank.gg/internal/session"
)

// DefaultServerURL is the production ingest endpoint.
const DefaultServerURL = "https://ingest.pingrank.gg"

const (
	maxBatchSize    = 64
	maxPostRetries  = 3
	shutdownTimeout = 8 * time.Second
)

// Result reports where the server stored a verified recording.
type Result struct {
	Duplicate bool
	Region    string
	City      string
}

type liveStart struct {
	AgentID       string `json:"agentId"`
	PublicKey     string `json:"publicKey"`
	ClientVersion string `json:"clientVersion"`
	GameID        string `json:"gameId"`
	Signature     string `json:"signature"`
}
type liveEvents struct {
	Seq       int              `json:"seq"`
	Challenge string           `json:"challenge"`
	Events    []session.Record `json:"events"`
	Signature string           `json:"signature"`
}
type liveFinal struct {
	Challenge string `json:"challenge"`
	Signature string `json:"signature"`
}
type liveReply struct {
	RecordingID string    `json:"recordingId"`
	Challenge   string    `json:"challenge"`
	Deadline    time.Time `json:"deadline"`
	Accepted    bool      `json:"accepted"`
	Duplicate   bool      `json:"duplicate"`
	Region      string    `json:"region"`
	City        string    `json:"city"`
}

// LiveRecording streams an opted-in recording without blocking the recorder.
type LiveRecording struct {
	mu            sync.Mutex
	base, version string
	creds         identity.Credentials
	client        *http.Client
	events        chan session.Record
	closing       chan struct{}
	closeOnce     sync.Once
	done          chan struct{}
	err           error
	id, challenge string
	seq           int
	result        Result
}

func NewLiveRecording(base, version string, creds identity.Credentials) *LiveRecording {
	l := &LiveRecording{
		base:    base,
		version: version,
		creds:   creds,
		client:  &http.Client{Timeout: 10 * time.Second},
		events:  make(chan session.Record, 512),
		closing: make(chan struct{}),
		done:    make(chan struct{}),
	}
	go l.run()
	return l
}
func (l *LiveRecording) Push(r session.Record) {
	select {
	case l.events <- minimizeForUpload(r):
	default:
		l.setErr(fmt.Errorf("live event buffer full"))
	}
}
func (l *LiveRecording) Close() (Result, error) {
	l.closeOnce.Do(func() {
		close(l.closing)
		close(l.events)
	})
	<-l.done
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.result, l.err
}
func (l *LiveRecording) setErr(err error) {
	l.mu.Lock()
	if l.err == nil {
		l.err = err
	}
	l.mu.Unlock()
}

// minimizeForUpload drops client-only address/port observations that the server
// never uses, keeping only the classification, evidence, NAT64 prefix, and the
// two correlation inputs the server hashes (ObservedPublicIPv4, IPv6Prefix).
func minimizeForUpload(r session.Record) session.Record {
	if r.AccessPath == nil {
		return r
	}
	ap := *r.AccessPath
	ap.RouterExternalIPv4 = ""
	ap.ObservedPublicIPv6 = ""
	ap.Observations = nil
	r.AccessPath = &ap
	return r
}

func startMsg(q liveStart) []byte {
	return []byte("PINGRANK-START-v1\x00" + q.AgentID + "\x00" + q.PublicKey + "\x00" + q.ClientVersion + "\x00" + q.GameID)
}
func eventsMsg(id string, q liveEvents) []byte {
	raw, _ := json.Marshal(q.Events)
	h := sha256.Sum256(raw)
	return []byte(fmt.Sprintf("PINGRANK-EVENTS-v1\x00%s\x00%d\x00%s\x00%x", id, q.Seq, q.Challenge, h))
}
func finalMsg(id, ch string) []byte { return []byte("PINGRANK-FINAL-v1\x00" + id + "\x00" + ch) }
func sig(priv ed25519.PrivateKey, b []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, b))
}

func (l *LiveRecording) drainBatch(first session.Record) ([]session.Record, bool) {
	batch := []session.Record{first}
	for len(batch) < maxBatchSize {
		select {
		case r, ok := <-l.events:
			if !ok {
				return batch, true
			}
			batch = append(batch, r)
		default:
			return batch, false
		}
	}
	return batch, false
}

func (l *LiveRecording) opContext() (context.Context, context.CancelFunc) {
	select {
	case <-l.closing:
		// Bound drain/finalize during service shutdown so we stay well inside
		// the 20s Windows service stop budget.
		return context.WithTimeout(context.Background(), shutdownTimeout)
	default:
		return context.Background(), func() {}
	}
}

func (l *LiveRecording) run() {
	defer close(l.done)
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	started := false
	for {
		select {
		case r, ok := <-l.events:
			if !ok {
				if !started {
					l.setErr(fmt.Errorf("recording never started"))
					return
				}
				ctx, cancel := l.opContext()
				l.finish(ctx)
				cancel()
				return
			}
			ctx, cancel := l.opContext()
			if !started {
				if r.T != "session_start" {
					cancel()
					continue
				}
				if err := l.start(ctx, r); err != nil {
					cancel()
					l.setErr(err)
					return
				}
				started = true
			}
			batch, closed := l.drainBatch(r)
			if err := l.send(ctx, batch); err != nil {
				cancel()
				l.setErr(err)
				return
			}
			if closed {
				l.finish(ctx)
				cancel()
				return
			}
			cancel()
		case <-ticker.C:
			if !started {
				continue
			}
			ctx, cancel := l.opContext()
			select {
			case r, ok := <-l.events:
				if !ok {
					l.finish(ctx)
					cancel()
					return
				}
				batch, closed := l.drainBatch(r)
				if err := l.send(ctx, batch); err != nil {
					cancel()
					l.setErr(err)
					return
				}
				if closed {
					l.finish(ctx)
					cancel()
					return
				}
			default:
				if err := l.send(ctx, []session.Record{}); err != nil {
					cancel()
					l.setErr(err)
					return
				}
			}
			cancel()
		}
	}
}

func (l *LiveRecording) start(ctx context.Context, r session.Record) error {
	q := liveStart{AgentID: l.creds.AgentID, PublicKey: base64.StdEncoding.EncodeToString(l.creds.PublicKey), ClientVersion: l.version, GameID: r.GameID}
	q.Signature = sig(l.creds.PrivateKey, startMsg(q))
	var out liveReply
	if err := l.postWithRetry(ctx, "/v1/recordings", q, &out); err != nil {
		return err
	}
	l.id, l.challenge, l.seq = out.RecordingID, out.Challenge, 1
	return nil
}
func (l *LiveRecording) send(ctx context.Context, ev []session.Record) error {
	if ev == nil {
		ev = []session.Record{}
	}
	q := liveEvents{Seq: l.seq, Challenge: l.challenge, Events: ev}
	q.Signature = sig(l.creds.PrivateKey, eventsMsg(l.id, q))
	var out liveReply
	if err := l.postWithRetry(ctx, "/v1/recordings/"+l.id+"/events", q, &out); err != nil {
		return err
	}
	l.seq++
	l.challenge = out.Challenge
	return nil
}
func (l *LiveRecording) finish(ctx context.Context) {
	q := liveFinal{Challenge: l.challenge}
	q.Signature = sig(l.creds.PrivateKey, finalMsg(l.id, l.challenge))
	var out liveReply
	if err := l.postWithRetry(ctx, "/v1/recordings/"+l.id+"/finalize", q, &out); err != nil {
		l.setErr(err)
		return
	}
	if !out.Accepted {
		l.setErr(fmt.Errorf("server did not accept verified recording"))
		return
	}
	l.mu.Lock()
	l.result = Result{Duplicate: out.Duplicate, Region: out.Region, City: out.City}
	l.mu.Unlock()
}

type httpStatusError struct {
	code int
	body string
}

func (e httpStatusError) Error() string {
	return fmt.Sprintf("verified ingest returned %d: %s", e.code, e.body)
}

func retryable(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var se httpStatusError
	if errors.As(err, &se) {
		return se.code >= 500 || se.code == http.StatusTooManyRequests
	}
	return true
}

func (l *LiveRecording) postWithRetry(ctx context.Context, path string, in, out any) error {
	var err error
	backoff := 250 * time.Millisecond
	for attempt := 0; attempt < maxPostRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		err = l.post(ctx, path, in, out)
		if !retryable(err) {
			return err
		}
	}
	return err
}

func (l *LiveRecording) post(ctx context.Context, path string, in, out any) error {
	raw, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pingrank/"+l.version)
	resp, err := l.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return httpStatusError{code: resp.StatusCode, body: string(bytes.TrimSpace(body))}
	}
	return json.Unmarshal(body, out)
}
