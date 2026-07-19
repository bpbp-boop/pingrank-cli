package submit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"pingrank.gg/internal/identity"
	"pingrank.gg/internal/session"
)

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
	events        chan session.Record
	done          chan struct{}
	err           error
	id, challenge string
	seq           int
	result        Result
}

func NewLiveRecording(base, version string, creds identity.Credentials) *LiveRecording {
	l := &LiveRecording{base: base, version: version, creds: creds, events: make(chan session.Record, 512), done: make(chan struct{})}
	go l.run()
	return l
}
func (l *LiveRecording) Push(r session.Record) {
	select {
	case l.events <- r:
	default:
		l.setErr(fmt.Errorf("live event buffer full"))
	}
}
func (l *LiveRecording) Close() (Result, error) {
	close(l.events)
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

func (l *LiveRecording) run() {
	defer close(l.done)
	ctx := context.Background()
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
				l.finish(ctx)
				return
			}
			if !started {
				if r.T != "session_start" {
					continue
				}
				if err := l.start(ctx, r); err != nil {
					l.setErr(err)
					return
				}
				started = true
			}
			if err := l.send(ctx, []session.Record{r}); err != nil {
				l.setErr(err)
				return
			}
		case <-ticker.C:
			if !started {
				continue
			}
			select {
			case r, ok := <-l.events:
				if !ok {
					l.finish(ctx)
					return
				}
				if err := l.send(ctx, []session.Record{r}); err != nil {
					l.setErr(err)
					return
				}
			default:
				if err := l.send(ctx, nil); err != nil {
					l.setErr(err)
					return
				}
			}
		}
	}
}
func (l *LiveRecording) start(ctx context.Context, r session.Record) error {
	q := liveStart{AgentID: l.creds.AgentID, PublicKey: base64.StdEncoding.EncodeToString(l.creds.PublicKey), ClientVersion: l.version, GameID: r.GameID}
	q.Signature = sig(l.creds.PrivateKey, startMsg(q))
	var out liveReply
	if err := l.post(ctx, "/v1/recordings", q, &out); err != nil {
		return err
	}
	l.id, l.challenge, l.seq = out.RecordingID, out.Challenge, 1
	return nil
}
func (l *LiveRecording) send(ctx context.Context, ev []session.Record) error {
	q := liveEvents{Seq: l.seq, Challenge: l.challenge, Events: ev}
	q.Signature = sig(l.creds.PrivateKey, eventsMsg(l.id, q))
	var out liveReply
	if err := l.post(ctx, "/v1/recordings/"+l.id+"/events", q, &out); err != nil {
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
	if err := l.post(ctx, "/v1/recordings/"+l.id+"/finalize", q, &out); err != nil {
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
func (l *LiveRecording) post(ctx context.Context, path string, in, out any) error {
	raw, _ := json.Marshal(in)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, l.base+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pingrank/"+l.version)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("verified ingest returned %d: %s", resp.StatusCode, bytes.TrimSpace(body))
	}
	return json.Unmarshal(body, out)
}
