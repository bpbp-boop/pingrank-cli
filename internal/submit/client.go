package submit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to the ingest backend.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

func NewClient(baseURL string) *Client {
	return &Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Result reports a delivered submission. Duplicate means the server had
// already stored this session (an earlier attempt we never saw
// acknowledged) — success as far as the queue is concerned. Region and City
// are where the server filed the session, derived server-side from the
// submitting connection ("" on older servers or when unknown).
type Result struct {
	Duplicate bool
	Region    string
	City      string
}

// Error classifies a failed submission. Retryable failures (network,
// server-side trouble) belong in the outbox; permanent ones (validation,
// gated client version) must be dropped, not retried forever.
type Error struct {
	Status    int // 0 for network errors
	Msg       string
	Retryable bool
}

func (e *Error) Error() string {
	if e.Status == 0 {
		return e.Msg
	}
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Msg)
}

// Submit delivers one payload.
func (c *Client) Submit(ctx context.Context, p Payload) (Result, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return Result{}, &Error{Msg: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.BaseURL+"/v1/sessions", bytes.NewReader(body))
	if err != nil {
		return Result{}, &Error{Msg: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "pingrank/"+p.ClientVersion)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return Result{}, &Error{Msg: err.Error(), Retryable: true}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		var ok struct {
			Accepted  bool   `json:"accepted"`
			Duplicate bool   `json:"duplicate"`
			Region    string `json:"region"`
			City      string `json:"city"`
		}
		if err := json.Unmarshal(raw, &ok); err != nil {
			return Result{}, &Error{Status: resp.StatusCode, Msg: "invalid success response: " + err.Error(), Retryable: true}
		}
		if !ok.Accepted {
			return Result{}, &Error{Status: resp.StatusCode, Msg: "server did not acknowledge the submission", Retryable: true}
		}
		return Result{Duplicate: ok.Duplicate, Region: ok.Region, City: ok.City}, nil
	}

	msg := strings.TrimSpace(string(raw))
	var eresp struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &eresp) == nil && eresp.Error != "" {
		msg = eresp.Error
	}
	retryable := resp.StatusCode == http.StatusRequestTimeout ||
		resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode >= 500
	return Result{}, &Error{Status: resp.StatusCode, Msg: msg, Retryable: retryable}
}

// IsRetryable reports whether err should be queued for another attempt.
func IsRetryable(err error) bool {
	if e, ok := err.(*Error); ok {
		return e.Retryable
	}
	return false
}
