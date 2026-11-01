// Package update keeps the installed app current. The service asks the
// server for the newest release, downloads the MSI, checks its SHA-256 and
// its Authenticode signer, waits until no game is being recorded, and then
// hands the MSI to Windows Installer.
//
// The server's answer alone cannot make the app run anything: the MSI must
// also carry a valid signature from SignerName, and Windows Installer
// refuses to install an older version over a newer one.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SignerName is the subject common name every release is signed with.
const SignerName = "Open Source Developer Boden Phillip Garman"

// MaxInstallerBytes bounds a download; releases are under 10 MB.
const MaxInstallerBytes = 100 << 20

// Release is the server's answer from GET /v1/client/latest.
type Release struct {
	Version string `json:"version"`
	MSIURL  string `json:"msiUrl"`
	SHA256  string `json:"sha256"`
}

var (
	versionPattern = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	sha256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// parseVersion reads a plain release version. Dev builds ("0.7.12-dev")
// do not parse, so they never update themselves.
func parseVersion(v string) ([3]int, bool) {
	m := versionPattern.FindStringSubmatch(v)
	if m == nil {
		return [3]int{}, false
	}
	var out [3]int
	for i := range out {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

// Newer reports whether latest is a later release than current.
func Newer(latest, current string) bool {
	l, ok1 := parseVersion(latest)
	c, ok2 := parseVersion(current)
	if !ok1 || !ok2 {
		return false
	}
	for i := range l {
		if l[i] != c[i] {
			return l[i] > c[i]
		}
	}
	return false
}

// FetchLatest asks the server for the newest release and checks the shape
// of its answer.
func FetchLatest(ctx context.Context, client *http.Client, serverURL, userAgent string) (Release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(serverURL, "/")+"/v1/client/latest", nil)
	if err != nil {
		return Release{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return Release{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Release{}, fmt.Errorf("update check: %s", resp.Status)
	}
	var r Release
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r); err != nil {
		return Release{}, fmt.Errorf("update check: %w", err)
	}
	r.SHA256 = strings.ToLower(r.SHA256)
	if _, ok := parseVersion(r.Version); !ok {
		return Release{}, fmt.Errorf("update check: bad version %q", r.Version)
	}
	if !strings.HasPrefix(r.MSIURL, "https://") {
		return Release{}, fmt.Errorf("update check: installer URL is not https")
	}
	if !sha256Pattern.MatchString(r.SHA256) {
		return Release{}, fmt.Errorf("update check: bad checksum")
	}
	return r, nil
}

// Download saves the installer into dir and checks its SHA-256. dir must
// be writable only by the service, so nobody can swap the file between
// these checks and the install.
func Download(ctx context.Context, client *http.Client, r Release, dir, userAgent string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.MSIURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download: %s", resp.Status)
	}
	path := filepath.Join(dir, "pingrank.gg-"+r.Version+"-x64.msi")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, hash), io.LimitReader(resp.Body, MaxInstallerBytes+1))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil && n > MaxInstallerBytes {
		err = fmt.Errorf("download: installer is larger than %d bytes", MaxInstallerBytes)
	}
	if err == nil && hex.EncodeToString(hash.Sum(nil)) != r.SHA256 {
		err = errors.New("download: checksum does not match")
	}
	if err != nil {
		_ = os.Remove(path)
		return "", err
	}
	return path, nil
}

// Config wires an Updater. The function fields are the Windows-specific
// steps; tests replace them.
type Config struct {
	ServerURL      string
	CurrentVersion string
	Client         *http.Client

	// Enabled reports whether the machine allows automatic updates.
	Enabled func() bool
	// Idle reports whether no game is being recorded.
	Idle func() bool
	// Stage makes a new directory that only the service can write to.
	Stage func() (string, error)
	// Verify checks the installer's Authenticode signature and signer.
	Verify func(path string) error
	// Install starts Windows Installer on the MSI and returns once it is
	// running. The installer stops this service as part of the upgrade.
	Install func(msiPath, dir string) error
	// Log records progress and failures.
	Log func(string)

	FirstCheck time.Duration // delay after start; default 5 minutes
	Interval   time.Duration // between checks; default 6 hours, ±1 hour
	IdlePoll   time.Duration // how often to look for a gap between games
}

// Updater runs the check-download-install loop.
type Updater struct{ cfg Config }

func New(cfg Config) *Updater {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	if cfg.Enabled == nil {
		cfg.Enabled = func() bool { return true }
	}
	if cfg.FirstCheck == 0 {
		cfg.FirstCheck = 5 * time.Minute
	}
	if cfg.Interval == 0 {
		cfg.Interval = 6 * time.Hour
	}
	if cfg.IdlePoll == 0 {
		cfg.IdlePoll = time.Minute
	}
	return &Updater{cfg: cfg}
}

// Run checks for updates until ctx ends or an install starts. It returns
// true when the installer is running, so the caller can wait to be stopped.
func (u *Updater) Run(ctx context.Context) bool {
	if _, ok := parseVersion(u.cfg.CurrentVersion); !ok {
		u.cfg.Log("updates off: " + u.cfg.CurrentVersion + " is not a release build")
		return false
	}
	wait := u.cfg.FirstCheck
	for {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
		installed, err := u.Check(ctx)
		if installed {
			return true
		}
		if err != nil && ctx.Err() == nil {
			u.cfg.Log(err.Error())
		}
		wait = jitter(u.cfg.Interval)
	}
}

func jitter(d time.Duration) time.Duration {
	spread := d / 6
	if spread <= 0 {
		return d
	}
	return d - spread + rand.N(2*spread)
}

// Check runs one update attempt. It returns true once the installer has
// started.
func (u *Updater) Check(ctx context.Context) (bool, error) {
	if !u.cfg.Enabled() {
		return false, nil
	}
	ua := "pingrank/" + u.cfg.CurrentVersion
	r, err := FetchLatest(ctx, u.cfg.Client, u.cfg.ServerURL, ua)
	if err != nil {
		return false, err
	}
	if !Newer(r.Version, u.cfg.CurrentVersion) {
		return false, nil
	}
	u.cfg.Log("update " + r.Version + " found")
	dir, err := u.cfg.Stage()
	if err != nil {
		return false, fmt.Errorf("update staging: %w", err)
	}
	path, err := Download(ctx, u.cfg.Client, r, dir, ua)
	if err != nil {
		_ = os.RemoveAll(dir)
		return false, err
	}
	if err := u.cfg.Verify(path); err != nil {
		_ = os.RemoveAll(dir)
		return false, fmt.Errorf("update %s rejected: %w", r.Version, err)
	}
	// Wait for a gap between games, but give up at the next check so a
	// newer release can replace this one.
	deadline := time.Now().Add(u.cfg.Interval)
	for !u.cfg.Idle() {
		if time.Now().After(deadline) {
			_ = os.RemoveAll(dir)
			return false, errors.New("update postponed: a game was running all along")
		}
		select {
		case <-ctx.Done():
			_ = os.RemoveAll(dir)
			return false, ctx.Err()
		case <-time.After(u.cfg.IdlePoll):
		}
	}
	if !u.cfg.Enabled() {
		_ = os.RemoveAll(dir)
		return false, nil
	}
	u.cfg.Log("installing update " + r.Version)
	if err := u.cfg.Install(path, dir); err != nil {
		_ = os.RemoveAll(dir)
		return false, fmt.Errorf("update install: %w", err)
	}
	return true, nil
}
