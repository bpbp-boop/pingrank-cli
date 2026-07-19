package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"pingrank.gg/internal/session"
	"pingrank.gg/internal/store"
	"pingrank.gg/internal/submit"
)

// resolveServer picks the ingest URL: -server flag, then PINGRANK_SERVER,
// then the production default.
func resolveServer(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("PINGRANK_SERVER"); env != "" {
		return env
	}
	return submit.DefaultServerURL
}

// cmdSubmit implements `pingrank submit`: explicit, opt-in sharing of one
// stored session (milestone 5). Nothing is ever sent without this command
// or `record -share`.
func cmdSubmit(args []string) int {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	dryRun := fs.Bool("dry-run", false, "print the exact payload that would be sent, send nothing")
	flush := fs.Bool("flush", false, "only retry queued submissions; no session argument")
	server := fs.String("server", "", "ingest server URL (default $PINGRANK_SERVER or "+submit.DefaultServerURL+")")
	dir := storeDirFlag(fs)
	fs.Parse(args)

	if *flush {
		if fs.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "usage: pingrank submit -flush [-server URL]")
			return 2
		}
		return flushOutbox(resolveServer(*server), os.Stdout)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pingrank submit [-dry-run] [-server URL] [-dir <dir>] <session-name-or-prefix>")
		return 2
	}

	storeDir, err := resolveStoreDir(*dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	recs, name, err := store.Load(storeDir, fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	payload := submit.Build(session.Summarize(recs), clientVersion)
	if len(payload.Session.Segments) == 0 {
		fmt.Fprintf(os.Stderr, "pingrank: %s has no segments; nothing to submit\n", name)
		return 1
	}

	url := resolveServer(*server)
	if *dryRun {
		raw, err := json.Marshal(payload)
		if err != nil {
			fmt.Fprintln(os.Stderr, "pingrank: encoding payload:", err)
			return 1
		}
		// Print exactly the request body used by Client.Submit, with no
		// explanatory prefix or pretty-print transformation.
		os.Stdout.Write(raw)
		return 0
	}

	flushOutbox(url, os.Stdout) // drain earlier failures first, best effort
	if !deliver(url, payload, name, os.Stdout) {
		return 1
	}
	return 0
}

// deliver submits one payload, queueing it on retryable failure. Returns
// false only for permanent rejection.
func deliver(url string, payload submit.Payload, label string, out io.Writer) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := submit.NewClient(url).Submit(ctx, payload)
	region := ""
	if res.Region != "" {
		region = " · region " + res.Region
		if res.City != "" {
			region += " (" + res.City + ")"
		}
	}
	switch {
	case err == nil && res.Duplicate:
		fmt.Fprintf(out, "submitted: %s (server already had it)%s\n", label, region)
	case err == nil:
		fmt.Fprintf(out, "submitted: %s → %s%s\n", label, url, region)
	case submit.IsRetryable(err):
		outDir, derr := submit.DefaultOutboxDir()
		if derr != nil {
			fmt.Fprintf(out, "submit failed (%v) and queueing is unavailable: %v\n", err, derr)
			return false
		}
		if _, qerr := submit.Enqueue(outDir, payload); qerr != nil {
			fmt.Fprintf(out, "submit failed (%v) and queueing failed: %v\n", err, qerr)
			return false
		}
		fmt.Fprintf(out, "server unreachable (%v); queued for retry on the next submit/record run\n", err)
	default:
		fmt.Fprintf(out, "submission rejected: %v\n", err)
		return false
	}
	return true
}

// flushOutbox drains queued submissions that are due. Always best-effort.
func flushOutbox(url string, out io.Writer) int {
	dir, err := submit.DefaultOutboxDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	if submit.Pending(dir) == 0 {
		return 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	st, err := submit.Flush(ctx, dir, submit.NewClient(url))
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank: flushing outbox:", err)
	}
	if st.Sent+st.Dropped+st.Deferred > 0 {
		fmt.Fprintf(out, "outbox: %d sent, %d dropped, %d still queued\n",
			st.Sent, st.Dropped, st.Deferred)
	}
	return 0
}
