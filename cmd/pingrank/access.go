package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"pingrank.gg/internal/accesspath"
)

func cmdAccess(args []string) int {
	fs := flag.NewFlagSet("access", flag.ContinueOnError)
	jsonOut := fs.Bool("json", false, "emit structured JSON")
	refresh := fs.Bool("refresh", false, "ignore the 24-hour cached result")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	path, err := accesspath.DefaultCachePath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	var result accesspath.Result
	if !*refresh {
		if cached, ok := accesspath.LoadCache(path, 24*time.Hour); ok {
			result = cached
		}
	}
	if result.TestedAt.IsZero() {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		result, err = accesspath.Measure(ctx, accesspath.ReflectorsFromEnv())
		if err != nil {
			fmt.Fprintln(os.Stderr, "pingrank: access test:", err)
			return 1
		}
		_ = accesspath.SaveCache(path, result)
	}
	if *jsonOut {
		if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
			fmt.Fprintln(os.Stderr, "pingrank:", err)
			return 1
		}
		return 0
	}
	fmt.Printf("Internet access: %s\nConfidence: %s\n\n%s\n", result.Classification, result.Confidence, accesspath.Explanation(result))
	if len(result.Evidence) > 0 {
		fmt.Println("Evidence:")
		for _, e := range result.Evidence {
			if e.Source != "" {
				fmt.Printf("  - %s (%s)\n", e.Type, e.Source)
			} else {
				fmt.Printf("  - %s\n", e.Type)
			}
		}
	}
	fmt.Printf("\nIPv4 available: %t\nGlobal IPv6 available: %t\nLast tested: %s\n", result.LocalIPv4Available, result.GlobalIPv6Available, result.TestedAt.Local().Format(time.RFC3339))
	return 0
}
