package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"pingrank.gg/internal/gamelog"
)

type logReport struct {
	GameID      string           `json:"gameId"`
	DisplayName string           `json:"displayName"`
	Path        string           `json:"path"`
	Servers     []gamelog.Server `json:"servers"`
}

// cmdParseLog implements `pingrank parse-log`: extract server endpoints from
// a game log without inspecting or attaching to the game process.
func cmdParseLog(args []string) int {
	fs := flag.NewFlagSet("parse-log", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	gameID := fs.String("game", "rocketleague", "game log format (currently: rocketleague)")
	jsonOut := fs.Bool("json", false, "emit structured JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: pingrank parse-log [-game <id>] [-json] [log-file]")
		return 2
	}

	parser, err := gamelog.ForGame(*gameID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	path := ""
	if fs.NArg() == 1 {
		path = fs.Arg(0)
	} else if path, err = parser.DefaultLogPath(); err != nil {
		fmt.Fprintln(os.Stderr, "pingrank: finding default log:", err)
		return 1
	}

	f, err := os.Open(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank: opening game log:", err)
		return 1
	}
	defer f.Close()
	endpoints, err := gamelog.Parse(f, parser)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pingrank:", err)
		return 1
	}
	report := logReport{
		GameID: parser.GameID(), DisplayName: parser.DisplayName(), Path: path,
		Servers: gamelog.GroupServers(endpoints),
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintln(os.Stderr, "pingrank:", err)
			return 1
		}
		return 0
	}

	fmt.Printf("game: %s\nlog:  %s\n", report.DisplayName, report.Path)
	if len(endpoints) == 0 {
		fmt.Println("no match server endpoints found.")
		return 0
	}
	fmt.Printf("match servers (%d):\n", len(report.Servers))
	for i, server := range report.Servers {
		fmt.Printf(" %d. %s\n", i+1, server.IP)
		for _, endpoint := range server.Endpoints {
			fmt.Printf("      %-4s %-4s :%-5d  source: %s  lines: %d-%d\n",
				endpoint.Protocol, endpoint.Role, endpoint.Port,
				strings.Join(endpoint.Sources, ", "), endpoint.FirstLine, endpoint.LastLine)
		}
	}
	return 0
}
