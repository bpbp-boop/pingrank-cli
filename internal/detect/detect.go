// Package detect identifies running games by matching process executable
// names against an embedded signature list.
//
// Anti-cheat safety: we only enumerate the process list. We never open a
// process handle at all in this package — CreateToolhelp32Snapshot returns
// executable names directly, so there is nothing to open.
package detect

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

//go:embed signatures.json
var signaturesJSON []byte

// Signature describes one game we know how to recognize. Adding a game is a
// one-entry edit to signatures.json; no code changes required.
type Signature struct {
	GameID      string   `json:"gameId"`
	DisplayName string   `json:"displayName"`
	ExeNames    []string `json:"exeNames"`
	PeerToPeer  bool     `json:"peerToPeer,omitempty"`
	Hints       Hints    `json:"hints,omitempty"`
}

// Hints are optional per-game knowledge that sharpens endpoint ranking and
// measurement. All fields are optional; an empty Hints changes nothing.
type Hints struct {
	// ExpectedPorts are remote port ranges the game's servers are known
	// to use, e.g. "7000-9000" or "27015". Candidates in range rank
	// higher.
	ExpectedPorts []string `json:"expectedPorts,omitempty"`
	// ProbeMethod selects a game-protocol latency probe ("a2s" for
	// Source-lineage servers). Preferred over ICMP when it works: it
	// measures the real UDP path and port.
	ProbeMethod string `json:"probeMethod,omitempty"`
	// RelayCIDRs are network prefixes of a relay fleet (e.g. Valve SDR).
	// Endpoints inside are tagged relay: the measurement is to the relay,
	// not the game server, and must be labelled as such.
	RelayCIDRs []string `json:"relayCidrs,omitempty"`
	// RelayLabel names the relay fleet ("valve-sdr").
	RelayLabel string `json:"relayLabel,omitempty"`
}

// Process is one entry from the system process list.
type Process struct {
	PID     uint32
	ExeName string
}

// Match is a running game: a signature plus the PIDs of its processes.
type Match struct {
	Signature Signature
	PIDs      []uint32
}

// Lister enumerates running processes. Wrapped in an interface so the
// matching logic is testable without a live system.
type Lister interface {
	Processes() ([]Process, error)
}

// LoadSignatures parses the embedded signature list.
func LoadSignatures() ([]Signature, error) {
	var sigs []Signature
	if err := json.Unmarshal(signaturesJSON, &sigs); err != nil {
		return nil, fmt.Errorf("parsing embedded signatures.json: %w", err)
	}
	return sigs, nil
}

// MatchProcesses matches a process list against signatures. Exe name
// comparison is case-insensitive (NTFS is case-insensitive and launchers
// vary the casing). Pure function, table-tested.
func MatchProcesses(procs []Process, sigs []Signature) []Match {
	byExe := make(map[string]int) // lower exe name -> index into sigs
	for i, sig := range sigs {
		for _, exe := range sig.ExeNames {
			byExe[strings.ToLower(exe)] = i
		}
	}

	pids := make(map[int][]uint32) // sig index -> pids, preserving sig order
	for _, p := range procs {
		if i, ok := byExe[strings.ToLower(p.ExeName)]; ok {
			pids[i] = append(pids[i], p.PID)
		}
	}

	var matches []Match
	for i, sig := range sigs {
		if ps := pids[i]; len(ps) > 0 {
			matches = append(matches, Match{Signature: sig, PIDs: ps})
		}
	}
	return matches
}

// MatchExe matches a specific executable name (the --game flag path),
// bypassing the signature list.
func MatchExe(procs []Process, exeName string) []uint32 {
	var pids []uint32
	for _, p := range procs {
		if strings.EqualFold(p.ExeName, exeName) {
			pids = append(pids, p.PID)
		}
	}
	return pids
}

// ToolhelpLister lists processes via CreateToolhelp32Snapshot.
//
// Why Toolhelp over EnumProcesses: EnumProcesses returns bare PIDs, so
// getting each name would require OpenProcess + QueryFullProcessImageName
// per PID — hundreds of handle opens per poll, each visible to anti-cheat
// hooks and each a potential ACCESS_DENIED on protected processes. The
// Toolhelp snapshot hands us PID + exe name in one documented call with no
// per-process handles at all.
type ToolhelpLister struct{}

func (ToolhelpLister) Processes() ([]Process, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Process32First(snap, &entry); err != nil {
		return nil, fmt.Errorf("Process32First: %w", err)
	}

	var procs []Process
	for {
		procs = append(procs, Process{
			PID:     entry.ProcessID,
			ExeName: windows.UTF16ToString(entry.ExeFile[:]),
		})
		if err := windows.Process32Next(snap, &entry); err != nil {
			if err == windows.ERROR_NO_MORE_FILES {
				break
			}
			return nil, fmt.Errorf("Process32Next: %w", err)
		}
	}
	return procs, nil
}
