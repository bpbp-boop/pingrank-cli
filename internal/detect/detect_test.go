package detect

import (
	"testing"

	"pingrank.gg/internal/flows"
	"pingrank.gg/internal/probe"
)

func TestLoadSignatures(t *testing.T) {
	sigs, err := LoadSignatures()
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	if len(sigs) < 5 {
		t.Fatalf("expected at least the 5 seed games, got %d", len(sigs))
	}
	for _, sig := range sigs {
		if sig.GameID == "" || sig.DisplayName == "" || len(sig.ExeNames) == 0 {
			t.Errorf("incomplete signature: %+v", sig)
		}
		if sig.GameID == "helldivers2" && !sig.PeerToPeer {
			t.Error("Helldivers 2 signature is not marked peer-to-peer")
		}
	}
}

// TestSignatureCoverageAndHints guards the curated data: M4 wants ~20
// titles, and every hint must parse (typos in signatures.json should fail
// CI, not silently disable a hint at runtime).
func TestSignatureCoverageAndHints(t *testing.T) {
	sigs, err := LoadSignatures()
	if err != nil {
		t.Fatal(err)
	}
	if len(sigs) < 20 {
		t.Errorf("signature coverage regressed: %d titles, want 20+", len(sigs))
	}
	seen := map[string]bool{}
	for _, sig := range sigs {
		if seen[sig.GameID] {
			t.Errorf("duplicate gameId %q", sig.GameID)
		}
		seen[sig.GameID] = true
		if _, err := flows.ParseHints(sig.Hints.ExpectedPorts, sig.Hints.RelayCIDRs, sig.Hints.RelayLabel); err != nil {
			t.Errorf("%s: bad hints: %v", sig.GameID, err)
		}
		if sig.Hints.ProbeMethod != "" && !probe.GameProtocolAllowed(sig.GameID, sig.Hints.ProbeMethod) {
			t.Errorf("%s: probeMethod %q is not in the compiled active-probe allowlist", sig.GameID, sig.Hints.ProbeMethod)
		}
		if len(sig.Hints.RelayCIDRs) > 0 && sig.Hints.RelayLabel == "" {
			t.Errorf("%s: relay CIDRs without a relayLabel", sig.GameID)
		}
	}
}

var testSigs = []Signature{
	{GameID: "cs2", DisplayName: "Counter-Strike 2", ExeNames: []string{"cs2.exe"}},
	{GameID: "valorant", DisplayName: "Valorant", ExeNames: []string{"VALORANT-Win64-Shipping.exe"}},
	{GameID: "multi", DisplayName: "Multi-Exe Game", ExeNames: []string{"game.exe", "game_dx12.exe"}},
}

func TestMatchProcesses(t *testing.T) {
	tests := []struct {
		name      string
		procs     []Process
		wantGames []string
		wantPIDs  map[string][]uint32
	}{
		{
			name:      "no processes",
			procs:     nil,
			wantGames: nil,
		},
		{
			name:      "no matching processes",
			procs:     []Process{{PID: 1, ExeName: "explorer.exe"}, {PID: 2, ExeName: "chrome.exe"}},
			wantGames: nil,
		},
		{
			name:      "exact match",
			procs:     []Process{{PID: 100, ExeName: "cs2.exe"}},
			wantGames: []string{"cs2"},
			wantPIDs:  map[string][]uint32{"cs2": {100}},
		},
		{
			name:      "case-insensitive match",
			procs:     []Process{{PID: 100, ExeName: "CS2.EXE"}, {PID: 200, ExeName: "valorant-win64-shipping.exe"}},
			wantGames: []string{"cs2", "valorant"},
			wantPIDs:  map[string][]uint32{"cs2": {100}, "valorant": {200}},
		},
		{
			name:      "multiple pids for one game",
			procs:     []Process{{PID: 10, ExeName: "cs2.exe"}, {PID: 20, ExeName: "cs2.exe"}},
			wantGames: []string{"cs2"},
			wantPIDs:  map[string][]uint32{"cs2": {10, 20}},
		},
		{
			name:      "any exe alias matches",
			procs:     []Process{{PID: 7, ExeName: "game_dx12.exe"}},
			wantGames: []string{"multi"},
			wantPIDs:  map[string][]uint32{"multi": {7}},
		},
		{
			name:      "substring must not match",
			procs:     []Process{{PID: 1, ExeName: "notcs2.exe"}, {PID: 2, ExeName: "cs2.exe.bak"}},
			wantGames: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MatchProcesses(tt.procs, testSigs)
			if len(got) != len(tt.wantGames) {
				t.Fatalf("got %d matches, want %d: %+v", len(got), len(tt.wantGames), got)
			}
			for i, m := range got {
				if m.Signature.GameID != tt.wantGames[i] {
					t.Errorf("match %d: got game %s, want %s", i, m.Signature.GameID, tt.wantGames[i])
				}
				wantPIDs := tt.wantPIDs[m.Signature.GameID]
				if len(m.PIDs) != len(wantPIDs) {
					t.Errorf("game %s: got pids %v, want %v", m.Signature.GameID, m.PIDs, wantPIDs)
					continue
				}
				for j, pid := range m.PIDs {
					if pid != wantPIDs[j] {
						t.Errorf("game %s: got pids %v, want %v", m.Signature.GameID, m.PIDs, wantPIDs)
						break
					}
				}
			}
		})
	}
}

func TestMatchExe(t *testing.T) {
	procs := []Process{
		{PID: 1, ExeName: "explorer.exe"},
		{PID: 2, ExeName: "MyGame.exe"},
		{PID: 3, ExeName: "mygame.exe"},
	}
	pids := MatchExe(procs, "MYGAME.EXE")
	if len(pids) != 2 || pids[0] != 2 || pids[1] != 3 {
		t.Errorf("MatchExe case-insensitive: got %v, want [2 3]", pids)
	}
	if got := MatchExe(procs, "other.exe"); got != nil {
		t.Errorf("MatchExe no match: got %v, want nil", got)
	}
}
