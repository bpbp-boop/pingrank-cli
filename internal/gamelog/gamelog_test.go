package gamelog

import (
	"strings"
	"testing"
)

func TestRocketLeagueParseFindsMatchEndpoints(t *testing.T) {
	log := strings.Join([]string{
		`[0018.82] ScriptLog: RegionPinger_X_0 PingRegions ("13.244.191.147:7789","3.26.122.40:7759")`,
		`[0063.89] Party: HandleServerReserved (Reservation=(ServerName="OCE1-Test"),PingURL="3.26.125.197:7717",GameURL="3.26.125.197:7716")`,
		`[0067.29] DevNet: Browse: 3.26.125.197:7716/MENU_Main_p?Name=player`,
	}, "\n")

	got, err := Parse(strings.NewReader(log), RocketLeagueParser{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d endpoints, want 2: %+v", len(got), got)
	}
	if got[0].Address != "3.26.125.197:7716" || got[0].Role != "game" || got[0].Occurrences != 2 {
		t.Errorf("first endpoint = %+v", got[0])
	}
	if got[1].Address != "3.26.125.197:7717" || got[1].Role != "ping" {
		t.Errorf("ping endpoint = %+v", got[1])
	}
	if len(got[0].Sources) != 2 {
		t.Errorf("game endpoint sources = %v", got[0].Sources)
	}
}

func TestRocketLeagueParseRejectsUnrelatedAndPrivateAddresses(t *testing.T) {
	log := strings.Join([]string{
		`[0018.82] ScriptLog: RegionPinger_X_0 PingRegions ("13.244.191.147:7789")`,
		`[0063.89] Party: PingURL="10.0.0.1:7717",GameURL="not-an-address"`,
	}, "\n")
	got, err := Parse(strings.NewReader(log), RocketLeagueParser{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unexpected endpoints: %+v", got)
	}
}

func TestRegistry(t *testing.T) {
	parser, err := ForGame("RocketLeague")
	if err != nil || parser.GameID() != "rocketleague" {
		t.Fatalf("parser=%v err=%v", parser, err)
	}
	if _, err := ForGame("unknown"); err == nil {
		t.Fatal("unknown game unexpectedly had a parser")
	}
}

func TestGroupServersCombinesRolesOnSameIP(t *testing.T) {
	endpoints := []Endpoint{
		{Address: "3.26.125.197:7716", IP: "3.26.125.197", Port: 7716, Role: "game"},
		{Address: "3.26.125.197:7717", IP: "3.26.125.197", Port: 7717, Role: "ping"},
		{Address: "44.1.2.3:8000", IP: "44.1.2.3", Port: 8000, Role: "game"},
	}

	got := GroupServers(endpoints)
	if len(got) != 2 {
		t.Fatalf("got %d servers, want 2: %+v", len(got), got)
	}
	if got[0].IP != "3.26.125.197" || len(got[0].Endpoints) != 2 {
		t.Errorf("first server = %+v", got[0])
	}
	if got[0].Endpoints[0].Role != "game" || got[0].Endpoints[1].Role != "ping" {
		t.Errorf("grouped roles = %+v", got[0].Endpoints)
	}
	if got[1].IP != "44.1.2.3" || len(got[1].Endpoints) != 1 {
		t.Errorf("second server = %+v", got[1])
	}
}
