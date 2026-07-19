package cgnat

import (
	"net/netip"
	"testing"
)

func hop(number int, addr string) Hop {
	return Hop{Number: number, Addr: netip.MustParseAddr(addr)}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name       string
		hops       []Hop
		localClass string
		status     string
		rangeName  string
	}{
		{"confirmed shared space", []Hop{hop(1, "192.168.1.1"), hop(2, "100.72.0.1")}, LocalPrivate, StatusConfirmed, "100.64.0.0/10"},
		{"likely private beyond gateway", []Hop{hop(1, "192.168.1.1"), hop(2, "10.20.0.1")}, LocalPrivate, StatusLikely, "10.0.0.0/8"},
		{"own gateway alone is not likely", []Hop{hop(1, "192.168.1.1"), hop(2, "1.2.3.4")}, LocalPrivate, StatusNone, ""},
		{"public local overrides trace", []Hop{hop(2, "100.72.0.1")}, LocalPublic, StatusNone, ""},
		{"confirmed outranks earlier likely", []Hop{hop(2, "10.0.0.1"), hop(3, "100.64.1.1")}, LocalPrivate, StatusConfirmed, "100.64.0.0/10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.hops, tt.localClass)
			if got.Status != tt.status {
				t.Fatalf("status = %q, want %q", got.Status, tt.status)
			}
			if tt.rangeName == "" && got.Evidence != nil {
				t.Fatalf("unexpected evidence: %+v", got.Evidence)
			}
			if tt.rangeName != "" && (got.Evidence == nil || got.Evidence.Range != tt.rangeName) {
				t.Fatalf("evidence = %+v, want range %s", got.Evidence, tt.rangeName)
			}
		})
	}
}
