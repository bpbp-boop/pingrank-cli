package probe

import (
	"net/netip"
	"testing"
)

func TestGameProtocolAllowlist(t *testing.T) {
	for _, tc := range []struct {
		game, method string
		want         bool
	}{
		{"cs2", "a2s", true},
		{"dota2", "a2s", true},
		{"valorant", "a2s", false},
		{"cs2", "future-method", false},
		{"custom", "a2s", false},
	} {
		if got := GameProtocolAllowed(tc.game, tc.method); got != tc.want {
			t.Errorf("GameProtocolAllowed(%q, %q) = %v, want %v", tc.game, tc.method, got, tc.want)
		}
	}
}

func TestValidA2SResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		buf  []byte
		want bool
	}{
		{"info", []byte{0xff, 0xff, 0xff, 0xff, 0x49}, true},
		{"challenge", []byte{0xff, 0xff, 0xff, 0xff, 0x41}, true},
		{"unrelated type", []byte{0xff, 0xff, 0xff, 0xff, 0x00}, false},
		{"split packet", []byte{0xfe, 0xff, 0xff, 0xff, 0x49}, false},
		{"short", []byte{0xff, 0xff, 0xff, 0xff}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validA2SResponse(tc.buf); got != tc.want {
				t.Fatalf("validA2SResponse() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestProtocolRejectsUnsafeTargetsAndBursts(t *testing.T) {
	p := IcmpProber{}
	public := netip.MustParseAddrPort("1.1.1.1:27015")
	for _, count := range []int{0, maxProtocolProbeBurst + 1} {
		if _, err := p.Protocol("a2s", public, count); err == nil {
			t.Errorf("Protocol count %d unexpectedly allowed", count)
		}
	}
	if _, err := p.Protocol("a2s", netip.MustParseAddrPort("127.0.0.1:27015"), 1); err == nil {
		t.Error("Protocol unexpectedly allowed loopback target")
	}
	if _, err := p.Protocol("a2s", netip.MustParseAddrPort("192.168.1.10:27015"), 1); err == nil {
		t.Error("Protocol unexpectedly allowed private target")
	}
	if _, err := p.Protocol("a2s", netip.MustParseAddrPort("100.64.0.1:27015"), 1); err == nil {
		t.Error("Protocol unexpectedly allowed CGNAT target")
	}
}
