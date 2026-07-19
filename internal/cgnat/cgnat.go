// Package cgnat classifies whether a session appears to traverse carrier-
// grade NAT. It records only an address class and range evidence, never a
// local or intermediate-hop address.
package cgnat

import (
	"net"
	"net/netip"
)

const (
	StatusNone      = "none"
	StatusLikely    = "likely"
	StatusConfirmed = "confirmed"

	LocalPrivate = "private"
	LocalPublic  = "public"
	LocalUnknown = "unknown"

	maxTraceHops = 5
)

var probeTarget = netip.MustParseAddr("1.1.1.1")

type Hop struct {
	Number int
	Addr   netip.Addr
}

type Tracer interface {
	Trace(target netip.Addr, maxHops int) ([]Hop, error)
}

type SystemDetector struct {
	Tracer Tracer
}

func (d SystemDetector) Detect() Result { return Detect(d.Tracer) }

type Evidence struct {
	Hop   int    `json:"hop"`
	Range string `json:"range"`
}

type Result struct {
	Status            string    `json:"status"`
	Evidence          *Evidence `json:"evidence,omitempty"`
	LocalAddressClass string    `json:"localAddressClass"`
}

// Detect selects the outbound interface without sending application data,
// then walks only the first few ICMP hops. A public local address is
// definitive evidence that NAT44/CGNAT is not in use and skips the trace.
func Detect(tracer Tracer) Result {
	localClass := outboundAddressClass(probeTarget)
	if localClass == LocalPublic {
		return Result{Status: StatusNone, LocalAddressClass: localClass}
	}
	hops, err := tracer.Trace(probeTarget, maxTraceHops)
	if err != nil {
		return Result{Status: StatusNone, LocalAddressClass: localClass}
	}
	return Classify(hops, localClass)
}

// Classify implements the milestone rules. RFC 6598 wins over RFC1918,
// regardless of observation order. RFC1918 counts only beyond hop one,
// which is normally the user's own gateway.
func Classify(hops []Hop, localClass string) Result {
	if localClass == LocalPublic {
		return Result{Status: StatusNone, LocalAddressClass: localClass}
	}
	result := Result{Status: StatusNone, LocalAddressClass: localClass}
	if result.LocalAddressClass == "" {
		result.LocalAddressClass = LocalUnknown
	}
	var likely *Evidence
	for _, hop := range hops {
		addr := hop.Addr.Unmap()
		if inSharedSpace(addr) {
			result.Status = StatusConfirmed
			result.Evidence = &Evidence{Hop: hop.Number, Range: "100.64.0.0/10"}
			return result
		}
		if hop.Number > 1 {
			if r := privateRange(addr); r != "" && likely == nil {
				likely = &Evidence{Hop: hop.Number, Range: r}
			}
		}
	}
	if likely != nil {
		result.Status = StatusLikely
		result.Evidence = likely
	}
	return result
}

func outboundAddressClass(target netip.Addr) string {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IP(target.AsSlice()), Port: 53})
	if err != nil {
		return LocalUnknown
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return LocalUnknown
	}
	addr, ok := netip.AddrFromSlice(local.IP)
	if !ok {
		return LocalUnknown
	}
	addr = addr.Unmap()
	if addr.IsPrivate() || inSharedSpace(addr) {
		return LocalPrivate
	}
	if addr.IsGlobalUnicast() {
		return LocalPublic
	}
	return LocalUnknown
}

func inSharedSpace(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[0] == 100 && b[1] >= 64 && b[1] <= 127
}

func privateRange(addr netip.Addr) string {
	if !addr.Is4() {
		return ""
	}
	b := addr.As4()
	switch {
	case b[0] == 10:
		return "10.0.0.0/8"
	case b[0] == 172 && b[1] >= 16 && b[1] <= 31:
		return "172.16.0.0/12"
	case b[0] == 192 && b[1] == 168:
		return "192.168.0.0/16"
	default:
		return ""
	}
}
