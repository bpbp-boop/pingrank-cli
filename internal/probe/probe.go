// Package probe measures latency to candidate endpoints.
//
// It uses IcmpSendEcho from iphlpapi.dll rather than raw ICMP sockets:
// raw sockets require administrator rights on Windows, while IcmpSendEcho
// is a documented userland API that works unelevated and returns the same
// min/avg/max/loss numbers. It also supports a TTL option, which gives us
// an unelevated traceroute: when a target drops ICMP echo entirely, we
// walk the path with increasing TTLs, find the last hop that answers, and
// ping that instead (method "last-hop") — a close lower bound on the real
// server latency. (plan.md sketched a UDP traceroute; receiving its
// TTL-exceeded replies would itself need a raw socket, so the ICMP-TTL
// variant is what fits the no-elevation constraint.)
package probe

import (
	"fmt"
	"net/netip"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"pingrank.gg/internal/cgnat"
)

// Stats summarizes one batch of echo probes.
type Stats struct {
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	MinMs    uint32  `json:"minMs"`
	AvgMs    float64 `json:"avgMs"`
	MaxMs    uint32  `json:"maxMs"`
	LossPct  float64 `json:"lossPct"`
}

// Result is the measurement for one candidate endpoint.
type Result struct {
	Target netip.Addr `json:"target"`
	// Method is "direct" (target answered echo) or "last-hop" (target was
	// silent; stats are for the nearest responding router).
	Method string `json:"method"`
	// Probed is the address actually measured: Target for "direct", the
	// last responding hop for "last-hop".
	Probed netip.Addr `json:"probed"`
	Stats  Stats      `json:"stats"`
	Note   string     `json:"note,omitempty"`
}

// Prober measures latency to an address. Interface so higher layers can be
// tested with canned results.
type Prober interface {
	Probe(target netip.Addr) (Result, error)
}

const (
	pingCount   = 5
	pingTimeout = time.Second

	maxHops         = 30
	probesPerHop    = 3
	silentHopsLimit = 5 // stop the walk after this many consecutive silent hops
)

// ICMP status codes from ipexport.h.
const (
	ipSuccess           = 0
	ipReqTimedOut       = 11010
	ipTTLExpiredTransit = 11013 // IPv4: TTL expired in transit
	ipHopLimitExceeded  = 11015 // IPv6: hop limit exceeded (the v6 analogue)
)

var (
	modiphlpapi         = windows.NewLazySystemDLL("iphlpapi.dll")
	procIcmpCreateFile  = modiphlpapi.NewProc("IcmpCreateFile")
	procIcmp6CreateFile = modiphlpapi.NewProc("Icmp6CreateFile")
	procIcmpCloseHandle = modiphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = modiphlpapi.NewProc("IcmpSendEcho")
	procIcmp6SendEcho2  = modiphlpapi.NewProc("Icmp6SendEcho2")
)

// ipOptionInformation mirrors IP_OPTION_INFORMATION (amd64).
type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

// icmpEchoReply mirrors ICMP_ECHO_REPLY (amd64).
type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

// sockaddrIn6 mirrors Windows SOCKADDR_IN6 (ws2ipdef.h, amd64): naturally
// aligned to 28 bytes. Icmp6SendEcho2 requires both a source (unspecified ::)
// and destination in this form.
type sockaddrIn6 struct {
	Family   uint16
	Port     uint16
	Flowinfo uint32
	Addr     [16]byte
	ScopeID  uint32
}

// icmpv6EchoReply mirrors ICMPV6_ECHO_REPLY (ipexport.h). Its first field,
// IPV6_ADDRESS_EX, is #pragma pack(1) (26 bytes: port, flowinfo, addr[16],
// scope), so it is kept as raw bytes here — a Go struct would pad it wrong. The
// reply struct itself is naturally aligned, so two pad bytes precede Status,
// giving 36 bytes total. If a Windows run returns garbage RTT/status, this
// packing is the first thing to check (see the size assertion in the test).
type icmpv6EchoReply struct {
	Address       [26]byte
	_             [2]byte
	Status        uint32
	RoundTripTime uint32
}

// addr extracts the sin6_addr (offset 6..21 within the packed IPV6_ADDRESS_EX).
func (r icmpv6EchoReply) addr() netip.Addr {
	var b [16]byte
	copy(b[:], r.Address[6:22])
	return netip.AddrFrom16(b)
}

// IcmpProber is the live implementation over iphlpapi.
type IcmpProber struct{}

var payload = []byte("pingrank-latency-probe")

// echoReply is one parsed echo reply, independent of address family. addr is
// the responder (the target on success, an intermediate router on a
// TTL/hop-limit-exceeded reply); rtt is the round trip in ms (valid only when
// status is ipSuccess).
type echoReply struct {
	addr   netip.Addr
	status uint32
	rtt    uint32
}

// echoFn sends one echo toward a fixed destination with the given TTL (IPv4)
// or hop limit (IPv6). ok=false means the probe timed out or errored with no
// usable reply. It closes over the ICMP handle, destination, and timeout so the
// family-agnostic walk below need not know which protocol it is driving.
type echoFn func(ttl uint8) (echoReply, bool)

// echo4 sends one ICMPv4 echo via IcmpSendEcho.
func echo4(handle uintptr, dst netip.Addr, ttl uint8, timeout time.Duration) (echoReply, bool) {
	b := dst.As4()
	dstAddr := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24

	opts := ipOptionInformation{TTL: ttl}
	replyBuf := make([]byte, unsafe.Sizeof(icmpEchoReply{})+uintptr(len(payload))+8)

	n, _, _ := procIcmpSendEcho.Call(
		handle,
		uintptr(dstAddr),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(timeout.Milliseconds()),
	)
	rep := *(*icmpEchoReply)(unsafe.Pointer(&replyBuf[0]))
	r := echoReply{
		addr: netip.AddrFrom4([4]byte{byte(rep.Address), byte(rep.Address >> 8),
			byte(rep.Address >> 16), byte(rep.Address >> 24)}),
		status: rep.Status, rtt: rep.RoundTripTime,
	}
	if n == 0 {
		// No reply entries. For TTL-expired probes IcmpSendEcho still
		// returns 0 with the reply struct filled in, so inspect Status.
		if rep.Status == ipTTLExpiredTransit && rep.Address != 0 {
			return r, true
		}
		return r, false
	}
	if rep.Status != ipSuccess && rep.Status != ipTTLExpiredTransit {
		return r, false
	}
	return r, true
}

// echo6 sends one ICMPv6 echo via Icmp6SendEcho2. The v6 API requires a source
// address (the unspecified :: is fine) and reports the responding hop inside a
// packed IPV6_ADDRESS_EX; otherwise it mirrors echo4, with hop-limit-exceeded
// standing in for TTL-expired.
func echo6(handle uintptr, dst netip.Addr, hopLimit uint8, timeout time.Duration) (echoReply, bool) {
	src := sockaddrIn6{Family: windows.AF_INET6}
	d := sockaddrIn6{Family: windows.AF_INET6, Addr: dst.As16()}
	opts := ipOptionInformation{TTL: hopLimit}
	replyBuf := make([]byte, unsafe.Sizeof(icmpv6EchoReply{})+uintptr(len(payload))+8)

	n, _, _ := procIcmp6SendEcho2.Call(
		handle,
		0, // Event
		0, // ApcRoutine
		0, // ApcContext
		uintptr(unsafe.Pointer(&src)),
		uintptr(unsafe.Pointer(&d)),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(len(payload)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&replyBuf[0])),
		uintptr(len(replyBuf)),
		uintptr(timeout.Milliseconds()),
	)
	rep := *(*icmpv6EchoReply)(unsafe.Pointer(&replyBuf[0]))
	r := echoReply{addr: rep.addr(), status: rep.Status, rtt: rep.RoundTripTime}
	if n == 0 {
		if rep.Status == ipHopLimitExceeded && r.addr.IsValid() && !r.addr.IsUnspecified() {
			return r, true
		}
		return r, false
	}
	if rep.Status != ipSuccess && rep.Status != ipHopLimitExceeded {
		return r, false
	}
	return r, true
}

// icmpHandle opens the ICMP (v4) or ICMPv6 (v6) handle for target and returns a
// closer. Icmp6CreateFile handles are freed with the same IcmpCloseHandle.
func icmpHandle(target netip.Addr) (handle uintptr, closeFn func(), err error) {
	proc, name := procIcmpCreateFile, "IcmpCreateFile"
	if target.Is6() {
		proc, name = procIcmp6CreateFile, "Icmp6CreateFile"
	}
	h, _, callErr := proc.Call()
	if h == uintptr(windows.InvalidHandle) {
		return 0, nil, fmt.Errorf("%s: %w", name, callErr)
	}
	return h, func() { procIcmpCloseHandle.Call(h) }, nil
}

// sender binds an ICMP handle and destination into an echoFn of the right
// family.
func sender(handle uintptr, dst netip.Addr) echoFn {
	if dst.Is6() {
		return func(ttl uint8) (echoReply, bool) { return echo6(handle, dst, ttl, pingTimeout) }
	}
	return func(ttl uint8) (echoReply, bool) { return echo4(handle, dst, ttl, pingTimeout) }
}

// ping sends count echoes (full TTL) and aggregates stats.
func ping(send echoFn, count int) Stats {
	s := Stats{Sent: count}
	var sum uint64
	for range count {
		rep, ok := send(128)
		if !ok || rep.status != ipSuccess {
			continue
		}
		rtt := rep.rtt
		if s.Received == 0 {
			s.MinMs, s.MaxMs = rtt, rtt
		} else {
			s.MinMs = min(s.MinMs, rtt)
			s.MaxMs = max(s.MaxMs, rtt)
		}
		s.Received++
		sum += uint64(rtt)
	}
	if s.Received > 0 {
		s.AvgMs = float64(sum) / float64(s.Received)
	}
	s.LossPct = float64(s.Sent-s.Received) / float64(s.Sent) * 100
	return s
}

// lastHop walks toward dst with increasing TTLs (or hop limits) and returns the
// last hop that answered with TTL/hop-limit-exceeded. Stops early once the path
// goes silent for silentHopsLimit consecutive TTLs (past the last cooperative
// router everything is usually silent, and 30 full hops at 3×1s each is slow).
func lastHop(send echoFn, dst netip.Addr) (netip.Addr, bool) {
	var last netip.Addr
	found := false
	silent := 0
	for ttl := 1; ttl <= maxHops; ttl++ {
		answered := false
		for range probesPerHop {
			rep, ok := send(uint8(ttl))
			if !ok {
				continue
			}
			if rep.status == ipSuccess {
				// Destination answered after all (e.g. rate-limited
				// earlier); treat it as the final hop.
				return dst, true
			}
			hop := rep.addr
			if hop.IsValid() && !hop.IsUnspecified() {
				last, found, answered = hop, true, true
				break
			}
		}
		if found && last == dst {
			break
		}
		if answered {
			silent = 0
		} else {
			silent++
			if silent >= silentHopsLimit {
				break
			}
		}
	}
	return last, found
}

func (p IcmpProber) Probe(target netip.Addr) (Result, error) {
	return p.Resolve(target, pingCount)
}

// Ping measures a known-good address directly with a burst of count
// echoes — no traceroute fallback. Continuous sampling (internal/session)
// uses this once Resolve has established what to ping. Works for IPv4 and IPv6.
func (IcmpProber) Ping(addr netip.Addr, count int) (Stats, error) {
	h, closeFn, err := icmpHandle(addr)
	if err != nil {
		return Stats{}, err
	}
	defer closeFn()
	return ping(sender(h, addr), count), nil
}

// Resolve probes target with a burst of count echoes, falling back to the
// last-hop walk when the target is ICMP-silent. Works for IPv4 and IPv6.
func (IcmpProber) Resolve(target netip.Addr, count int) (Result, error) {
	h, closeFn, err := icmpHandle(target)
	if err != nil {
		return Result{}, err
	}
	defer closeFn()

	res := Result{Target: target}
	direct := ping(sender(h, target), count)
	if direct.Received > 0 {
		res.Method = "direct"
		res.Probed = target
		res.Stats = direct
		return res, nil
	}

	// Target drops ICMP echo — measure the last responding hop instead.
	hop, ok := lastHop(sender(h, target), target)
	if !ok {
		res.Method = "direct"
		res.Probed = target
		res.Stats = direct
		res.Note = "no ICMP response from target and no responding intermediate hop; latency unknown"
		return res, nil
	}
	res.Method = "last-hop"
	res.Probed = hop
	res.Stats = ping(sender(h, hop), count)
	res.Note = fmt.Sprintf("target does not answer ICMP echo; measured last responding hop %s (lower bound)", hop)
	return res, nil
}

// Trace returns responding hops from a short TTL walk. M6 uses this only for
// CGNAT classification (an IPv4-only concept: RFC 6598) and stores no hop
// addresses.
func (IcmpProber) Trace(target netip.Addr, maxTraceHops int) ([]cgnat.Hop, error) {
	if !target.Is4() {
		return nil, fmt.Errorf("probe: CGNAT trace is IPv4-only, got %s", target)
	}
	h, closeFn, err := icmpHandle(target)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	var hops []cgnat.Hop
	for ttl := 1; ttl <= maxTraceHops; ttl++ {
		rep, ok := echo4(h, target, uint8(ttl), pingTimeout)
		if !ok {
			continue
		}
		addr := rep.addr
		if rep.status == ipSuccess {
			addr = target
		}
		if addr.IsValid() && !addr.IsUnspecified() {
			hops = append(hops, cgnat.Hop{Number: ttl, Addr: addr})
		}
		if rep.status == ipSuccess {
			break
		}
	}
	return hops, nil
}
