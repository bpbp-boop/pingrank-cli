// Package etw observes UDP flow metadata via the documented
// Microsoft-Windows-Kernel-Network ETW provider. This is how we learn the
// remote endpoint of UDP traffic: the socket table doesn't carry it, but
// the OS network stack emits a per-datagram event with PID, addresses,
// ports, and byte count.
//
// Anti-cheat safety: this is OS self-telemetry. The events carry header
// metadata only — no payload bytes — and we never touch the game process.
// No capture driver is involved; ETW is a built-in userland-consumable
// facility.
//
// Limitation: starting a real-time ETW session requires elevation (or
// Performance Log Users membership). Callers must treat ErrAccessDenied as
// "run unelevated" and degrade gracefully.
package etw

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrAccessDenied means the process lacks the rights to start an ETW
// session (not elevated, not in Performance Log Users).
var ErrAccessDenied = errors.New("starting an ETW trace session requires elevation")

// Flow is aggregated UDP traffic between one local socket and one remote
// endpoint, attributed to a PID.
type Flow struct {
	PID       uint32
	Local     netip.AddrPort
	Remote    netip.AddrPort
	SentPkts  uint64
	RecvPkts  uint64
	SentBytes uint64
	RecvBytes uint64
}

// Bidirectional reports whether traffic was seen in both directions —
// the strongest signal that this is a live game-server conversation
// rather than fire-and-forget telemetry.
func (f Flow) Bidirectional() bool { return f.SentPkts > 0 && f.RecvPkts > 0 }

// Microsoft-Windows-Kernel-Network provider GUID
// {7DD42A49-5329-4832-8DFD-43D979153A88}.
var kernelNetworkGUID = windows.GUID{
	Data1: 0x7DD42A49, Data2: 0x5329, Data3: 0x4832,
	Data4: [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88},
}

// Event IDs from the provider manifest (task KERNEL_NETWORK_TASK_UDPIP).
// The v6 variants carry the same fields with 16-byte addresses and reuse the
// v4 send/receive opcodes even though their event IDs differ.
const (
	eventUDPv4Send     = 42
	eventUDPv4Recv     = 43
	eventUDPv6Send     = 58
	eventUDPv6Recv     = 59
	eventUDPSendOpcode = 42
	eventUDPRecvOpcode = 43
	eventUDPTask       = 11
	eventVersion       = 0
)

const (
	sessionName        = "pingrank-kernel-network"
	serviceSessionName = "pingrank-kernel-network-service"
)

const (
	wnodeFlagTracedGUID       = 0x00020000
	eventTraceRealTimeMode    = 0x00000100
	eventTraceControlStop     = 1
	eventTraceControlQuery    = 0
	eventControlCodeDisable   = 0
	eventControlCodeEnable    = 1
	traceLevelInformational   = 4
	kernelNetworkKeywordIPv4  = 0x10
	kernelNetworkKeywordIPv6  = 0x20
	kernelNetworkKeywordUDP   = kernelNetworkKeywordIPv4 | kernelNetworkKeywordIPv6
	processTraceModeRealTime  = 0x00000100
	processTraceModeRawTime   = 0x00001000
	processTraceModeEventRec  = 0x10000000
	invalidProcessTraceHandle = ^uintptr(0)
	enableTraceParametersV2   = 2
	eventFilterTypeEventID    = 0x80000200
)

var (
	modadvapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW    = modadvapi32.NewProc("StartTraceW")
	procControlTraceW  = modadvapi32.NewProc("ControlTraceW")
	procEnableTraceEx2 = modadvapi32.NewProc("EnableTraceEx2")
	procOpenTraceW     = modadvapi32.NewProc("OpenTraceW")
	procProcessTrace   = modadvapi32.NewProc("ProcessTrace")
	procCloseTrace     = modadvapi32.NewProc("CloseTrace")
	modkernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerfCount = modkernel32.NewProc("QueryPerformanceCounter")
)

// The struct layouts below mirror the evntrace.h / evntcons.h C structs for
// windows/amd64 exactly; field order and implicit padding both match.

type wnodeHeader struct {
	BufferSize        uint32
	ProviderID        uint32
	HistoricalContext uint64
	KernelHandle      uintptr // union with TimeStamp
	Guid              windows.GUID
	ClientContext     uint32
	Flags             uint32
}

type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadID      uintptr
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

type eventDescriptor struct {
	ID      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadID        uint32
	ProcessID       uint32
	TimeStamp       int64
	ProviderID      windows.GUID
	EventDescriptor eventDescriptor
	ProcessorTime   uint64
	ActivityID      windows.GUID
}

type etwBufferContext struct {
	ProcessorNumber uint8
	Alignment       uint8
	LoggerID        uint16
}

type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      uintptr
	UserData          unsafe.Pointer
	UserContext       uintptr
}

type eventTraceHeader struct {
	Size           uint16
	FieldTypeFlags uint16
	Version        uint32
	ThreadID       uint32
	ProcessID      uint32
	TimeStamp      int64
	GUID           windows.GUID
	ProcessorTime  uint64
}

type eventTrace struct {
	Header           eventTraceHeader
	InstanceID       uint32
	ParentInstanceID uint32
	ParentGUID       windows.GUID
	MofData          uintptr
	MofLength        uint32
	ClientContext    uint32
}

type traceLogfileHeader struct {
	BufferSize         uint32
	Version            uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	LogInstanceGUID    windows.GUID
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           windows.Timezoneinformation
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}

type eventTraceLogfile struct {
	LogFileName         *uint16
	LoggerName          *uint16
	CurrentTime         int64
	BuffersRead         uint32
	ProcessTraceMode    uint32
	CurrentEvent        eventTrace
	LogfileHeader       traceLogfileHeader
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr
	IsKernelTrace       uint32
	Context             uintptr
}

// udpEventV4 is the fixed-layout payload of UDP v4 send/recv events
// version 0 (manifest template: PID, size, daddr, saddr, dport, sport,
// seqnum, connid).
// Addresses are raw IPv4 bytes; ports are network byte order.
const udpEventV4Len = 28

// udpEventV6Min is the smallest v6 payload we can parse: the same template with
// 16-byte addresses, up to and including the ports (PID4+size4+daddr16+saddr16+
// dport2+sport2). The full event also carries seqnum+connid (52 bytes total),
// but those trail the fields we read, so we accept any event at least this long
// rather than pinning an exact length — a manifest revision to the trailing
// fields then still parses. (v4 keeps its exact-length schema guard.)
const udpEventV6Min = 44

type eventFilterDescriptor struct {
	Ptr  uint64
	Size uint32
	Type uint32
}

type eventIDFilter struct {
	FilterIn uint8
	Reserved uint8
	Count    uint16
	Events   [4]uint16
}

type enableTraceParameters struct {
	Version          uint32
	EnableProperty   uint32
	ControlFlags     uint32
	SourceID         windows.GUID
	EnableFilterDesc uintptr
	FilterDescCount  uint32
}

// Health is a cumulative snapshot of trace delivery and parser health.
// Callers compare snapshots to detect loss during a specific poll window.
type Health struct {
	EventsLost   uint64
	BuffersLost  uint64
	SchemaErrors uint64
}

// IsElevated reports whether the current process token is elevated —
// the cheap pre-check before attempting a session.
func IsElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Session is a live real-time trace of UDP v4 flows, aggregated by
// (PID, local, remote). It observes all processes; callers filter by PID.
type Session struct {
	traceHandle    uintptr // controller handle from StartTraceW
	consumerHandle uintptr // consumer handle from OpenTraceW
	namePtr        *uint16
	sessionGUID    windows.GUID

	mu      sync.Mutex
	flows   map[flowKey]*Flow
	targets map[uint32]struct{}

	done chan struct{}
	// keep the callback and logfile struct referenced (and not moved by
	// the GC) for the session's lifetime
	callback uintptr
	logfile  *eventTraceLogfile

	controlMu sync.Mutex
	enabled   bool
	closed    bool

	collecting    atomic.Bool
	minimumQPC    atomic.Int64
	schemaErrors  atomic.Uint64
	processStatus atomic.Uint32
}

type flowKey struct {
	pid    uint32
	local  netip.AddrPort
	remote netip.AddrPort
}

func newProperties() (*eventTraceProperties, []byte) {
	propsSize := unsafe.Sizeof(eventTraceProperties{})
	buf := make([]byte, propsSize+2*2048)
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.Wnode.ClientContext = 1 // QPC timestamps
	props.LoggerNameOffset = uint32(propsSize)
	props.LogFileNameOffset = 0 // real-time session, no file
	return props, buf
}

// stopExisting stops a stale session left behind by a previous run
// (session names are system-global). Missing session is not an error.
func stopExisting(namePtr *uint16) {
	props, _ := newProperties()
	procControlTraceW.Call(
		0,
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
		eventTraceControlStop,
	)
}

// startSession starts an empty real-time trace and its consumer. Providers are
// enabled separately so a long-running service can create the trace before an
// anti-cheat starts, then collect events only while a game is being recorded.
func startSession(name string) (*Session, error) {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	stopExisting(namePtr)

	props, _ := newProperties()
	props.LogFileMode = eventTraceRealTimeMode
	props.BufferSize = 64 // KB per buffer

	var traceHandle uintptr
	ret, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&traceHandle)),
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(props)),
	)
	if errno := windows.Errno(ret); errno != windows.ERROR_SUCCESS {
		if errno == windows.ERROR_ACCESS_DENIED {
			return nil, ErrAccessDenied
		}
		return nil, fmt.Errorf("StartTraceW: %w", errno)
	}

	s := &Session{
		traceHandle: traceHandle,
		namePtr:     namePtr,
		sessionGUID: props.Wnode.Guid,
		flows:       make(map[flowKey]*Flow),
		targets:     make(map[uint32]struct{}),
		done:        make(chan struct{}),
	}
	s.callback = windows.NewCallback(s.onEvent)

	s.logfile = new(eventTraceLogfile)
	s.logfile.LoggerName = namePtr
	// RAW_TIMESTAMP keeps EventHeader.TimeStamp in the QPC clock domain used
	// for the provider-transition lower bound below.
	s.logfile.ProcessTraceMode = processTraceModeRealTime | processTraceModeRawTime | processTraceModeEventRec
	s.logfile.EventRecordCallback = s.callback

	consumer, _, callErr := procOpenTraceW.Call(uintptr(unsafe.Pointer(s.logfile)))
	if consumer == invalidProcessTraceHandle {
		stopExisting(namePtr)
		return nil, fmt.Errorf("OpenTraceW: %w", callErr)
	}
	s.consumerHandle = consumer

	go func() {
		defer close(s.done)
		// Blocks until the session is stopped and buffers drain.
		status, _, _ := procProcessTrace.Call(
			uintptr(unsafe.Pointer(&s.consumerHandle)),
			1,
			0,
			0,
		)
		s.processStatus.Store(uint32(status))
	}()

	return s, nil
}

// StartPersistentSession creates the service-owned trace without enabling any
// providers. It should be called at service startup, before a game or its
// anti-cheat starts. Enable and Disable delimit each recording, while Close is
// reserved for service shutdown.
func StartPersistentSession() (*Session, error) {
	return startSession(serviceSessionName)
}

// StartDormantSession creates the short-lived CLI trace without enabling its
// provider yet. Record mode uses this before waiting for a game so an
// anti-cheat cannot block session creation between detection and capture.
func StartDormantSession() (*Session, error) {
	return startSession(sessionName)
}

// StartSession starts a self-contained trace for short-lived CLI commands.
// The installed service uses StartPersistentSession instead.
func StartSession(targetPIDs []uint32) (*Session, error) {
	s, err := StartDormantSession()
	if err != nil {
		return nil, err
	}
	if err := s.Enable(targetPIDs); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Enable begins collecting events from the kernel-network provider. Repeated
// calls are harmless. Any events retained from the previous recording are
// discarded before the provider is enabled.
func (s *Session) Enable(targetPIDs []uint32) error {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	if s.closed {
		return fmt.Errorf("ETW session is closed")
	}
	select {
	case <-s.done:
		return fmt.Errorf("ETW consumer stopped (status %d)", s.processStatus.Load())
	default:
	}
	if s.enabled {
		s.setTargetPIDs(targetPIDs)
		return nil
	}
	if len(targetPIDs) == 0 {
		return fmt.Errorf("ETW target PID set is empty")
	}

	s.collecting.Store(false)
	s.mu.Lock()
	s.flows = make(map[flowKey]*Flow)
	s.replaceTargets(targetPIDs)
	s.mu.Unlock()

	var qpc int64
	ret, _, callErr := procQueryPerfCount.Call(uintptr(unsafe.Pointer(&qpc)))
	if ret == 0 {
		return fmt.Errorf("QueryPerformanceCounter: %w", callErr)
	}
	s.minimumQPC.Store(qpc)
	s.collecting.Store(true)

	if err := s.enableProviderFiltered(); err != nil {
		s.collecting.Store(false)
		return err
	}
	s.enabled = true
	return nil
}

func (s *Session) enableProviderFiltered() error {
	filter := eventIDFilter{FilterIn: 1, Count: 4, Events: [4]uint16{eventUDPv4Send, eventUDPv4Recv, eventUDPv6Send, eventUDPv6Recv}}
	descriptor := eventFilterDescriptor{
		Ptr:  uint64(uintptr(unsafe.Pointer(&filter))),
		Size: uint32(unsafe.Sizeof(filter)),
		Type: eventFilterTypeEventID,
	}
	params := enableTraceParameters{
		Version:          enableTraceParametersV2,
		SourceID:         s.sessionGUID,
		EnableFilterDesc: uintptr(unsafe.Pointer(&descriptor)),
		FilterDescCount:  1,
	}
	ret, _, _ := procEnableTraceEx2.Call(
		s.traceHandle,
		uintptr(unsafe.Pointer(&kernelNetworkGUID)),
		eventControlCodeEnable,
		traceLevelInformational,
		kernelNetworkKeywordUDP,
		0, // MatchAllKeyword
		0, // Timeout: async
		uintptr(unsafe.Pointer(&params)),
	)
	runtime.KeepAlive(filter)
	runtime.KeepAlive(descriptor)
	runtime.KeepAlive(params)
	if errno := windows.Errno(ret); errno != windows.ERROR_SUCCESS {
		// Depending on rights, the denial can surface here rather than at
		// StartTraceW (e.g. session creation allowed but enabling the
		// kernel provider is not).
		if errno == windows.ERROR_ACCESS_DENIED {
			return ErrAccessDenied
		}
		return fmt.Errorf("EnableTraceEx2(kernel-network): %w", errno)
	}
	return nil
}

// Disable stops collecting provider events but leaves the trace session and
// consumer alive for the next game. Repeated calls are harmless.
func (s *Session) Disable() error {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	if s.closed || !s.enabled {
		return nil
	}
	s.collecting.Store(false)
	if err := s.setProvider(eventControlCodeDisable); err != nil {
		s.collecting.Store(true)
		return err
	}
	s.enabled = false
	return nil
}

func (s *Session) setProvider(controlCode uint32) error {
	ret, _, _ := procEnableTraceEx2.Call(
		s.traceHandle,
		uintptr(unsafe.Pointer(&kernelNetworkGUID)),
		uintptr(controlCode),
		traceLevelInformational,
		kernelNetworkKeywordUDP,
		0,
		0,
		0,
	)
	if errno := windows.Errno(ret); errno != windows.ERROR_SUCCESS {
		if errno == windows.ERROR_ACCESS_DENIED {
			return ErrAccessDenied
		}
		return fmt.Errorf("EnableTraceEx2(kernel-network): %w", errno)
	}
	return nil
}

// SetTargetPIDs replaces the consumer-side PID allowlist. Kernel-network is a
// kernel provider, so ETW's user-mode PID scope filter cannot narrow it for us.
func (s *Session) SetTargetPIDs(targetPIDs []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replaceTargets(targetPIDs)
	for key := range s.flows {
		if _, ok := s.targets[key.pid]; !ok {
			delete(s.flows, key)
		}
	}
}

func (s *Session) setTargetPIDs(targetPIDs []uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.replaceTargets(targetPIDs)
}

// replaceTargets requires s.mu to be held.
func (s *Session) replaceTargets(targetPIDs []uint32) {
	targets := make(map[uint32]struct{}, len(targetPIDs))
	for _, pid := range targetPIDs {
		if pid != 0 {
			targets[pid] = struct{}{}
		}
	}
	s.targets = targets
}

// Health queries ETW's cumulative loss counters and combines them with parser
// validation failures observed by the callback.
func (s *Session) Health() (Health, error) {
	s.controlMu.Lock()
	defer s.controlMu.Unlock()
	if s.closed {
		return Health{}, fmt.Errorf("ETW session is closed")
	}
	select {
	case <-s.done:
		return Health{}, fmt.Errorf("ETW consumer stopped (status %d)", s.processStatus.Load())
	default:
	}
	props, _ := newProperties()
	ret, _, _ := procControlTraceW.Call(
		s.traceHandle,
		0,
		uintptr(unsafe.Pointer(props)),
		eventTraceControlQuery,
	)
	if errno := windows.Errno(ret); errno != windows.ERROR_SUCCESS {
		return Health{}, fmt.Errorf("ControlTraceW(query): %w", errno)
	}
	return Health{
		EventsLost:   uint64(props.EventsLost),
		BuffersLost:  uint64(props.LogBuffersLost) + uint64(props.RealTimeBuffersLost),
		SchemaErrors: s.schemaErrors.Load(),
	}, nil
}

// onEvent is invoked by ETW for every event in the session. It must be
// fast: parse the fixed-layout UDP v4 payload and bump counters.
func (s *Session) onEvent(rec *eventRecord) uintptr {
	if !s.collecting.Load() || rec.EventHeader.ProviderID != kernelNetworkGUID {
		return 0
	}
	id := rec.EventHeader.EventDescriptor.ID
	send := id == eventUDPv4Send || id == eventUDPv6Send
	v4 := id == eventUDPv4Send || id == eventUDPv4Recv
	v6 := id == eventUDPv6Send || id == eventUDPv6Recv
	if !v4 && !v6 {
		return 0
	}
	wantOpcode := uint8(eventUDPRecvOpcode)
	if send {
		wantOpcode = eventUDPSendOpcode
	}
	desc := rec.EventHeader.EventDescriptor
	badLen := (v4 && rec.UserDataLength != udpEventV4Len) || (v6 && rec.UserDataLength < udpEventV6Min)
	if desc.Version != eventVersion || desc.Task != eventUDPTask || desc.Opcode != wantOpcode ||
		badLen || rec.UserData == nil {
		s.schemaErrors.Add(1)
		return 0
	}
	if rec.EventHeader.TimeStamp < s.minimumQPC.Load() {
		return 0
	}
	data := unsafe.Slice((*byte)(rec.UserData), rec.UserDataLength)

	pid := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	s.mu.Lock()
	if _, ok := s.targets[pid]; !ok {
		s.mu.Unlock()
		return 0
	}
	// Both templates start PID, size, daddr, saddr, dport, sport; only the
	// address width differs (4 bytes for v4, 16 for v6).
	size := uint32(data[4]) | uint32(data[5])<<8 | uint32(data[6])<<16 | uint32(data[7])<<24
	var daddr, saddr netip.Addr
	var dport, sport uint16
	if v4 {
		daddr = netip.AddrFrom4([4]byte{data[8], data[9], data[10], data[11]})
		saddr = netip.AddrFrom4([4]byte{data[12], data[13], data[14], data[15]})
		dport = uint16(data[16])<<8 | uint16(data[17])
		sport = uint16(data[18])<<8 | uint16(data[19])
	} else {
		daddr = netip.AddrFrom16(*(*[16]byte)(data[8:24]))
		saddr = netip.AddrFrom16(*(*[16]byte)(data[24:40]))
		dport = uint16(data[40])<<8 | uint16(data[41])
		sport = uint16(data[42])<<8 | uint16(data[43])
	}

	var key flowKey
	key.pid = pid
	if send {
		key.local = netip.AddrPortFrom(saddr, sport)
		key.remote = netip.AddrPortFrom(daddr, dport)
	} else {
		key.local = netip.AddrPortFrom(daddr, dport)
		key.remote = netip.AddrPortFrom(saddr, sport)
	}

	f := s.flows[key]
	if f == nil {
		f = &Flow{PID: pid, Local: key.local, Remote: key.remote}
		s.flows[key] = f
	}
	if send {
		f.SentPkts++
		f.SentBytes += uint64(size)
	} else {
		f.RecvPkts++
		f.RecvBytes += uint64(size)
	}
	s.mu.Unlock()
	return 0
}

// TakeFlows returns the flows aggregated since the last call and resets
// the accumulator, so each poll interval sees only its own traffic.
func (s *Session) TakeFlows() []Flow {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Flow, 0, len(s.flows))
	for _, f := range s.flows {
		out = append(out, *f)
	}
	s.flows = make(map[flowKey]*Flow)
	return out
}

// Close stops the session and waits for the consumer goroutine to drain.
func (s *Session) Close() error {
	s.controlMu.Lock()
	if s.closed {
		s.controlMu.Unlock()
		return nil
	}
	if s.enabled {
		s.collecting.Store(false)
		_ = s.setProvider(eventControlCodeDisable)
		s.enabled = false
	}
	s.closed = true
	s.controlMu.Unlock()

	props, _ := newProperties()
	procControlTraceW.Call(
		s.traceHandle,
		uintptr(unsafe.Pointer(s.namePtr)),
		uintptr(unsafe.Pointer(props)),
		eventTraceControlStop,
	)
	procCloseTrace.Call(s.consumerHandle)
	<-s.done
	return nil
}
