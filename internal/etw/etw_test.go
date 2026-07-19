package etw

import (
	"encoding/binary"
	"net/netip"
	"runtime"
	"testing"
	"unsafe"
)

func TestFilterStructLayoutsAMD64(t *testing.T) {
	if unsafe.Sizeof(eventFilterDescriptor{}) != 16 {
		t.Fatalf("EVENT_FILTER_DESCRIPTOR size = %d, want 16", unsafe.Sizeof(eventFilterDescriptor{}))
	}
	if unsafe.Sizeof(eventIDFilter{}) != 12 {
		t.Fatalf("four-ID EVENT_FILTER_EVENT_ID size = %d, want 12", unsafe.Sizeof(eventIDFilter{}))
	}
	if unsafe.Sizeof(enableTraceParameters{}) != 48 {
		t.Fatalf("ENABLE_TRACE_PARAMETERS size = %d, want 48", unsafe.Sizeof(enableTraceParameters{}))
	}
}

func TestOnEventValidatesSchemaAndTargetPID(t *testing.T) {
	s := &Session{flows: make(map[flowKey]*Flow), targets: map[uint32]struct{}{42: {}}}
	s.collecting.Store(true)
	s.minimumQPC.Store(100)

	valid := udpPayload(42)
	rec := udpRecord(eventUDPv4Send, 101, valid)
	s.onEvent(&rec)
	runtime.KeepAlive(valid)

	got := s.TakeFlows()
	if len(got) != 1 || got[0].PID != 42 || got[0].Remote != netip.MustParseAddrPort("1.2.3.4:27015") {
		t.Fatalf("valid flow = %+v", got)
	}

	nonTarget := udpPayload(99)
	rec = udpRecord(eventUDPv4Send, 102, nonTarget)
	s.onEvent(&rec)
	runtime.KeepAlive(nonTarget)
	if got := s.TakeFlows(); len(got) != 0 {
		t.Fatalf("non-target flow was retained: %+v", got)
	}

	badSchema := udpPayload(42)
	rec = udpRecord(eventUDPv4Send, 103, badSchema)
	rec.EventHeader.EventDescriptor.Version = 1
	s.onEvent(&rec)
	runtime.KeepAlive(badSchema)
	if got := s.schemaErrors.Load(); got != 1 {
		t.Fatalf("schema errors = %d, want 1", got)
	}

	// A UDPv6 send event yields the IPv6 remote endpoint the same way.
	v6 := udpPayloadV6(42)
	rec = udpRecord(eventUDPv6Send, 104, v6)
	s.onEvent(&rec)
	runtime.KeepAlive(v6)
	if got := s.TakeFlows(); len(got) != 1 || got[0].PID != 42 ||
		got[0].Remote != netip.MustParseAddrPort("[2001:db8::4]:27015") {
		t.Fatalf("valid v6 flow = %+v", got)
	}
}

func udpPayload(pid uint32) []byte {
	b := make([]byte, udpEventV4Len)
	binary.LittleEndian.PutUint32(b[0:4], pid)
	binary.LittleEndian.PutUint32(b[4:8], 120)
	copy(b[8:12], []byte{1, 2, 3, 4})
	copy(b[12:16], []byte{10, 0, 0, 1})
	binary.BigEndian.PutUint16(b[16:18], 27015)
	binary.BigEndian.PutUint16(b[18:20], 50000)
	return b
}

func udpPayloadV6(pid uint32) []byte {
	b := make([]byte, 52) // full v6 template incl. trailing seqnum+connid
	binary.LittleEndian.PutUint32(b[0:4], pid)
	binary.LittleEndian.PutUint32(b[4:8], 120)
	copy(b[8:24], netip.MustParseAddr("2001:db8::4").AsSlice())   // daddr
	copy(b[24:40], netip.MustParseAddr("2001:db8::100").AsSlice()) // saddr
	binary.BigEndian.PutUint16(b[40:42], 27015)
	binary.BigEndian.PutUint16(b[42:44], 50000)
	return b
}

func udpRecord(id uint16, timestamp int64, payload []byte) eventRecord {
	return eventRecord{
		EventHeader: eventHeader{
			TimeStamp:  timestamp,
			ProviderID: kernelNetworkGUID,
			EventDescriptor: eventDescriptor{
				ID: id, Version: eventVersion, Level: traceLevelInformational,
				Opcode: uint8(id), Task: eventUDPTask, Keyword: kernelNetworkKeywordIPv4,
			},
		},
		UserDataLength: uint16(len(payload)),
		UserData:       unsafe.Pointer(&payload[0]),
	}
}
