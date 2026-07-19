// Package sockets wraps the IP Helper connection-table APIs
// (GetExtendedTcpTable / GetExtendedUdpTable) with hand-written syscall
// bindings. IPv4 only for now, matching the milestone scope.
//
// Anti-cheat safety: these APIs read OS-owned tables. No process handles,
// no packet capture, no game interaction of any kind.
package sockets

import (
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Proto is the transport protocol of a socket-table entry.
type Proto string

const (
	ProtoTCP Proto = "tcp"
	ProtoUDP Proto = "udp"
)

// TCP connection states from MIB_TCP_STATE.
const (
	TCPStateEstablished uint32 = 5
)

// Entry is one normalized socket-table row.
//
// For UDP, Remote is the zero AddrPort: the Windows UDP table simply does
// not carry remote endpoints (see internal/flows for how that gap is
// bridged). We return what the OS gives us.
type Entry struct {
	Proto    Proto
	Local    netip.AddrPort
	Remote   netip.AddrPort // zero value for UDP
	PID      uint32
	TCPState uint32 // MIB_TCP_STATE; 0 for UDP
}

// Querier snapshots the socket tables. Interface so flows logic and future
// tests can run against canned data.
type Querier interface {
	Snapshot() ([]Entry, error)
}

var (
	modiphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1 // UDP_TABLE_OWNER_PID
)

// mibTCPRowOwnerPID mirrors MIB_TCPROW_OWNER_PID. Addresses are IPv4 in
// network byte order; ports are in the low 16 bits, network byte order.
type mibTCPRowOwnerPID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPID  uint32
}

// mibUDPRowOwnerPID mirrors MIB_UDPROW_OWNER_PID. No remote endpoint —
// the OS does not track one for UDP, even for connect()ed sockets.
type mibUDPRowOwnerPID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPID uint32
}

// SystemQuerier reads the live OS tables.
type SystemQuerier struct{}

func (SystemQuerier) Snapshot() ([]Entry, error) {
	tcp, err := tcpTable()
	if err != nil {
		return nil, err
	}
	udp, err := udpTable()
	if err != nil {
		return nil, err
	}
	return append(tcp, udp...), nil
}

// getTable calls one of the GetExtended*Table procs with the standard
// grow-the-buffer-on-ERROR_INSUFFICIENT_BUFFER dance and returns the raw
// table buffer. Layout: uint32 row count, then packed rows.
func getTable(proc *windows.LazyProc, tableClass uint32) ([]byte, error) {
	var size uint32
	for range 4 {
		var buf []byte
		var ptr unsafe.Pointer
		if size > 0 {
			buf = make([]byte, size)
			ptr = unsafe.Pointer(&buf[0])
		}
		ret, _, _ := proc.Call(
			uintptr(ptr),
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder: unsorted is fine
			uintptr(windows.AF_INET),
			uintptr(tableClass),
			0, // Reserved
		)
		switch windows.Errno(ret) {
		case windows.ERROR_SUCCESS:
			if buf == nil {
				return nil, fmt.Errorf("%s: success with nil buffer", proc.Name)
			}
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			// size was updated; loop and retry. The table can grow between
			// the size query and the fetch, hence the retry loop.
			continue
		default:
			return nil, fmt.Errorf("%s: %w", proc.Name, windows.Errno(ret))
		}
	}
	return nil, fmt.Errorf("%s: table kept growing after 4 attempts", proc.Name)
}

func tcpTable() ([]Entry, error) {
	buf, err := getTable(procGetExtendedTcpTable, tcpTableOwnerPidAll)
	if err != nil {
		return nil, err
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibTCPRowOwnerPID{})
	if uintptr(len(buf)) < 4+uintptr(count)*rowSize {
		return nil, fmt.Errorf("tcp table buffer too small for %d rows", count)
	}
	entries := make([]Entry, 0, count)
	for i := uintptr(0); i < uintptr(count); i++ {
		row := (*mibTCPRowOwnerPID)(unsafe.Pointer(&buf[4+i*rowSize]))
		entries = append(entries, Entry{
			Proto:    ProtoTCP,
			Local:    addrPort(row.LocalAddr, row.LocalPort),
			Remote:   addrPort(row.RemoteAddr, row.RemotePort),
			PID:      row.OwningPID,
			TCPState: row.State,
		})
	}
	return entries, nil
}

func udpTable() ([]Entry, error) {
	buf, err := getTable(procGetExtendedUdpTable, udpTableOwnerPid)
	if err != nil {
		return nil, err
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibUDPRowOwnerPID{})
	if uintptr(len(buf)) < 4+uintptr(count)*rowSize {
		return nil, fmt.Errorf("udp table buffer too small for %d rows", count)
	}
	entries := make([]Entry, 0, count)
	for i := uintptr(0); i < uintptr(count); i++ {
		row := (*mibUDPRowOwnerPID)(unsafe.Pointer(&buf[4+i*rowSize]))
		entries = append(entries, Entry{
			Proto: ProtoUDP,
			Local: addrPort(row.LocalAddr, row.LocalPort),
			PID:   row.OwningPID,
		})
	}
	return entries, nil
}

// addrPort converts the table's network-byte-order address and port words
// into a netip.AddrPort.
func addrPort(addr, port uint32) netip.AddrPort {
	var b [4]byte
	b[0] = byte(addr)
	b[1] = byte(addr >> 8)
	b[2] = byte(addr >> 16)
	b[3] = byte(addr >> 24)
	p := uint16(port&0xff)<<8 | uint16(port>>8)&0xff
	return netip.AddrPortFrom(netip.AddrFrom4(b), p)
}
