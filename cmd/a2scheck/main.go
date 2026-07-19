// Command a2scheck is a temporary validation harness: it asks the Valve
// master server for live CS2 community servers, then measures a few of
// them with the A2S protocol probe and (for comparison) ICMP.
package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"pingrank.gg/internal/probe"
)

// masterHosts: the classic DNS name plus historic Valve master IPs, since
// the hostname has gone NXDOMAIN.
var masterHosts = []string{
	"hl2master.steamgames.com:27011",
	"208.64.200.65:27011",
	"208.64.200.52:27011",
	"208.64.200.117:27011",
	"208.64.201.194:27011",
}

func main() {
	var servers []netip.AddrPort
	var err error
	if len(os.Args) > 1 {
		for _, arg := range os.Args[1:] {
			ep, err := netip.ParseAddrPort(arg)
			if err != nil {
				fmt.Fprintln(os.Stderr, "bad endpoint:", arg)
				os.Exit(2)
			}
			servers = append(servers, ep)
		}
	} else {
		for _, host := range masterHosts {
			servers, err = masterQuery(host, `\appid\730`, 8)
			if err == nil && len(servers) > 0 {
				fmt.Println("master server:", host)
				break
			}
			fmt.Fprintf(os.Stderr, "master %s: %v (%d servers)\n", host, err, len(servers))
		}
	}
	if len(servers) == 0 {
		os.Exit(1)
	}
	fmt.Printf("master server returned %d candidates\n", len(servers))

	p := probe.IcmpProber{}
	checked := 0
	for _, ep := range servers {
		if checked >= 3 {
			break
		}
		a2s, err := p.Protocol("a2s", ep, 3)
		if err != nil || a2s.Received == 0 {
			fmt.Printf("%-22s a2s: no reply\n", ep)
			continue
		}
		checked++
		icmp, _ := p.Ping(ep.Addr(), 3)
		fmt.Printf("%-22s a2s: %d/%d replies, avg %.1fms | icmp: %d/%d replies, avg %.1fms\n",
			ep, a2s.Received, a2s.Sent, a2s.AvgMs, icmp.Received, icmp.Sent, icmp.AvgMs)
	}
	if checked == 0 {
		fmt.Println("no server answered A2S")
		os.Exit(1)
	}
}

// masterQuery speaks the Valve master-server protocol: one request, one
// batch of ip:port entries back.
func masterQuery(host, filter string, max int) ([]netip.AddrPort, error) {
	conn, err := net.Dial("udp4", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	req := []byte{0x31, 0xFF} // query, region: all
	req = append(req, "0.0.0.0:0\x00"...)
	req = append(req, filter...)
	req = append(req, 0x00)

	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 6 {
		return nil, fmt.Errorf("short reply (%d bytes)", n)
	}
	var out []netip.AddrPort
	for i := 6; i+6 <= n && len(out) < max; i += 6 {
		addr := netip.AddrFrom4([4]byte{buf[i], buf[i+1], buf[i+2], buf[i+3]})
		port := uint16(buf[i+4])<<8 | uint16(buf[i+5])
		if addr.IsUnspecified() || port == 0 {
			continue
		}
		out = append(out, netip.AddrPortFrom(addr, port))
	}
	return out, nil
}
