package accesspath

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

type Reflector struct{ ID, HTTPS, TCP, UDP string }

func ReflectorsFromEnv() []Reflector {
	raw := strings.TrimSpace(os.Getenv("PINGRANK_REFLECTORS"))
	if raw == "" {
		return []Reflector{{ID: "syd-1", HTTPS: "https://ingest.pingrank.gg/v1/reflect", TCP: "syd.reflector.pingrank.gg:3479", UDP: "syd.reflector.pingrank.gg:3478"}}
	}
	var out []Reflector
	for _, item := range strings.Split(raw, ",") {
		p := strings.Split(item, "|")
		if len(p) == 4 {
			out = append(out, Reflector{ID: p[0], HTTPS: p[1], TCP: p[2], UDP: p[3]})
		}
	}
	return out
}

type reflectResponse struct {
	Nonce       string `json:"nonce"`
	PublicIPv4  string `json:"observedPublicIpv4,omitempty"`
	PublicIPv6  string `json:"observedPublicIpv6,omitempty"`
	PublicPort  int    `json:"observedPublicPort"`
	Transport   string `json:"transport"`
	ReflectorID string `json:"reflectorId"`
}

func nonce() string { b := make([]byte, 16); _, _ = rand.Read(b); return hex.EncodeToString(b) }

func observeHTTPS(ctx context.Context, r Reflector, network string) (Observation, error) {
	if r.HTTPS == "" {
		return Observation{}, fmt.Errorf("https unavailable")
	}
	n := nonce()
	d := net.Dialer{Timeout: 3 * time.Second}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) }}
	defer tr.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.HTTPS+"?nonce="+n, nil)
	if err != nil {
		return Observation{}, err
	}
	resp, err := (&http.Client{Transport: tr, Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return Observation{}, err
	}
	defer resp.Body.Close()
	var rr reflectResponse
	if err = json.NewDecoder(resp.Body).Decode(&rr); err != nil {
		return Observation{}, err
	}
	if rr.Nonce != n {
		return Observation{}, fmt.Errorf("reflector nonce mismatch")
	}
	return observation(rr, r.ID), nil
}

func observeTCP(ctx context.Context, r Reflector, network string) (Observation, error) {
	if r.TCP == "" {
		return Observation{}, fmt.Errorf("tcp unavailable")
	}
	c, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, r.TCP)
	if err != nil {
		return Observation{}, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(4 * time.Second))
	n := nonce()
	if _, err = fmt.Fprintln(c, n); err != nil {
		return Observation{}, err
	}
	var rr reflectResponse
	if err = json.NewDecoder(bufio.NewReader(c)).Decode(&rr); err != nil {
		return Observation{}, err
	}
	if rr.Nonce != n {
		return Observation{}, fmt.Errorf("reflector nonce mismatch")
	}
	return observation(rr, r.ID), nil
}

func observeUDP(ctx context.Context, r Reflector, conn *net.UDPConn, override *net.UDPAddr) (Observation, error) {
	if r.UDP == "" && override == nil {
		return Observation{}, fmt.Errorf("udp unavailable")
	}
	owned := false
	if conn == nil {
		var err error
		network := "udp4"
		if override != nil && override.IP.To4() == nil {
			network = "udp6"
		}
		conn, err = net.ListenUDP(network, nil)
		if err != nil {
			return Observation{}, err
		}
		owned = true
	}
	if owned {
		defer conn.Close()
	}
	dst := override
	if dst == nil {
		a, err := net.ResolveUDPAddr("udp", r.UDP)
		if err != nil {
			return Observation{}, err
		}
		dst = a
	}
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	n := nonce()
	if _, err := conn.WriteToUDP([]byte("PINGRANK1 "+n), dst); err != nil {
		return Observation{}, err
	}
	b := make([]byte, 2048)
	nr, _, err := conn.ReadFromUDP(b)
	if err != nil {
		return Observation{}, err
	}
	var rr reflectResponse
	if err = json.Unmarshal(b[:nr], &rr); err != nil {
		return Observation{}, err
	}
	if rr.Nonce != n {
		return Observation{}, fmt.Errorf("reflector nonce mismatch")
	}
	return observation(rr, r.ID), nil
}

func observation(rr reflectResponse, fallbackID string) Observation {
	id := rr.ReflectorID
	if id == "" {
		id = fallbackID
	}
	return Observation{PublicIPv4: rr.PublicIPv4, PublicIPv6: rr.PublicIPv6, PublicPort: rr.PublicPort, Transport: rr.Transport, ReflectorID: id}
}

func firstIPv4(hostport string) (netip.Addr, uint16, error) {
	host, portText, err := net.SplitHostPort(hostport)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	port64, err := net.LookupPort("udp", portText)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	ips, err := net.DefaultResolver.LookupNetIP(context.Background(), "ip4", host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, 0, fmt.Errorf("no IPv4 for reflector")
	}
	return ips[0].Unmap(), uint16(port64), nil
}
