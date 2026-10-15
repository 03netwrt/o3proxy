package proxy

import (
	"fmt"
	"io"
	"net"
	"time"
)

// SOCKS5 server with source IP binding for egress
type Server struct {
	ListenAddr string // e.g., "0.0.0.0:1081"
	SourceIP   string // e.g., "2400:9800:262:540e::a1" (egress source)
	listener   net.Listener
}

// New creates a SOCKS5 server
func New(listenAddr, sourceIP string) *Server {
	return &Server{
		ListenAddr: listenAddr,
		SourceIP:   sourceIP,
	}
}

// Start begins listening
func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.ListenAddr, err)
	}
	s.listener = l

	go s.acceptLoop()
	return nil
}

// Stop closes the listener
func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(client net.Conn) {
	defer client.Close()

	// SOCKS5 handshake
	// 1. Client sends: VER, NMETHODS, METHODS
	buf := make([]byte, 258)
	client.SetDeadline(time.Now().Add(10 * time.Second))

	n, err := client.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}

	// 2. Server replies: VER, METHOD (0x00 = no auth)
	client.Write([]byte{0x05, 0x00})

	// 3. Client sends request: VER, CMD, RSV, ATYP, DST.ADDR, DST.PORT
	n, err = client.Read(buf)
	if err != nil || n < 4 || buf[0] != 0x05 {
		return
	}

	if buf[1] != 0x01 { // Only CONNECT supported
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Parse destination
	var host string
	var port int
	atyp := buf[3]
	switch atyp {
	case 0x01: // IPv4
		if n < 10 {
			return
		}
		host = net.IP(buf[4:8]).String()
		port = int(buf[8])<<8 | int(buf[9])
	case 0x03: // Domain
		if n < 5 {
			return
		}
		dlen := int(buf[4])
		if n < 5+dlen+2 {
			return
		}
		host = string(buf[5 : 5+dlen])
		port = int(buf[5+dlen])<<8 | int(buf[5+dlen+1])
	case 0x04: // IPv6
		if n < 22 {
			return
		}
		host = net.IP(buf[4:20]).String()
		port = int(buf[20])<<8 | int(buf[21])
	default:
		return
	}

	// Connect to destination with source IP binding via NAT64
	// Key insight (Latifan): the proxy must explicitly use NAT64.
	// For IPv4 destinations, synthesize 64:ff9b::/96 address so the
	// kernel routes via NAT64 with our bound IPv6 source.
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: net.ParseIP(s.SourceIP),
		},
	}

	var server net.Conn

	// Resolve destination to IP(s)
	ips, resolveErr := net.LookupIP(host)
	if resolveErr != nil || len(ips) == 0 {
		// If host is already an IP literal, use it directly
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else {
			client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
	}

	for _, ip := range ips {
		var target string
		var network string

		if ip.To4() != nil {
			// IPv4 destination → synthesize NAT64 IPv6 (64:ff9b::/96)
			nat64 := synthesizeNAT64(ip)
			target = fmt.Sprintf("[%s]:%d", nat64.String(), port)
			network = "tcp6"
		} else {
			// IPv6 destination → direct
			target = fmt.Sprintf("[%s]:%d", ip.String(), port)
			network = "tcp6"
		}

		server, err = dialer.Dial(network, target)
		if err == nil {
			break
		}
	}

	if err != nil || server == nil {
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer server.Close()

	// 4. Server replies success
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	client.SetDeadline(time.Time{})

	// 5. Relay
	go io.Copy(server, client)
	io.Copy(client, server)
}

// synthesizeNAT64 converts an IPv4 to its NAT64 IPv6 equivalent
// using the well-known prefix 64:ff9b::/96 (RFC 6052).
// e.g., 1.1.1.1 -> 64:ff9b::101:101
func synthesizeNAT64(ipv4 net.IP) net.IP {
	v4 := ipv4.To4()
	if v4 == nil {
		return ipv4
	}
	// 64:ff9b::/96 + 32-bit IPv4
	nat64 := make(net.IP, 16)
	nat64[0] = 0x00
	nat64[1] = 0x64
	nat64[2] = 0xff
	nat64[3] = 0x9b
	// bytes 4-9 are zero (already)
	// bytes 10-11 are zero (already, per RFC 6052 for /96)
	copy(nat64[12:16], v4)
	return nat64
}
