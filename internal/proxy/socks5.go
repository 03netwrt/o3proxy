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

	// Connect to destination with source IP binding
	target := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		LocalAddr: &net.TCPAddr{
			IP: net.ParseIP(s.SourceIP),
		},
	}

	// Prefer IPv6 if source is IPv6
	network := "tcp"
	if net.ParseIP(s.SourceIP).To4() == nil {
		// Source is IPv6, try tcp6 first for IPv6 destinations
		// But allow fallback for IPv4 via NAT64
	}

	server, err := dialer.Dial(network, target)
	if err != nil {
		// Try with domain resolution
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
