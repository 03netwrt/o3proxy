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

	if buf[1] == 0x01 {
		s.handleConnect(client, buf, n)
	} else if buf[1] == 0x03 {
		s.handleUDPAssociate(client)
	} else {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
}

// handleConnect handles SOCKS5 CONNECT (TCP)
func (s *Server) handleConnect(client net.Conn, buf []byte, n int) {
	defer client.Close()

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

	var dialErr error

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

		server, dialErr = dialer.Dial(network, target)
		if dialErr == nil {
			break
		}
	}

	if dialErr != nil || server == nil {
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

// handleUDPAssociate handles SOCKS5 UDP ASSOCIATE (RFC 1928).
// The client sends a UDP ASSOCIATE request over the TCP control connection.
// We create a UDP relay socket, reply with its address, then forward
// datagrams between the client and destinations, binding our source IPv6.
func (s *Server) handleUDPAssociate(client net.Conn) {
	defer client.Close()

	// Create UDP relay socket bound to localhost (same port as TCP listener's IP)
	// We bind to 127.0.0.1:0 and report the actual port.
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		return
	}
	relay, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}
	defer relay.Close()

	relayPort := relay.LocalAddr().(*net.UDPAddr).Port

	// Reply: VER(0x05) REP(0x00) RSV(0x00) ATYP(0x01 IPv4) BND.ADDR(127.0.0.1) BND.PORT
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1,
		byte(relayPort >> 8), byte(relayPort & 0xff)}
	if _, err := client.Write(reply); err != nil {
		return
	}
	client.SetDeadline(time.Time{})

	// Relay loop. Each datagram from the client has a SOCKS5 UDP header:
	// RSV(2) FRAG(1) ATYP(1) DST.ADDR(var) DST.PORT(2) DATA...
	// We only support FRAG=0.
	buf := make([]byte, 65535)
	// Remember client UDP address from first datagram
	var clientUDP *net.UDPAddr

	// Source-bound UDP dialer for upstream
	srcIP := net.ParseIP(s.SourceIP)

	for {
		// Short read deadline so we can exit when TCP control conn closes
		relay.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, from, err := relay.ReadFromUDP(buf)
		if err != nil {
			// Check if TCP control connection is still alive
			client.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
			probe := make([]byte, 1)
			if _, perr := client.Read(probe); perr != nil {
				// Timeout means still alive (no data); other errors mean closed
				if ne, ok := perr.(net.Error); !ok || !ne.Timeout() {
					return
				}
			} else {
				return // got data on control conn = unexpected, close
			}
			client.SetReadDeadline(time.Time{})
			continue
		}
		if clientUDP == nil {
			clientUDP = from
		}
		if n < 4 || buf[2] != 0x00 { // FRAG must be 0
			continue
		}
		// Parse destination from SOCKS5 UDP header
		atyp := buf[3]
		var host string
		var port int
		var dataStart int
		switch atyp {
		case 0x01: // IPv4
			if n < 10 {
				continue
			}
			host = net.IP(buf[4:8]).String()
			port = int(buf[8])<<8 | int(buf[9])
			dataStart = 10
		case 0x03: // Domain
			if n < 5 {
				continue
			}
			dlen := int(buf[4])
			if n < 5+dlen+2 {
				continue
			}
			host = string(buf[5 : 5+dlen])
			port = int(buf[5+dlen])<<8 | int(buf[5+dlen+1])
			dataStart = 5 + dlen + 2
		case 0x04: // IPv6
			if n < 22 {
				continue
			}
			host = net.IP(buf[4:20]).String()
			port = int(buf[20])<<8 | int(buf[21])
			dataStart = 22
		default:
			continue
		}
		payload := buf[dataStart:n]

		// Resolve and send via source-bound UDP with NAT64 synthesis
		// Use from (actual UDP source) not clientUDP (TCP addr)
		go s.relayUDP(relay, from, srcIP, host, port, payload)
	}
}

// relayUDP forwards one UDP payload to the destination and relays the
// response back to the SOCKS5 client, wrapped in a SOCKS5 UDP header.
func (s *Server) relayUDP(relay *net.UDPConn, clientUDP *net.UDPAddr, srcIP net.IP, host string, port int, payload []byte) {
	// Resolve destination: check if it's already an IP first (avoid DNS lookup)
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		var err error
		ips, err = net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return
		}
	}

	for _, ip := range ips {
		var raddr *net.UDPAddr
		if ip.To4() != nil {
			nat64 := synthesizeNAT64(ip)
			raddr = &net.UDPAddr{IP: nat64, Port: port}
		} else {
			raddr = &net.UDPAddr{IP: ip, Port: port}
		}

		// Dial UDP with source IP binding
		laddr := &net.UDPAddr{IP: srcIP, Port: 0}
		upstream, err := net.DialUDP("udp6", laddr, raddr)
		if err != nil {
			continue
		}

		upstream.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := upstream.Write(payload); err != nil {
			upstream.Close()
			continue
		}

		resp := make([]byte, 65535)
		upstream.SetDeadline(time.Now().Add(10 * time.Second))
		nr, err := upstream.Read(resp)
		upstream.Close()
		if err != nil || nr == 0 {
			continue
		}

		// Wrap response in SOCKS5 UDP header and send back to client
		out := buildUDPReply(ip, port, resp[:nr])
		relay.WriteToUDP(out, clientUDP)
		return
	}
}

// buildUDPReply wraps payload in a SOCKS5 UDP response header.
func buildUDPReply(srcIP net.IP, srcPort int, payload []byte) []byte {
	var header []byte
	header = append(header, 0x00, 0x00, 0x00) // RSV(2) FRAG(1)=0
	if v4 := srcIP.To4(); v4 != nil {
		header = append(header, 0x01)
		header = append(header, v4...)
	} else {
		header = append(header, 0x04)
		header = append(header, srcIP.To16()...)
	}
	header = append(header, byte(srcPort>>8), byte(srcPort&0xff))
	return append(header, payload...)
}
