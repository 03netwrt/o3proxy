package proxy

import (
	"fmt"
	"io"
	"net"
	"sync"
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

// nat64Prefix holds the discovered NAT64 prefix (RFC 7050).
// Initialized at startup via network.DiscoverNAT64Prefix(), defaults to 64:ff9b::/96.
var nat64Prefix = "64:ff9b::/96"

// SetNAT64Prefix sets the NAT64 prefix used for IPv4 synthesis.
// Called at startup after RFC 7050 discovery.
func SetNAT64Prefix(prefix string) {
	if prefix != "" {
		nat64Prefix = prefix
	}
}

// synthesizeNAT64 converts an IPv4 to its NAT64 IPv6 equivalent
// using the discovered prefix (RFC 6052 + RFC 7050).
// e.g., 1.1.1.1 -> 64:ff9b::101:101 (with default /96 prefix)
func synthesizeNAT64(ipv4 net.IP) net.IP {
	v4 := ipv4.To4()
	if v4 == nil {
		return ipv4
	}
	// Parse the prefix to get its bytes
	prefixIP, prefixNet, err := net.ParseCIDR(nat64Prefix)
	if err != nil {
		// Fallback to well-known
		prefixIP = net.ParseIP("64:ff9b::")
		prefixNet = &net.IPNet{Mask: net.CIDRMask(96, 128)}
	}
	ones, _ := prefixNet.Mask.Size()

	nat64 := make(net.IP, 16)
	copy(nat64, prefixIP.To16())

	if ones == 96 {
		// /96: embed IPv4 in last 32 bits
		copy(nat64[12:16], v4)
	} else if ones == 64 {
		// /64: embed IPv4 in bits 64-96
		copy(nat64[8:12], v4)
	} else {
		// Unknown prefix length, fallback to /96 behavior
		copy(nat64[12:16], v4)
	}
	return nat64
}

// handleUDPAssociate handles SOCKS5 UDP ASSOCIATE (RFC 1928).
// The client sends a UDP ASSOCIATE request over the TCP control connection.
// We create a UDP relay socket, reply with its address, then forward
// datagrams between the client and destinations, binding our source IPv6.
func (s *Server) handleUDPAssociate(client net.Conn) {
	defer client.Close()

	// Get the local address the client connected to (for BND.ADDR).
	// This allows LAN/WiFi clients (not just localhost) to reach the relay.
	// Falls back to 127.0.0.1 if we can't determine it.
	bindIP := "127.0.0.1"
	if localAddr, ok := client.LocalAddr().(*net.TCPAddr); ok && localAddr.IP != nil {
		// Use the interface IP, not the client's IP
		bindIP = localAddr.IP.String()
		// If it's 0.0.0.0 (listening on all), use 127.0.0.1 for localhost clients
		// or try to find a suitable LAN IP
		if bindIP == "0.0.0.0" || bindIP == "::" {
			bindIP = "127.0.0.1"
		}
	}

	// Create UDP relay socket bound to the same IP the client used
	udpAddr, err := net.ResolveUDPAddr("udp", bindIP+":0")
	if err != nil {
		return
	}
	relay, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return
	}
	defer relay.Close()

	relayPort := relay.LocalAddr().(*net.UDPAddr).Port
	relayIP := relay.LocalAddr().(*net.UDPAddr).IP

	// Reply: VER(0x05) REP(0x00) RSV(0x00) ATYP BND.ADDR BND.PORT
	// Use ATYP 0x01 (IPv4) or 0x04 (IPv6) based on the bind IP
	var reply []byte
	if ip4 := relayIP.To4(); ip4 != nil {
		reply = []byte{0x05, 0x00, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3],
			byte(relayPort >> 8), byte(relayPort & 0xff)}
	} else {
		ip16 := relayIP.To16()
		reply = []byte{0x05, 0x00, 0x00, 0x04}
		reply = append(reply, ip16...)
		reply = append(reply, byte(relayPort>>8), byte(relayPort&0xff))
	}
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

	// Persistent UDP sessions keyed by destination (for QUIC/HTTP3/gaming)
	sessions := make(map[string]*udpSession)
	var sessionsMu sync.Mutex

	// Cleanup all sessions when this function returns (TCP control closed)
	defer func() {
		sessionsMu.Lock()
		for key, sess := range sessions {
			close(sess.done)
			sess.upstream.Close()
			delete(sessions, key)
		}
		sessionsMu.Unlock()
	}()

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

		// Resolve destination
		var destIP net.IP
		var destPort = port
		if ip := net.ParseIP(host); ip != nil {
			destIP = ip
		} else {
			ips, err := net.LookupIP(host)
			if err != nil || len(ips) == 0 {
				continue
			}
			destIP = ips[0]
		}

		// Get or create persistent upstream session for this destination
		destKey := destIP.String() + ":" + fmt.Sprintf("%d", destPort)

		// Check if this is a new session (need to start reader)
		sessionsMu.Lock()
		_, exists := sessions[destKey]
		sessionsMu.Unlock()

		session := getOrCreateSession(sessions, &sessionsMu, destKey, srcIP, destIP, destPort)
		if session == nil {
			continue
		}

		// Start reader goroutine for new sessions
		if !exists {
			// Wait until we know clientUDP (from first datagram)
			if clientUDP != nil {
				startSessionReader(relay, clientUDP, session, sessions, &sessionsMu, destKey)
			}
		}

		// Send via the persistent session
		if _, err := session.upstream.Write(payload); err != nil {
			// Session broken, remove it so next packet creates a new one
			removeSession(sessions, &sessionsMu, destKey)
			continue
		}
		// Response will arrive via the session's reader goroutine
	}
}

// udpSession holds a persistent upstream UDP connection for one destination.
// Responses are forwarded back to the SOCKS5 client via the relay socket.
type udpSession struct {
	upstream *net.UDPConn
	destIP   net.IP
	destPort int
	done     chan struct{}
}

// getOrCreateSession returns an existing session or creates a new one.
// A reader goroutine is started for new sessions to forward responses.
func getOrCreateSession(sessions map[string]*udpSession, mu *sync.Mutex, key string, srcIP, destIP net.IP, destPort int) *udpSession {
	mu.Lock()
	defer mu.Unlock()

	if s, ok := sessions[key]; ok {
		return s
	}

	// Resolve destination address (with NAT64 synthesis for IPv4)
	var raddr *net.UDPAddr
	if destIP.To4() != nil {
		nat64 := synthesizeNAT64(destIP)
		raddr = &net.UDPAddr{IP: nat64, Port: destPort}
	} else {
		raddr = &net.UDPAddr{IP: destIP, Port: destPort}
	}

	laddr := &net.UDPAddr{IP: srcIP, Port: 0}
	upstream, err := net.DialUDP("udp6", laddr, raddr)
	if err != nil {
		return nil
	}

	s := &udpSession{
		upstream: upstream,
		destIP:   destIP,
		destPort: destPort,
		done:     make(chan struct{}),
	}
	sessions[key] = s
	return s
}

// removeSession closes and removes a session from the map.
func removeSession(sessions map[string]*udpSession, mu *sync.Mutex, key string) {
	mu.Lock()
	defer mu.Unlock()
	if s, ok := sessions[key]; ok {
		close(s.done)
		s.upstream.Close()
		delete(sessions, key)
	}
}

// startSessionReader starts a goroutine that forwards upstream responses
// back to the SOCKS5 client. Runs until the session is removed.
func startSessionReader(relay *net.UDPConn, clientUDP *net.UDPAddr, s *udpSession, sessions map[string]*udpSession, mu *sync.Mutex, key string) {
	go func() {
		buf := make([]byte, 65535)
		for {
			select {
			case <-s.done:
				return
			default:
			}
			s.upstream.SetReadDeadline(time.Now().Add(30 * time.Second))
			n, err := s.upstream.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				// Connection broken, clean up
				removeSession(sessions, mu, key)
				return
			}
			if n == 0 {
				continue
			}
			out := buildUDPReply(s.destIP, s.destPort, buf[:n])
			relay.WriteToUDP(out, clientUDP)
		}
	}()
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
