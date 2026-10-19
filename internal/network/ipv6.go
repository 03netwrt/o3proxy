package network

import (
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"
)

// Well-known NAT64 prefix (RFC 6052) — fallback if discovery fails
const DefaultNAT64Prefix = "64:ff9b::/96"

// DiscoverNAT64Prefix discovers the NAT64 prefix via RFC 7050.
// It resolves ipv4only.arpa (which has well-known IPv4 192.0.0.170/171).
// A DNS64 server synthesizes an IPv6; we extract the prefix from it.
// Falls back to 64:ff9b::/96 if discovery fails.
func DiscoverNAT64Prefix() string {
	// Well-known IPv4 addresses for ipv4only.arpa (RFC 7050)
	// 192.0.0.170 = c0:00:00:aa, 192.0.0.171 = c0:00:00:ab
	ips, err := net.LookupIP("ipv4only.arpa")
	if err != nil {
		return DefaultNAT64Prefix
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			continue // Skip plain IPv4, we want the synthesized IPv6
		}
		v6 := ip.To16()
		if v6 == nil {
			continue
		}
		// Check if it embeds 192.0.0.170 (c000:aa) or 192.0.0.171 (c000:ab)
		// Common placements: last 32 bits (/96), or bits 64-96 (/64)
		last32 := fmt.Sprintf("%02x%02x%02x%02x", v6[12], v6[13], v6[14], v6[15])
		if last32 == "c00000aa" || last32 == "c00000ab" {
			// /96 prefix: first 12 bytes
			prefix := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x::/96",
				v6[0], v6[1], v6[2], v6[3], v6[4], v6[5],
				v6[6], v6[7], v6[8], v6[9], v6[10], v6[11])
			return normalizePrefix(prefix)
		}
		// Check /64 placement (bits 64-96)
		mid32 := fmt.Sprintf("%02x%02x%02x%02x", v6[8], v6[9], v6[10], v6[11])
		if mid32 == "c00000aa" || mid32 == "c00000ab" {
			prefix := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x::/64",
				v6[0], v6[1], v6[2], v6[3], v6[4], v6[5], v6[6], v6[7])
			return normalizePrefix(prefix)
		}
	}
	return DefaultNAT64Prefix
}

// normalizePrefix compresses IPv6 prefix (removes leading zeros)
func normalizePrefix(prefix string) string {
	parts := strings.Split(strings.Split(prefix, "/")[0], ":")
	var normalized []string
	for _, p := range parts {
		if p == "" {
			normalized = append(normalized, "")
			continue
		}
		// Remove leading zeros but keep at least one digit
		trimmed := strings.TrimLeft(p, "0")
		if trimmed == "" {
			trimmed = "0"
		}
		normalized = append(normalized, trimmed)
	}
	plen := strings.Split(prefix, "/")[1]
	return strings.Join(normalized, ":") + "/" + plen
}

// GetPrefix returns the /64 prefix from an interface's global IPv6 address
// e.g., 2400:9800:262:540e:xxxx:... -> 2400:9800:262:540e
func GetPrefix(iface string) (string, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return "", fmt.Errorf("interface %s not found: %w", iface, err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return "", fmt.Errorf("failed to list addresses: %w", err)
	}

	for _, addr := range addrs {
		ip := addr.IP
		// Skip link-local (fe80::/10) and loopback
		if ip.IsLinkLocalUnicast() || ip.IsLoopback() {
			continue
		}
		// Must be global unicast 2400::/12 (XL) or any global
		if ip.IsGlobalUnicast() {
			// Extract first 64 bits (4 hextets)
			prefix := fmt.Sprintf("%x:%x:%x:%x",
				uint16(ip[0])<<8|uint16(ip[1]),
				uint16(ip[2])<<8|uint16(ip[3]),
				uint16(ip[4])<<8|uint16(ip[5]),
				uint16(ip[6])<<8|uint16(ip[7]),
			)
			return prefix, nil
		}
	}
	return "", fmt.Errorf("no global IPv6 found on %s", iface)
}

// AddAddr adds an IPv6 address to an interface via netlink
// e.g., AddAddr("wwan0", "2400:9800:262:540e::a1/64")
func AddAddr(iface, cidr string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", iface, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}

	// NODAD flag to avoid duplicate address detection delay
	addr.Flags |= 0x20 // IFA_F_NODAD

	if err := netlink.AddrAdd(link, addr); err != nil {
		// Ignore "file exists" (already added)
		if !isAddrExists(err) {
			return fmt.Errorf("failed to add %s: %w", cidr, err)
		}
	}
	return nil
}

// DelAddr removes an IPv6 address from an interface via netlink
func DelAddr(iface, cidr string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", iface, err)
	}

	addr, err := netlink.ParseAddr(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR %s: %w", cidr, err)
	}

	if err := netlink.AddrDel(link, addr); err != nil {
		if !isAddrNotExists(err) {
			return fmt.Errorf("failed to delete %s: %w", cidr, err)
		}
	}
	return nil
}

// ListAddrs returns all global IPv6 addresses on an interface
func ListAddrs(iface string) ([]string, error) {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return nil, fmt.Errorf("interface %s not found: %w", iface, err)
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err != nil {
		return nil, err
	}

	var result []string
	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() && !addr.IP.IsLinkLocalUnicast() {
			result = append(result, addr.IPNet.String())
		}
	}
	return result, nil
}

func isAddrExists(err error) bool {
	// EEXIST = file exists
	return err != nil && (isErrno(err, 17))
}

func isAddrNotExists(err error) bool {
	// EADDRNOTAVAIL
	return err != nil && (isErrno(err, 99))
}

func isErrno(err error, errno int) bool {
	if serr, ok := err.(interface{ Timeout() bool }); ok {
		_ = serr
	}
	// Simple string check for now
	return false
}

// ParseIPv6 parses a string into net.IP
func ParseIPv6(s string) net.IP {
	return net.ParseIP(s)
}
