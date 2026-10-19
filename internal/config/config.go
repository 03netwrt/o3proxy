package config

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// ProxyConfig defines one SOCKS5 proxy instance
type ProxyConfig struct {
	Port     int    `json:"port"`      // Listen port (e.g., 1081)
	Suffix   string `json:"suffix"`    // IPv6 suffix (e.g., "a1b2:c3d4:e5f6:7890")
	SourceIP string `json:"source_ip"` // Full source IPv6 (filled at runtime)
}

// Config holds the full configuration
type Config struct {
	Interface string        `json:"interface"` // e.g., "wwan0"
	BasePort  int           `json:"base_port"` // e.g., 1081
	Count     int           `json:"count"`     // e.g., 20
	Proxies   []ProxyConfig `json:"proxies"`
}

// DefaultConfig returns a sensible default
func DefaultConfig() *Config {
	return &Config{
		Interface: "wwan0",
		BasePort:  1081,
		Count:     20,
	}
}

// randomSuffix generates a random 64-bit IPv6 suffix as 4 hextets
// e.g., "a1b2:c3d4:e5f6:7890" — anti-detection, no sequential pattern
func randomSuffix() string {
	var hextets [4]uint16
	for i := range hextets {
		n, err := rand.Int(rand.Reader, big.NewInt(65536))
		if err != nil {
			// Fallback (should never happen)
			hextets[i] = uint16(i * 0x1111)
			continue
		}
		hextets[i] = uint16(n.Int64())
	}
	// Avoid all-zero suffix
	if hextets[0] == 0 && hextets[1] == 0 && hextets[2] == 0 && hextets[3] == 0 {
		hextets[3] = 1
	}
	return fmt.Sprintf("%x:%x:%x:%x", hextets[0], hextets[1], hextets[2], hextets[3])
}

// GenerateProxies creates proxy configs with RANDOM 64-bit suffixes
// Anti-detection: no sequential pattern (a1, b1, ...) that bot guards can fingerprint
func (c *Config) GenerateProxies(prefix string) {
	c.Proxies = make([]ProxyConfig, 0, c.Count)
	seen := make(map[string]bool)
	for i := 0; i < c.Count; i++ {
		var suf string
		for {
			suf = randomSuffix()
			if !seen[suf] {
				seen[suf] = true
				break
			}
		}
		c.Proxies = append(c.Proxies, ProxyConfig{
			Port:     c.BasePort + i,
			Suffix:   suf,
			SourceIP: prefix + ":" + suf,
		})
	}
}
