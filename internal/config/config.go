package config

import "fmt"

// ProxyConfig defines one SOCKS5 proxy instance
type ProxyConfig struct {
	Port     int    `json:"port"`      // Listen port (e.g., 1081)
	Suffix   string `json:"suffix"`    // IPv6 suffix (e.g., "a1")
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

// GenerateProxies creates proxy configs with auto-generated suffixes
// Supports any count (e.g., 50, 100) — suffixes like a1, b1, ... f9, a10, ...
func (c *Config) GenerateProxies(prefix string) {
	c.Proxies = make([]ProxyConfig, 0, c.Count)
	letters := []string{"a", "b", "c", "d", "e", "f"}
	idx := 0
	num := 1
	for len(c.Proxies) < c.Count {
		for _, l := range letters {
			if len(c.Proxies) >= c.Count {
				break
			}
			suf := fmt.Sprintf("%s%d", l, num)
			c.Proxies = append(c.Proxies, ProxyConfig{
				Port:     c.BasePort + idx,
				Suffix:   suf,
				SourceIP: prefix + "::" + suf,
			})
			idx++
		}
		num++
	}
}
