package config

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

// GenerateProxies creates proxy configs with suffixes
func (c *Config) GenerateProxies(prefix string) {
	suffixes := []string{"a1", "b1", "c1", "d1", "e1", "f1", "a2", "b2", "c2", "d2",
		"e2", "f2", "a3", "b3", "c3", "d3", "e3", "f3", "a4", "b4"}
	c.Proxies = make([]ProxyConfig, 0, c.Count)
	for i := 0; i < c.Count && i < len(suffixes); i++ {
		suf := suffixes[i]
		c.Proxies = append(c.Proxies, ProxyConfig{
			Port:     c.BasePort + i,
			Suffix:   suf,
			SourceIP: prefix + "::" + suf,
		})
	}
}
