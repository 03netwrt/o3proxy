package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/03netwrt/o3proxy/internal/config"
	"github.com/03netwrt/o3proxy/internal/dashboard"
	"github.com/03netwrt/o3proxy/internal/network"
	"github.com/03netwrt/o3proxy/internal/proxy"
)

func main() {
	var (
		iface    = flag.String("iface", "wwan0", "Network interface")
		basePort = flag.String("baseport", "1081", "Base SOCKS5 port")
		count    = flag.String("count", "20", "Number of proxies")
		action   = flag.String("action", "run", "Action: run|prefix|add|list|web")
		addr     = flag.String("addr", "", "IPv6 CIDR (for add action)")
		webAddr  = flag.String("web", "127.0.0.1:8080", "Dashboard listen address")
	)
	flag.Parse()

	switch *action {
	case "prefix":
		pfx, err := network.GetPrefix(*iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", pfx)

	case "add":
		if *addr == "" {
			fmt.Fprintln(os.Stderr, "Need -addr")
			os.Exit(1)
		}
		if err := network.AddAddr(*iface, *addr); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Added %s\n", *addr)

	case "list":
		addrs, err := network.ListAddrs(*iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, a := range addrs {
			fmt.Println(a)
		}

	case "run":
		runProxies(*iface, *basePort, *count, *webAddr)

	case "web":
		var bp, c int
		fmt.Sscanf(*basePort, "%d", &bp)
		fmt.Sscanf(*count, "%d", &c)
		dash := dashboard.New(bp, c, 10, "/data/local/tmp/earnapp-chroots")
		fmt.Printf("Dashboard on http://%s\n", *webAddr)
		if err := dash.Start(*webAddr); err != nil {
			fmt.Fprintf(os.Stderr, "Dashboard error: %v\n", err)
			os.Exit(1)
		}

	default:
		fmt.Fprintf(os.Stderr, "Unknown action: %s\n", *action)
		os.Exit(1)
	}
}

func runProxies(iface, basePortStr, countStr, webAddr string) {
	var basePort, count int
	fmt.Sscanf(basePortStr, "%d", &basePort)
	fmt.Sscanf(countStr, "%d", &count)

	// Discover NAT64 prefix via RFC 7050 (fallback: 64:ff9b::/96)
	nat64Prefix := network.DiscoverNAT64Prefix()
	proxy.SetNAT64Prefix(nat64Prefix)
	fmt.Printf("NAT64 prefix: %s\n", nat64Prefix)

	// Get current prefix
	prefix, err := network.GetPrefix(iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get prefix: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Using prefix: %s::/64 on %s\n", prefix, iface)

	// Generate config
	cfg := config.DefaultConfig()
	cfg.Interface = iface
	cfg.BasePort = basePort
	cfg.Count = count
	cfg.GenerateProxies(prefix)

	// Add IPv6 addresses via netlink
	for _, p := range cfg.Proxies {
		cidr := fmt.Sprintf("%s/64", p.SourceIP)
		if err := network.AddAddr(iface, cidr); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to add %s: %v\n", cidr, err)
		} else {
			fmt.Printf("Added %s\n", cidr)
		}
	}

	// Start SOCKS5 servers
	servers := make([]*proxy.Server, 0, len(cfg.Proxies))
	for _, p := range cfg.Proxies {
		listenAddr := fmt.Sprintf("0.0.0.0:%d", p.Port)
		srv := proxy.New(listenAddr, p.SourceIP)
		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to start :%d: %v\n", p.Port, err)
			continue
		}
		servers = append(servers, srv)
		fmt.Printf("SOCKS5 :%d -> [%s]\n", p.Port, p.SourceIP)
	}

	fmt.Printf("\n%d proxies running. Ctrl+C to stop.\n", len(servers))

	// Start prefix monitor (self-healing)
	go monitorPrefix(iface, prefix, cfg, servers)

	// Start web dashboard
	dash := dashboard.New(basePort, count, 10, "/data/local/tmp/earnapp-chroots")
	go func() {
		fmt.Printf("Dashboard on http://%s\n", webAddr)
		dash.Start(webAddr)
	}()

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")
	for _, srv := range servers {
		srv.Stop()
	}
}

// monitorPrefix watches for IPv6 prefix changes (modem reconnect)
// and updates addresses + proxy source IPs automatically
func monitorPrefix(iface, oldPrefix string, cfg *config.Config, servers []*proxy.Server) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	current := oldPrefix
	for range ticker.C {
		newPrefix, err := network.GetPrefix(iface)
		if err != nil {
			continue
		}
		if newPrefix == current {
			continue
		}

		fmt.Printf("\n[!] Prefix changed: %s -> %s. Updating...\n", current, newPrefix)

		// Remove old addresses, add new ones
		for i, p := range cfg.Proxies {
			oldCIDR := fmt.Sprintf("%s/64", p.SourceIP)
			network.DelAddr(iface, oldCIDR)

			newIP := newPrefix + "::" + p.Suffix
			newCIDR := fmt.Sprintf("%s/64", newIP)
			network.AddAddr(iface, newCIDR)

			// Update proxy source IP (affects new connections)
			cfg.Proxies[i].SourceIP = newIP
			if i < len(servers) {
				servers[i].SourceIP = newIP
			}
			fmt.Printf("  :%d -> [%s]\n", p.Port, newIP)
		}
		current = newPrefix
		fmt.Printf("[!] Update complete. %d proxies on new prefix.\n", len(servers))
	}
}
