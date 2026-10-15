# o3proxy — 03NET IPv6 Proxy Manager

Golang + netlink multi-port SOCKS5 proxy with self-healing IPv6 prefix detection.

Inspired by the concept of IPv6 multi-IP proxying. Built from scratch, no shell dependency.

## Features

- **Pure-Go netlink**: Add/remove IPv6 addresses via `vishvananda/netlink` (no `ip` shell commands)
- **Multi-port SOCKS5**: N ports, each bound to a different IPv6 source address
- **Self-healing**: Monitors IPv6 prefix every 30s, auto-updates on modem reconnect

## Usage

```sh
# Run 20 SOCKS5 proxies (ports 1081-1100) on wwan0
./o3proxy -action run -iface wwan0 -baseport 1081 -count 20

# Show current IPv6 prefix
./o3proxy -action prefix -iface wwan0

# List IPv6 addresses
./o3proxy -action list -iface wwan0
```

## Testing

```sh
curl --socks5-hostname <ip>:1081 http://api64.ipify.org
curl --socks5-hostname <ip>:1082 http://api64.ipify.org
# Each port should return a different IPv4 (via NAT64)
```

## Building

```sh
# Native
go build -o o3proxy ./cmd/o3proxy

# For aarch64 (OpenWrt STB / Android)
GOOS=linux GOARCH=arm64 go build -o o3proxy-aarch64 ./cmd/o3proxy
```

## License

GPL-3.0 — see LICENSE file.
