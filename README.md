# mcrelay

Lightweight multicast relay for VLAN interface bridging of:

- mDNS (`224.0.0.251:5353`, `ff02::fb:5353`)
- SSDP (`239.255.255.250:1900`, `ff02::c:1900`)

Supports IPv4 + IPv6 and fanout across multiple interfaces (for example `br10,br20,br40,br50`).

## Features

- Single static Go binary
- Multi-interface relay fanout
- Dual-stack relay (`-families 4,6`)
- Service selection (`-services mdns,ssdp`)
- Chromecast/Google preset (`-services chromecast` or `googlecast`, expands to `mdns,ssdp`)
- Loop suppression via short-lived packet fingerprint cache
- Destination-aware forwarding:
  - relays only packets actually addressed to the service multicast group
  - relays SSDP unicast responses to recent M-SEARCH requesters across VLANs
  - relays mDNS unicast responses (QU path) to recent mDNS queriers across VLANs
- Stdout/stderr logging only

## Why it exists

Most multicast relay tools do dumb flooding — they rebroadcast every multicast packet on every interface. This causes duplicate suppression failures and breaks Chromecast/SSDP discovery in networks with many VLANs. `mcrelay` only forwards packets addressed to the target multicast group, tracks recent M-SEARCH and mDNS QU queriers per-interface, and uses a fingerprint cache to suppress loops.

A typical two-VLAN scenario: IoT devices on `192.0.2.0/24` (VLAN 10, `eth0.10`) need to be discoverable from a client on `198.51.100.0/24` (VLAN 20, `eth0.20`). Without a relay, mDNS and SSDP are link-local and never cross the VLAN boundary. `mcrelay` bridges them without routing multicast at the network level.

## Build

```bash
git clone https://github.com/Quxyzzy/mcrelay
cd mcrelay
go build -o mcrelay .
```

Pre-built binaries for `linux/amd64` and `linux/arm64` are available on the [Releases](../../releases) page.

## Usage

```bash
sudo ./mcrelay \
  -interfaces eth0.10,eth0.20 \
  -services mdns,ssdp \
  -families 4,6 \
  -cache-ms 1500
```

Flags:

- `-interfaces` comma-separated interfaces (required, at least 2)
- `-services` `mdns,ssdp,chromecast,googlecast` (default `mdns,ssdp`)
- `-families` `4,6` (default both)
- `-cache-ms` duplicate suppression window in milliseconds (default `1500`)
- `-bufsize` read buffer size (default `65535`)
- `-quiet` reduce per-packet logs

## UDMP on-boot example

```sh
#!/bin/sh
sleep 15
/data/mcrelay/mcrelay \
  -interfaces br10,br20,br40,br50 \
  -services chromecast \
  -families 4,6 \
  -cache-ms 1500 \
  -quiet \
  >> /var/log/mcrelay.log 2>&1 &
```

## Notes

- This is a multicast relay, not an IGMP/MLD proxy.
- Duplicate suppression is intentionally simple and time-window based.
- For IPv6 multicast forwarding, sockets are bound to each interface and sends are scoped per interface.
