#!/usr/bin/env python3
"""
mcrelay: Lightweight multicast relay for mDNS and SSDP across interfaces.

Features:
- mDNS (224.0.0.251/ff02::fb, UDP 5353)
- SSDP (239.255.255.250/ff02::c, UDP 1900)
- IPv4 and IPv6
- Interface-to-interface fanout
- Loop suppression via short-lived packet fingerprint cache

Designed for Linux (tested assumptions: SO_BINDTODEVICE, IP_ADD_MEMBERSHIP with ifindex).
"""

from __future__ import annotations

import argparse
import hashlib
import selectors
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple


SERVICE_DEFS = {
    "mdns": {
        4: ("224.0.0.251", 5353),
        6: ("ff02::fb", 5353),
    },
    "ssdp": {
        4: ("239.255.255.250", 1900),
        6: ("ff02::c", 1900),
    },
}


@dataclass(frozen=True)
class RelayConfig:
    service: str
    family: int  # 4 or 6
    group: str
    port: int


@dataclass
class Listener:
    sock: socket.socket
    iface: str
    ifindex: int
    cfg: RelayConfig


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Relay mDNS/SSDP over IPv4/IPv6 between interfaces")
    p.add_argument(
        "-i",
        "--interfaces",
        required=True,
        help="Comma-separated interface names (example: br20,br30,br40)",
    )
    p.add_argument(
        "-s",
        "--services",
        default="mdns,ssdp",
        help="Comma-separated services: mdns,ssdp (default: mdns,ssdp)",
    )
    p.add_argument(
        "-f",
        "--families",
        default="4,6",
        help="IP families to relay: 4,6 (default: 4,6)",
    )
    p.add_argument(
        "--cache-ms",
        type=int,
        default=1500,
        help="Duplicate suppression window in ms (default: 1500)",
    )
    p.add_argument(
        "--bufsize",
        type=int,
        default=65535,
        help="Receive buffer size (default: 65535)",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Reduce per-packet logging",
    )
    return p.parse_args()


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def build_relay_configs(services: Iterable[str], families: Iterable[int]) -> List[RelayConfig]:
    out: List[RelayConfig] = []
    for svc in services:
        if svc not in SERVICE_DEFS:
            raise ValueError(f"Unsupported service '{svc}' (valid: {', '.join(SERVICE_DEFS)})")
        for fam in families:
            if fam not in (4, 6):
                raise ValueError("Family must be 4 or 6")
            grp, port = SERVICE_DEFS[svc][fam]
            out.append(RelayConfig(service=svc, family=fam, group=grp, port=port))
    return out


def parse_csv_list(value: str) -> List[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


def parse_family_list(value: str) -> List[int]:
    out: List[int] = []
    for part in parse_csv_list(value):
        if part not in ("4", "6"):
            raise ValueError("families must be comma-separated values from {4,6}")
        out.append(int(part))
    return out


def create_v4_listener(iface: str, ifindex: int, cfg: RelayConfig) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except OSError:
        pass

    s.bind(("0.0.0.0", cfg.port))

    # Bind rx/tx to this interface to avoid routing ambiguity.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\x00")

    # IP_ADD_MEMBERSHIP with ip_mreqn (group, local_addr_any, ifindex)
    mreq = struct.pack("=4s4si", socket.inet_aton(cfg.group), socket.inet_aton("0.0.0.0"), ifindex)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    # Keep multicast local to link and avoid loopback into local stack.
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)

    s.setblocking(False)
    return s


def create_v6_listener(iface: str, ifindex: int, cfg: RelayConfig) -> socket.socket:
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    except OSError:
        pass

    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind(("::", cfg.port))

    # Bind rx/tx to this interface to avoid routing ambiguity.
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\x00")

    # IPV6_JOIN_GROUP requires packed multicast addr + ifindex.
    mreq = struct.pack("=16si", socket.inet_pton(socket.AF_INET6, cfg.group), ifindex)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)

    s.setblocking(False)
    return s


def fingerprint(cfg: RelayConfig, payload: bytes) -> bytes:
    h = hashlib.blake2s(digest_size=16)
    h.update(cfg.service.encode())
    h.update(b"|")
    h.update(str(cfg.family).encode())
    h.update(b"|")
    h.update(str(cfg.port).encode())
    h.update(b"|")
    h.update(payload)
    return h.digest()


def cleanup_cache(cache: Dict[bytes, float], now: float) -> None:
    stale = [k for k, exp in cache.items() if exp <= now]
    for k in stale:
        cache.pop(k, None)


def send_to_listener(dst: Listener, payload: bytes) -> None:
    if dst.cfg.family == 4:
        dst.sock.sendto(payload, (dst.cfg.group, dst.cfg.port))
    else:
        # (addr, port, flowinfo, scopeid)
        dst.sock.sendto(payload, (dst.cfg.group, dst.cfg.port, 0, dst.ifindex))


def main() -> int:
    args = parse_args()

    interfaces = parse_csv_list(args.interfaces)
    if len(interfaces) < 2:
        eprint("Need at least 2 interfaces to relay between")
        return 2

    services = parse_csv_list(args.services)
    families = parse_family_list(args.families)

    try:
        relay_cfgs = build_relay_configs(services, families)
    except ValueError as exc:
        eprint(str(exc))
        return 2

    sel = selectors.DefaultSelector()
    listeners: List[Listener] = []

    for iface in interfaces:
        try:
            ifindex = socket.if_nametoindex(iface)
        except OSError:
            eprint(f"Interface '{iface}' does not exist")
            return 2

        for cfg in relay_cfgs:
            try:
                if cfg.family == 4:
                    sock = create_v4_listener(iface, ifindex, cfg)
                else:
                    sock = create_v6_listener(iface, ifindex, cfg)
            except OSError as exc:
                eprint(f"Failed to create listener iface={iface} service={cfg.service} ipv{cfg.family}: {exc}")
                return 1

            lst = Listener(sock=sock, iface=iface, ifindex=ifindex, cfg=cfg)
            listeners.append(lst)
            sel.register(sock, selectors.EVENT_READ, data=lst)

    print("mcrelay started")
    print(f"interfaces={','.join(interfaces)} services={','.join(services)} families={','.join(map(str, families))}")

    dedupe_ttl = max(1, args.cache_ms) / 1000.0
    cache: Dict[bytes, float] = {}
    last_cleanup = time.monotonic()

    while True:
        events = sel.select(timeout=1.0)
        now = time.monotonic()

        if now - last_cleanup > 2.0:
            cleanup_cache(cache, now)
            last_cleanup = now

        for key, _ in events:
            src_listener: Listener = key.data
            try:
                payload, src_addr = src_listener.sock.recvfrom(args.bufsize)
            except BlockingIOError:
                continue
            except OSError as exc:
                eprint(f"recv error on {src_listener.iface}/{src_listener.cfg.service}/ipv{src_listener.cfg.family}: {exc}")
                continue

            fp = fingerprint(src_listener.cfg, payload)
            if fp in cache and cache[fp] > now:
                continue
            cache[fp] = now + dedupe_ttl

            fwd_count = 0
            for dst in listeners:
                if dst.iface == src_listener.iface:
                    continue
                if dst.cfg != src_listener.cfg:
                    continue
                try:
                    send_to_listener(dst, payload)
                    fwd_count += 1
                except OSError as exc:
                    eprint(
                        f"send error {src_listener.iface}->{dst.iface} {dst.cfg.service}/ipv{dst.cfg.family}: {exc}"
                    )

            if not args.quiet:
                src_repr = src_addr[0] if isinstance(src_addr, tuple) and src_addr else str(src_addr)
                print(
                    f"{src_listener.cfg.service}/ipv{src_listener.cfg.family} "
                    f"{src_listener.iface} <= {src_repr} len={len(payload)} forwarded={fwd_count}"
                )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nExiting")
        raise SystemExit(0)
