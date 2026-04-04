#!/usr/bin/env python3
"""
network_latency_check.py - Per-hop packet loss and TCP port latency checker.

Performs two measurements against a target hostname/IP and port:
  1. Per-hop packet loss via TCP-based traceroute probes (or system
     traceroute when TCP raw sockets are unavailable).
  2. TCP three-way-handshake (connect) latency to the destination port.

Cross-platform: works on Linux, macOS, and Windows.

When elevated privileges are available (root / Administrator), the script
uses raw TCP SYN packets with incrementing TTL values for per-hop loss.
Without privileges it falls back to system traceroute tools (traceroute
on Unix, tracert + per-hop ping on Windows).  TCP connect latency is
always measured with standard sockets regardless of privilege level.

Usage examples:
    python network_latency_check.py google.com 443
    sudo python network_latency_check.py -c 20 10.0.0.1 80
    python network_latency_check.py -l /var/log example.com 8080
"""

import argparse
import datetime
import math
import os
import platform
import random
import re
import select
import socket
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TextIO


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class HopResult:
    """Aggregated results for a single traceroute hop or TCP latency test."""

    hop_number: int
    ip_address: Optional[str] = None
    hostname: Optional[str] = None
    sent: int = 0
    received: int = 0
    # Per-probe round-trip times in milliseconds; None means the probe
    # timed out or was otherwise lost.
    rtts: List[Optional[float]] = field(default_factory=list)

    @property
    def loss_percent(self) -> float:
        if self.sent == 0:
            return 100.0
        return ((self.sent - self.received) / self.sent) * 100.0

    @property
    def min_rtt(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return min(valid) if valid else None

    @property
    def avg_rtt(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return sum(valid) / len(valid) if valid else None

    @property
    def max_rtt(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        return max(valid) if valid else None

    @property
    def stddev_rtt(self) -> Optional[float]:
        valid = [r for r in self.rtts if r is not None]
        if len(valid) < 2:
            return None
        avg = sum(valid) / len(valid)
        variance = sum((x - avg) ** 2 for x in valid) / (len(valid) - 1)
        return math.sqrt(variance)


# ---------------------------------------------------------------------------
# Dual-output writer (console + optional log file)
# ---------------------------------------------------------------------------

class DualOutput:
    """Writes every line to stdout and, optionally, to a log file."""

    def __init__(self, log_file: Optional[TextIO] = None):
        self._log = log_file

    def write(self, text: str) -> None:
        sys.stdout.write(text)
        sys.stdout.flush()
        if self._log:
            self._log.write(text)
            self._log.flush()

    def writeln(self, text: str = "") -> None:
        self.write(text + "\n")


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def resolve_host_ipv4(hostname: str) -> str:
    """Resolve *hostname* to an IPv4 address string.

    Uses ``socket.getaddrinfo`` with ``AF_INET`` to ensure only IPv4
    results are returned.  Exits with an error message on failure.
    """
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET,
                                   socket.SOCK_STREAM)
        if not infos:
            raise socket.gaierror("no IPv4 address found")
        return infos[0][4][0]
    except socket.gaierror as exc:
        sys.exit(f"Error: cannot resolve '{hostname}' to an IPv4 address: {exc}")


def get_local_ip(dst_ip: str) -> str:
    """Return the local IPv4 address the OS would use to reach *dst_ip*.

    Creates an unconnected UDP socket and calls ``connect`` which,
    without sending data, causes the kernel to select an outgoing
    interface.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dst_ip, 80))
        return s.getsockname()[0]
    except OSError:
        return "0.0.0.0"
    finally:
        s.close()


def can_use_raw_sockets() -> bool:
    """Return True if the process can create raw ICMP and TCP sockets.

    Windows restricts raw TCP sockets even for administrators, so we
    always return False there and rely on system tools instead.
    """
    if platform.system() == "Windows":
        return False
    try:
        s1 = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                           socket.IPPROTO_ICMP)
        s1.close()
        s2 = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                           socket.IPPROTO_TCP)
        s2.close()
        return True
    except (PermissionError, OSError):
        return False


def reverse_dns(ip: str) -> str:
    """Attempt a reverse-DNS lookup; return the IP unchanged on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ip


# ---------------------------------------------------------------------------
# Internet checksum (RFC 1071)
# ---------------------------------------------------------------------------

def inet_checksum(data: bytes) -> int:
    """Compute the ones-complement checksum used by TCP, UDP, and ICMP.

    The input bytes are treated as a sequence of 16-bit big-endian words.
    An odd trailing byte is padded with a zero byte before summing.  The
    return value is the 16-bit ones-complement of the sum.
    """
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    # Fold 32-bit accumulator into 16 bits
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


# ---------------------------------------------------------------------------
# TCP SYN packet construction
# ---------------------------------------------------------------------------

def build_tcp_syn(src_ip: str, src_port: int,
                  dst_ip: str, dst_port: int,
                  seq_num: int) -> bytes:
    """Build a minimal TCP SYN segment (no IP header, no TCP options).

    The kernel fills in the IP header when sending via a raw TCP socket
    (unless IP_HDRINCL is set, which we do not use).

    Returns the 20-byte TCP header with the correct checksum.
    """
    data_offset = 5                     # 5 × 4 = 20 bytes (no options)
    offset_and_reserved = data_offset << 4
    syn_flag = 0x02
    window = 65535

    # First pass: header with checksum field set to zero
    tcp_hdr = struct.pack(
        "!HHIIBBHHH",
        src_port,              # source port
        dst_port,              # destination port
        seq_num,               # sequence number
        0,                     # acknowledgment number
        offset_and_reserved,   # data offset + reserved bits
        syn_flag,              # flags (SYN)
        window,                # window size
        0,                     # checksum (placeholder)
        0,                     # urgent pointer
    )

    # Pseudo-header required for TCP checksum (RFC 793 §3.1)
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0,                     # reserved
        socket.IPPROTO_TCP,
        len(tcp_hdr),          # TCP segment length
    )

    chk = inet_checksum(pseudo + tcp_hdr)

    # Second pass: rebuild with the computed checksum
    tcp_hdr = struct.pack(
        "!HHIIBBH",
        src_port, dst_port, seq_num, 0,
        offset_and_reserved, syn_flag, window,
    ) + struct.pack("!H", chk) + struct.pack("!H", 0)

    return tcp_hdr


# ---------------------------------------------------------------------------
# Raw-socket TCP SYN traceroute (privileged)
# ---------------------------------------------------------------------------

def _drain_socket(sock: socket.socket) -> None:
    """Read and discard all pending datagrams from a non-blocking socket."""
    while True:
        try:
            sock.recvfrom(4096)
        except (BlockingIOError, OSError):
            return


def _match_icmp_time_exceeded(
    data: bytes, expected_src_port: int, expected_dst_port: int,
) -> bool:
    """Return True if *data* is an ICMP Time Exceeded message whose
    embedded original TCP segment matches our expected ports.

    Layout of an ICMP Time Exceeded datagram received on a raw socket:
        [outer IP header (variable)] [ICMP hdr 8 B] [original IP hdr] [≥8 B of original payload]

    The outer IP header is included by the kernel on raw ICMP sockets.
    """
    if len(data) < 36:
        return False

    outer_ihl = (data[0] & 0x0F) * 4
    icmp_offset = outer_ihl

    # ICMP type 11 = Time Exceeded, code 0 = TTL expired in transit
    if data[icmp_offset] != 11 or data[icmp_offset + 1] != 0:
        return False

    # The ICMP header is 8 bytes; immediately after it comes the
    # original (our) IP header and at least the first 8 bytes of the
    # original TCP segment.
    orig_ip_offset = icmp_offset + 8
    if len(data) < orig_ip_offset + 20:
        return False

    orig_ihl = (data[orig_ip_offset] & 0x0F) * 4
    tcp_offset = orig_ip_offset + orig_ihl
    if len(data) < tcp_offset + 4:
        return False

    emb_src = struct.unpack("!H", data[tcp_offset:tcp_offset + 2])[0]
    emb_dst = struct.unpack("!H", data[tcp_offset + 2:tcp_offset + 4])[0]
    return emb_src == expected_src_port and emb_dst == expected_dst_port


def _match_icmp_dest_unreachable(
    data: bytes, expected_src_port: int, expected_dst_port: int,
) -> bool:
    """Return True if *data* is an ICMP Destination Unreachable whose
    embedded TCP ports match ours.  Used to detect firewalled or
    closed destinations.
    """
    if len(data) < 36:
        return False

    outer_ihl = (data[0] & 0x0F) * 4
    icmp_offset = outer_ihl

    if data[icmp_offset] != 3:          # type 3 = Destination Unreachable
        return False

    orig_ip_offset = icmp_offset + 8
    if len(data) < orig_ip_offset + 20:
        return False

    orig_ihl = (data[orig_ip_offset] & 0x0F) * 4
    tcp_offset = orig_ip_offset + orig_ihl
    if len(data) < tcp_offset + 4:
        return False

    emb_src = struct.unpack("!H", data[tcp_offset:tcp_offset + 2])[0]
    emb_dst = struct.unpack("!H", data[tcp_offset + 2:tcp_offset + 4])[0]
    return emb_src == expected_src_port and emb_dst == expected_dst_port


def _match_tcp_response(
    data: bytes, expected_src_port: int, expected_dst_port: int,
) -> bool:
    """Return True if *data* (from a raw TCP socket) is a TCP segment
    whose source/dest ports indicate it is a reply to our SYN probe
    (SYN-ACK or RST).
    """
    if len(data) < 24:
        return False
    ihl = (data[0] & 0x0F) * 4
    if len(data) < ihl + 4:
        return False
    resp_src = struct.unpack("!H", data[ihl:ihl + 2])[0]
    resp_dst = struct.unpack("!H", data[ihl + 2:ihl + 4])[0]
    return resp_src == expected_dst_port and resp_dst == expected_src_port


def raw_tcp_traceroute(
    dst_ip: str,
    dst_port: int,
    count: int,
    max_hops: int,
    timeout: float,
    out: DualOutput,
) -> List[HopResult]:
    """Per-hop packet-loss measurement using raw TCP SYN probes.

    For each TTL from 1 to *max_hops* the function sends *count* TCP
    SYN packets destined for *dst_ip*:*dst_port*.  Intermediate routers
    decrement the TTL and, when it reaches zero, reply with an ICMP
    Time Exceeded message — revealing the router's IP and giving us an
    RTT sample.  The destination itself replies with a TCP SYN-ACK (port
    open) or RST (port closed), which also yields an RTT sample.

    Returns a list of ``HopResult`` objects, one per TTL probed.

    Requires root / CAP_NET_RAW on Linux, or root on macOS.
    """
    src_ip = get_local_ip(dst_ip)
    results: List[HopResult] = []

    # Persistent sockets reused across all probes
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                             socket.IPPROTO_TCP)
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                              socket.IPPROTO_ICMP)
    tcp_sock.setblocking(False)
    icmp_sock.setblocking(False)

    # Increase receive buffer to cope with background traffic
    for s in (tcp_sock, icmp_sock):
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        except OSError:
            pass

    try:
        for ttl in range(1, max_hops + 1):
            hop = HopResult(hop_number=ttl, sent=count)
            ip_votes: Dict[str, int] = {}
            destination_reached = False

            for probe_idx in range(count):
                src_port = random.randint(32768, 60999)
                seq_num = random.randint(0, 0xFFFFFFFF)

                tcp_sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                syn = build_tcp_syn(src_ip, src_port, dst_ip, dst_port,
                                    seq_num)

                # Throw away stale data that arrived between probes
                _drain_socket(icmp_sock)
                _drain_socket(tcp_sock)

                send_time = time.perf_counter()
                try:
                    tcp_sock.sendto(syn, (dst_ip, 0))
                except OSError:
                    hop.rtts.append(None)
                    continue

                matched = False
                deadline = send_time + timeout

                while not matched:
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0:
                        break

                    try:
                        readable, _, _ = select.select(
                            [icmp_sock, tcp_sock], [], [],
                            min(remaining, 0.05))
                    except (ValueError, OSError):
                        break

                    if not readable:
                        continue

                    for sock in readable:
                        # Drain everything available on this socket so we
                        # don't miss our packet in the next select round.
                        while True:
                            try:
                                data, addr = sock.recvfrom(4096)
                            except (BlockingIOError, OSError):
                                break

                            if matched:
                                continue  # keep draining but ignore

                            recv_time = time.perf_counter()

                            if sock is icmp_sock:
                                if _match_icmp_time_exceeded(
                                        data, src_port, dst_port):
                                    rtt = (recv_time - send_time) * 1000.0
                                    hop_ip = addr[0]
                                    ip_votes[hop_ip] = \
                                        ip_votes.get(hop_ip, 0) + 1
                                    hop.rtts.append(rtt)
                                    hop.received += 1
                                    matched = True
                                elif _match_icmp_dest_unreachable(
                                        data, src_port, dst_port):
                                    rtt = (recv_time - send_time) * 1000.0
                                    hop_ip = addr[0]
                                    ip_votes[hop_ip] = \
                                        ip_votes.get(hop_ip, 0) + 1
                                    hop.rtts.append(rtt)
                                    hop.received += 1
                                    matched = True
                                    destination_reached = True

                            elif sock is tcp_sock:
                                if _match_tcp_response(
                                        data, src_port, dst_port):
                                    rtt = (recv_time - send_time) * 1000.0
                                    hop_ip = addr[0]
                                    ip_votes[hop_ip] = \
                                        ip_votes.get(hop_ip, 0) + 1
                                    hop.rtts.append(rtt)
                                    hop.received += 1
                                    matched = True
                                    destination_reached = True

                if not matched:
                    hop.rtts.append(None)

                # Brief pause to avoid flooding the network
                time.sleep(0.05)

            # Pick the most-seen IP as the canonical address for this hop
            if ip_votes:
                hop.ip_address = max(ip_votes, key=ip_votes.get)
                hop.hostname = reverse_dns(hop.ip_address)

            results.append(hop)
            _print_hop_line(hop, out)

            if destination_reached:
                break

    finally:
        tcp_sock.close()
        icmp_sock.close()

    return results


# ---------------------------------------------------------------------------
# System-tool traceroute (unprivileged fallback)
# ---------------------------------------------------------------------------

def system_traceroute(
    dst_ip: str,
    dst_port: int,
    count: int,
    max_hops: int,
    timeout: float,
    out: DualOutput,
) -> List[HopResult]:
    """Per-hop loss via system ``traceroute`` (Unix) or ``tracert`` (Windows)."""
    if platform.system() == "Windows":
        return _windows_traceroute(dst_ip, dst_port, count, max_hops,
                                   timeout, out)
    return _unix_traceroute(dst_ip, dst_port, count, max_hops, timeout, out)


def _unix_traceroute(
    dst_ip: str,
    dst_port: int,
    count: int,
    max_hops: int,
    timeout: float,
    out: DualOutput,
) -> List[HopResult]:
    """Try TCP traceroute first, then fall back to UDP (Linux/macOS).

    On Linux the typical invocation is ``traceroute -T -p PORT``.
    On macOS the built-in traceroute may not support ``-T``; some
    installations accept ``-P TCP -p PORT`` instead.
    """
    wait = str(max(1, int(timeout)))

    # Candidate command lines, tried in order.  The first one that
    # produces output wins.
    candidates = []

    if platform.system() == "Darwin":
        candidates.append({
            "label": "TCP traceroute (macOS -P TCP)",
            "cmd": ["traceroute", "-n", "-P", "TCP",
                    "-p", str(dst_port),
                    "-q", str(count), "-m", str(max_hops),
                    "-w", wait, dst_ip],
        })
    else:
        candidates.append({
            "label": "TCP traceroute (-T)",
            "cmd": ["traceroute", "-T", "-n",
                    "-p", str(dst_port),
                    "-q", str(count), "-m", str(max_hops),
                    "-w", wait, dst_ip],
        })

    candidates.append({
        "label": "UDP traceroute (default)",
        "cmd": ["traceroute", "-n",
                "-q", str(count), "-m", str(max_hops),
                "-w", wait, dst_ip],
    })

    for entry in candidates:
        out.writeln(f"  Attempting: {entry['label']}...")
        try:
            proc = subprocess.run(
                entry["cmd"],
                capture_output=True, text=True,
                timeout=max_hops * count * timeout + 60,
            )
            text = proc.stdout.strip()
            if text:
                out.writeln(f"  Active method: {entry['label']}")
                return _parse_unix_traceroute_output(text, out)
        except FileNotFoundError:
            out.writeln("    'traceroute' not found, trying next...")
        except subprocess.TimeoutExpired:
            out.writeln("    Timed out, trying next...")
        except PermissionError:
            out.writeln("    Permission denied, trying next...")
        except OSError as exc:
            out.writeln(f"    OS error: {exc}, trying next...")

    out.writeln("  Warning: no traceroute tool available.  Per-hop data "
                "will be empty.")
    out.writeln("  Tip: install 'traceroute' or run with elevated "
                "privileges for raw-socket mode.")
    return []


def _parse_unix_traceroute_output(
    raw: str, out: DualOutput,
) -> List[HopResult]:
    """Parse the text output of Unix ``traceroute`` into ``HopResult`` list.

    Expected line format (with ``-n`` flag)::

        <hop>  <ip>  <rtt> ms  <rtt> ms  ...
        <hop>  * * *
        <hop>  <ip1>  <rtt> ms  <ip2>  <rtt> ms  ...   (load-balanced)

    """
    results: List[HopResult] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("traceroute"):
            continue

        match = re.match(r"(\d+)\s+(.*)", line)
        if not match:
            continue

        hop_num = int(match.group(1))
        rest = match.group(2)

        hop = HopResult(hop_number=hop_num)
        ip_seen: Dict[str, int] = {}
        current_ip: Optional[str] = None
        tokens = rest.split()
        i = 0

        while i < len(tokens):
            tok = tokens[i]

            if tok == "*":
                hop.rtts.append(None)
                hop.sent += 1
                i += 1

            elif re.match(r"\d+\.\d+\.\d+\.\d+$", tok):
                current_ip = tok
                ip_seen.setdefault(current_ip, 0)
                i += 1

            elif (re.match(r"[\d.]+$", tok)
                  and i + 1 < len(tokens)
                  and tokens[i + 1] == "ms"):
                rtt = float(tok)
                hop.rtts.append(rtt)
                hop.sent += 1
                hop.received += 1
                if current_ip:
                    ip_seen[current_ip] = ip_seen.get(current_ip, 0) + 1
                i += 2

            elif tok.startswith("!"):
                # ICMP error codes appended by traceroute (e.g. !N, !H)
                i += 1
            else:
                i += 1

        if ip_seen:
            hop.ip_address = max(ip_seen, key=ip_seen.get)
            hop.hostname = reverse_dns(hop.ip_address)

        results.append(hop)
        _print_hop_line(hop, out)

    return results


def _windows_traceroute(
    dst_ip: str,
    dst_port: int,
    count: int,
    max_hops: int,
    timeout: float,
    out: DualOutput,
) -> List[HopResult]:
    """Windows hop discovery via ``tracert`` followed by per-hop ``ping``.

    Windows ``tracert`` only supports ICMP and always sends three probes.
    To honour the user's ``-c`` count we discover hops first, then ping
    each one individually with the requested number of probes.

    Note: probes are ICMP, not TCP.  TCP traceroute on Windows requires
    third-party tools or raw-socket access that is not generally available.
    """
    out.writeln("  Note: Windows lacks built-in TCP traceroute.  Using "
                "ICMP tracert for hop")
    out.writeln("        discovery and per-hop ping for loss measurement.  "
                "TCP latency is")
    out.writeln("        measured separately at the destination.")

    timeout_ms = str(max(1000, int(timeout * 1000)))

    try:
        proc = subprocess.run(
            ["tracert", "-d", "-h", str(max_hops), "-w", timeout_ms,
             dst_ip],
            capture_output=True, text=True,
            timeout=max_hops * 3 * timeout + 60,
        )
    except FileNotFoundError:
        out.writeln("  Error: 'tracert' not found.")
        return []
    except subprocess.TimeoutExpired:
        out.writeln("  Error: tracert timed out.")
        return []

    # Extract hop IPs from tracert output
    hop_ips: Dict[int, str] = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        m = re.match(r"(\d+)\s+", line)
        if not m:
            continue
        hop_n = int(m.group(1))
        ip_m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s*$", line)
        if ip_m:
            hop_ips[hop_n] = ip_m.group(1)

    if not hop_ips:
        out.writeln("  Warning: tracert returned no hops.")
        return []

    results: List[HopResult] = []
    for hop_n in sorted(hop_ips):
        hop = _ping_host_for_loss(hop_ips[hop_n], count, timeout, hop_n)
        results.append(hop)
        _print_hop_line(hop, out)

    return results


def _ping_host_for_loss(
    ip: str, count: int, timeout: float, hop_number: int,
) -> HopResult:
    """Ping *ip* with *count* probes and return a ``HopResult``."""
    hop = HopResult(hop_number=hop_number, ip_address=ip, sent=count)
    hop.hostname = reverse_dns(ip)

    if platform.system() == "Windows":
        timeout_ms = str(max(1000, int(timeout * 1000)))
        cmd = ["ping", "-n", str(count), "-w", timeout_ms, ip]
    else:
        wait = str(max(1, int(timeout)))
        cmd = ["ping", "-c", str(count), "-W", wait, "-i", "0.2", ip]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=count * timeout + 30)

        for line in proc.stdout.splitlines():
            m = re.search(r"time[=<]([\d.]+)\s*ms", line, re.IGNORECASE)
            if m:
                hop.rtts.append(float(m.group(1)))
                hop.received += 1

        # Pad with None for any probes that didn't produce a time= line
        while len(hop.rtts) < count:
            hop.rtts.append(None)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        hop.rtts = [None] * count

    return hop


# ---------------------------------------------------------------------------
# TCP connect latency
# ---------------------------------------------------------------------------

def measure_tcp_latency(
    dst_ip: str,
    dst_port: int,
    count: int,
    timeout: float,
    out: DualOutput,
) -> HopResult:
    """Measure TCP three-way-handshake latency to *dst_ip*:*dst_port*.

    Each probe opens a fresh TCP socket, calls ``connect``, and times
    how long it takes to complete the handshake (SYN → SYN-ACK).

    ``ConnectionRefusedError`` means the host sent RST — the port is
    closed but the host is reachable.  We still record the RTT because
    the round-trip happened successfully.
    """
    result = HopResult(hop_number=0, ip_address=dst_ip, sent=count)
    result.hostname = reverse_dns(dst_ip)

    for i in range(count):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        start = time.perf_counter()
        try:
            sock.connect((dst_ip, dst_port))
            rtt_ms = (time.perf_counter() - start) * 1000.0
            result.rtts.append(rtt_ms)
            result.received += 1

        except ConnectionRefusedError:
            # RST received — host reachable, port closed
            rtt_ms = (time.perf_counter() - start) * 1000.0
            result.rtts.append(rtt_ms)
            result.received += 1

        except socket.timeout:
            result.rtts.append(None)

        except OSError:
            result.rtts.append(None)

        finally:
            try:
                sock.close()
            except OSError:
                pass

        status = f"{rtt_ms:.2f} ms" if result.rtts[-1] is not None \
            else "* (timeout)"
        out.writeln(f"    Probe {i + 1:>{len(str(count))}}/{count}: {status}")

        # Small inter-probe delay to avoid SYN flood triggers
        if i < count - 1:
            time.sleep(0.1)

    return result


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

_SEP_THICK = "=" * 78
_SEP_THIN = "-" * 78
_HOP_HDR = (
    f"  {'Hop':>3}  {'IP Address':<39} {'Loss':>6}  "
    f"{'Sent':>4}  {'Rcvd':>4}  "
    f"{'Min':>7}  {'Avg':>7}  {'Max':>7}"
)


def _print_hop_line(hop: HopResult, out: DualOutput) -> None:
    """Print a single per-hop result line (used for both progress and report)."""
    if hop.ip_address:
        ip_disp = hop.ip_address
        loss = f"{hop.loss_percent:.1f}%"
        mn = f"{hop.min_rtt:.2f}" if hop.min_rtt is not None else "-"
        av = f"{hop.avg_rtt:.2f}" if hop.avg_rtt is not None else "-"
        mx = f"{hop.max_rtt:.2f}" if hop.max_rtt is not None else "-"
    else:
        ip_disp = "*"
        loss = "100.0%"
        mn = av = mx = "-"

    out.writeln(
        f"  {hop.hop_number:>3}  {ip_disp:<39} {loss:>6}  "
        f"{hop.sent:>4}  {hop.received:>4}  "
        f"{mn:>7}  {av:>7}  {mx:>7}"
    )


def print_summary(
    hostname: str,
    dst_ip: str,
    dst_port: int,
    probe_count: int,
    max_hops: int,
    timeout: float,
    method: str,
    hops: List[HopResult],
    tcp: HopResult,
    out: DualOutput,
) -> None:
    """Print the full human-readable summary report."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    out.writeln()
    out.writeln(_SEP_THICK)
    out.writeln("  NETWORK LATENCY & PACKET LOSS REPORT")
    out.writeln(_SEP_THICK)
    out.writeln(f"  Target host   : {hostname} ({dst_ip})")
    out.writeln(f"  Target port   : {dst_port}")
    out.writeln(f"  Date / time   : {now_str}")
    out.writeln(f"  Probes / hop  : {probe_count}")
    out.writeln(f"  Max hops      : {max_hops}")
    out.writeln(f"  Probe timeout : {timeout:.1f}s")
    out.writeln(f"  Trace method  : {method}")
    out.writeln(f"  Platform      : {platform.system()} "
                f"{platform.release()}")
    out.writeln(_SEP_THICK)

    # -- Per-hop table --
    out.writeln()
    out.writeln("  PER-HOP PACKET LOSS AND LATENCY")
    out.writeln(_SEP_THIN)
    out.writeln(_HOP_HDR)
    out.writeln(_SEP_THIN)

    if hops:
        for h in hops:
            _print_hop_line(h, out)
    else:
        out.writeln("  (no traceroute data available)")

    out.writeln(_SEP_THIN)

    # -- Per-hop notes --
    no_response_hops = [h for h in hops
                        if h.received == 0 and h.ip_address is None]
    if no_response_hops:
        out.writeln()
        out.writeln("  Note: hops showing 100% loss with '*' may be routers "
                    "that silently drop")
        out.writeln("  ICMP Time Exceeded replies.  This is common and does "
                    "not necessarily")
        out.writeln("  indicate real packet loss on the path.")

    # -- TCP latency --
    out.writeln()
    out.writeln(f"  TCP CONNECT LATENCY TO {dst_ip}:{dst_port}")
    out.writeln(_SEP_THIN)
    out.writeln(f"  Probes sent       : {tcp.sent}")
    out.writeln(f"  Probes received   : {tcp.received}")
    out.writeln(f"  Packet loss       : {tcp.loss_percent:.1f}%")

    if tcp.min_rtt is not None:
        out.writeln(f"  Min latency       : {tcp.min_rtt:.2f} ms")
        out.writeln(f"  Avg latency       : {tcp.avg_rtt:.2f} ms")
        out.writeln(f"  Max latency       : {tcp.max_rtt:.2f} ms")
        if tcp.stddev_rtt is not None:
            out.writeln(f"  Std deviation     : {tcp.stddev_rtt:.2f} ms")
    else:
        out.writeln("  Latency           : N/A (no successful probes)")

    out.writeln(_SEP_THIN)

    # -- Individual TCP probe breakdown --
    out.writeln()
    out.writeln("  INDIVIDUAL TCP CONNECT PROBES")
    out.writeln(_SEP_THIN)
    for idx, rtt in enumerate(tcp.rtts, 1):
        if rtt is not None:
            out.writeln(f"    Probe {idx:>{len(str(tcp.sent))}}: "
                        f"{rtt:.2f} ms")
        else:
            out.writeln(f"    Probe {idx:>{len(str(tcp.sent))}}: "
                        f"* (timeout / error)")
    out.writeln(_SEP_THIN)

    out.writeln()
    out.writeln(_SEP_THICK)
    out.writeln("  END OF REPORT")
    out.writeln(_SEP_THICK)


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="network_latency_check.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Network Latency & Per-Hop Packet Loss Checker\n"
            "\n"
            "Reports per-hop packet loss using traceroute-style probes and\n"
            "TCP connect latency to a specified hostname/IP and port.\n"
            "\n"
            "Automatically selects the best available probing method based\n"
            "on platform and privilege level:\n"
            "  - Privileged (root/admin): raw TCP SYN traceroute for\n"
            "    accurate TCP-based per-hop loss.\n"
            "  - Unprivileged: system traceroute (UDP/ICMP) for hop\n"
            "    discovery and per-hop loss."
        ),
        epilog=(
            "examples:\n"
            "  %(prog)s google.com 443\n"
            "  %(prog)s -c 20 -l /var/log 10.0.0.1 80\n"
            "  %(prog)s --count 10 --timeout 3 example.com 8080\n"
            "  sudo %(prog)s google.com 443      # best accuracy\n"
            "\n"
            "notes:\n"
            "  - Uses IPv4 only.\n"
            "  - Elevated privileges enable raw TCP SYN traceroute.\n"
            "  - Without privileges, falls back to system traceroute;\n"
            "    probes may be UDP/ICMP rather than TCP.\n"
            "  - TCP connect latency to the destination port is always\n"
            "    measured regardless of privilege level.\n"
            "  - Hops showing 100%% loss with '*' may simply be routers\n"
            "    that suppress ICMP Time Exceeded replies."
        ),
    )

    parser.add_argument(
        "host",
        help="target hostname or IPv4 address",
    )
    parser.add_argument(
        "port",
        type=int,
        help="target TCP port (1-65535)",
    )
    parser.add_argument(
        "-c", "--count",
        type=int, default=15, metavar="N",
        help="number of probes per hop (default: 15)",
    )
    parser.add_argument(
        "-l", "--log",
        metavar="DIR",
        help="write results to a timestamped log file in DIR",
    )
    parser.add_argument(
        "-m", "--max-hops",
        type=int, default=30, metavar="N",
        help="maximum TTL / hop count (default: 30)",
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float, default=2.0, metavar="SEC",
        help="per-probe timeout in seconds (default: 2.0)",
    )

    args = parser.parse_args()

    # --- validation ---
    if not 1 <= args.port <= 65535:
        parser.error(f"port must be 1-65535 (got {args.port})")
    if args.count < 1:
        parser.error(f"count must be >= 1 (got {args.count})")
    if not 1 <= args.max_hops <= 255:
        parser.error(f"max-hops must be 1-255 (got {args.max_hops})")
    if args.timeout <= 0:
        parser.error(f"timeout must be > 0 (got {args.timeout})")
    if args.log and not os.path.isdir(args.log):
        parser.error(f"log directory does not exist: {args.log}")

    return args


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()

    # -- open optional log file --
    log_file: Optional[TextIO] = None
    log_path: Optional[str] = None

    if args.log:
        ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        log_path = os.path.join(args.log, f"latency_check.{ts}.log")
        try:
            log_file = open(log_path, "w", encoding="utf-8")
        except OSError as exc:
            sys.exit(f"Error: cannot create log file '{log_path}': {exc}")

    out = DualOutput(log_file)

    try:
        out.writeln(_SEP_THICK)
        out.writeln("  Network Latency & Packet Loss Check")
        out.writeln(_SEP_THICK)
        out.writeln()

        # -- DNS resolution --
        out.writeln(f"  Resolving '{args.host}' ...")
        dst_ip = resolve_host_ipv4(args.host)
        out.writeln(f"  Resolved : {dst_ip} (IPv4)")
        out.writeln()

        # -- choose probing method --
        use_raw = can_use_raw_sockets()

        if use_raw:
            method = "Raw TCP SYN traceroute (privileged)"
            out.writeln("  Elevated privileges detected — using raw TCP SYN "
                        "traceroute.")
        else:
            method = "System traceroute (unprivileged)"
            out.writeln("  Running without elevated privileges — using "
                        "system traceroute tools.")
            out.writeln("  Tip: run with sudo / admin for raw TCP SYN "
                        "traceroute accuracy.")
        out.writeln()

        # ---------------------------------------------------------------
        # Phase 1: per-hop traceroute
        # ---------------------------------------------------------------
        out.writeln(f"  Phase 1: per-hop traceroute to "
                    f"{dst_ip}:{args.port}")
        out.writeln(_SEP_THIN)
        out.writeln(_HOP_HDR)
        out.writeln(_SEP_THIN)

        if use_raw:
            try:
                hop_results = raw_tcp_traceroute(
                    dst_ip, args.port, args.count,
                    args.max_hops, args.timeout, out)
            except (PermissionError, OSError) as exc:
                out.writeln(f"  Raw sockets failed ({exc}); falling "
                            f"back to system tools.")
                hop_results = system_traceroute(
                    dst_ip, args.port, args.count,
                    args.max_hops, args.timeout, out)
                method = "System traceroute (fallback)"
        else:
            hop_results = system_traceroute(
                dst_ip, args.port, args.count,
                args.max_hops, args.timeout, out)

        out.writeln(_SEP_THIN)
        out.writeln()

        # ---------------------------------------------------------------
        # Phase 2: TCP connect latency
        # ---------------------------------------------------------------
        out.writeln(f"  Phase 2: TCP connect latency to "
                    f"{dst_ip}:{args.port}")
        out.writeln(_SEP_THIN)

        tcp_result = measure_tcp_latency(
            dst_ip, args.port, args.count, args.timeout, out)

        out.writeln(_SEP_THIN)
        out.writeln()

        # ---------------------------------------------------------------
        # Summary report
        # ---------------------------------------------------------------
        print_summary(
            args.host, dst_ip, args.port,
            args.count, args.max_hops, args.timeout,
            method, hop_results, tcp_result, out)

        if log_path:
            out.writeln(f"\n  Log saved to: {log_path}")

    finally:
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
