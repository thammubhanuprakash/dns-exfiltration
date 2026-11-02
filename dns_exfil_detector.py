#!/usr/bin/env python3
"""
DNS-ExfilWatch - DNS Tunneling Detection & Active Defense Tool

Usage examples:
    sudo python3 dns_exfilwatch.py -i eth0                      # monitor only
    sudo python3 dns_exfilwatch.py -i eth0 --auto-block         # block offenders
    python3 dns_exfilwatch.py --pcap capture.pcap --no-dashboard  # offline replay
    python3 dns_exfilwatch.py --history 50                      # show logged threats

Only use on networks you own or are authorised to monitor.
"""

from __future__ import annotations

import argparse
import ipaddress
import math
import os
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Deque, Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from scapy.all import AsyncSniffer, conf, get_if_addr, get_if_list, sniff
from scapy.layers.dns import DNS, DNSQR, dnsqtypes
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6

# =============================================================================
# analyzer - Detection Engine
# =============================================================================


class RiskLevel(Enum):
    NORMAL = "Normal"
    WARNING = "Warning"
    EXFILTRATION = "Exfiltration"


@dataclass
class Thresholds:
    entropy: float = 3.8      # entropy (bits/char) considered "high"
    label_length: int = 35    # label length considered "long"
    warning: float = 35.0     # composite score for Warning
    exfil: float = 60.0       # composite score for Exfiltration


@dataclass
class AnalysisResult:
    """Result of analyzing a single DNS query."""
    timestamp: float
    source_ip: str
    destination_ip: str
    domain: str
    record_type: str
    entropy: float
    label_lengths: List[int]
    total_domain_length: int
    max_label_length: int
    subdomain_depth: int
    risk_score: float
    risk_level: RiskLevel
    action_taken: str = "Logged"
    details: Dict = field(default_factory=dict)


# Suffixes that are legitimately high-entropy. Edit or extend with --allowlist.
# Note: allowlisting a large shared platform also lets an attacker hide there.
DEFAULT_ALLOWLIST = [
    "in-addr.arpa", "ip6.arpa", "local", "localhost",
    "cloudfront.net", "akamaiedge.net", "akamai.net", "edgekey.net",
    "googleusercontent.com", "1e100.net", "gstatic.com", "windowsupdate.com",
]

# Common two-label public suffixes (small built-in list; no external deps).
MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "co.jp", "com.br", "co.nz", "co.za", "com.cn",
}

# Record types often abused by tunnels (score 0-100).
RECORD_TYPE_SCORES = {
    "TXT": 100.0, "NULL": 100.0, "CNAME": 60.0, "ANY": 60.0,
    "MX": 40.0, "AAAA": 15.0, "PTR": 15.0,
}


def calculate_shannon_entropy(data: str) -> float:
    """H(X) = -sum(P(x) * log2(P(x)))"""
    if not data:
        return 0.0
    length = len(data)
    freq: Dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def split_domain(domain: str) -> Tuple[str, str]:
    """Return (subdomain_part, registered_domain). subdomain_part may be ''."""
    labels = domain.lower().split(".")
    suffix_len = 2 if ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES else 1
    reg_len = suffix_len + 1
    if len(labels) <= reg_len:
        return "", domain.lower()
    return ".".join(labels[:-reg_len]), ".".join(labels[-reg_len:])


def is_allowlisted(domain: str, allowlist: List[str]) -> bool:
    d = domain.lower()
    return any(d == s or d.endswith("." + s) for s in allowlist)


def extract_query(packet) -> Optional[Tuple[str, str]]:
    """Return (domain, record_type) for the first question in a DNS packet."""
    if not packet.haslayer(DNSQR):
        return None
    q = packet[DNSQR]
    qname = q.qname
    if isinstance(qname, bytes):
        qname = qname.decode("utf-8", errors="ignore")
    domain = str(qname).rstrip(".")
    record_type = dnsqtypes.get(q.qtype, str(q.qtype))
    return domain, record_type


def analyze_domain(domain: str, th: Thresholds) -> Dict:
    """Compute metrics and 0-100 component scores for a domain name."""
    if not domain:
        return {
            "entropy": 0.0, "label_lengths": [], "total_domain_length": 0,
            "max_label_length": 0, "subdomain_depth": 0, "entropy_score": 0.0,
            "length_score": 0.0, "depth_score": 0.0,
            "subdomain": "", "registered_domain": "",
        }

    labels = domain.split(".")
    label_lengths = [len(label) for label in labels]
    total_len = len(domain)
    max_label = max(label_lengths)
    depth = len(labels)

    sub, registered = split_domain(domain)

    # Entropy over the concatenated subdomain data (lowercased: resolvers using
    # 0x20 case randomisation would otherwise look random).
    payload = sub.replace(".", "")
    entropy = calculate_shannon_entropy(payload)

    # Short payloads can't reach high entropy, so scale their weight by length.
    length_weight = min(1.0, len(payload) / 16.0)
    entropy_score = min(100.0, (entropy * length_weight / th.entropy) * 100.0)

    length_score = 0.0
    if max_label > th.label_length:
        length_score += min(60.0, (max_label - th.label_length) * 3.0)
    if total_len > 60:
        length_score += min(40.0, (total_len - 60) * 1.0)
    length_score = min(100.0, length_score)

    depth_score = min(100.0, (depth - 3) * 25.0) if depth > 3 else 0.0

    return {
        "entropy": entropy,
        "label_lengths": label_lengths,
        "total_domain_length": total_len,
        "max_label_length": max_label,
        "subdomain_depth": depth,
        "entropy_score": entropy_score,
        "length_score": length_score,
        "depth_score": depth_score,
        "subdomain": sub,
        "registered_domain": registered,
    }


def calculate_risk_score(analysis: Dict, record_type: str, query_frequency: int,
                         unique_subdomains: int, th: Thresholds) -> Tuple[float, RiskLevel]:
    """Composite 0-100 score plus a hard rule for the obvious case."""
    entropy_score = analysis["entropy_score"]
    length_score = analysis["length_score"]
    depth_score = analysis["depth_score"]
    type_score = RECORD_TYPE_SCORES.get(record_type, 0.0)
    freq_score = min(100.0, max(0, query_frequency - 10) * 10.0)
    unique_score = min(100.0, max(0, unique_subdomains - 5) * 10.0)

    # Weights: entropy 40, length 25, type 15, frequency 10, depth 5, unique 5
    score = (
        entropy_score * 0.40 +
        length_score * 0.25 +
        type_score * 0.15 +
        freq_score * 0.10 +
        depth_score * 0.05 +
        unique_score * 0.05
    )

    # Hard rule: high entropy AND a long label is exfiltration on its own.
    if (analysis["entropy"] >= th.entropy
            and analysis["max_label_length"] >= th.label_length):
        score = max(score, th.exfil)

    score = max(0.0, min(100.0, score))

    if score >= th.exfil:
        level = RiskLevel.EXFILTRATION
    elif score >= th.warning:
        level = RiskLevel.WARNING
    else:
        level = RiskLevel.NORMAL
    return score, level


class DomainAnalyzer:
    """Tracks per-source query rates and analyses DNS query packets."""

    def __init__(self, thresholds: Thresholds, allowlist: Optional[List[str]] = None,
                 frequency_window: int = 10):
        self.th = thresholds
        self.allowlist = [a.lower().strip(".") for a in (allowlist or [])]
        self.window = frequency_window
        self.query_history: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=100))
        self.unique_history: Dict[Tuple[str, str], Deque[Tuple[float, str]]] = \
            defaultdict(lambda: deque(maxlen=200))
        self.lock = threading.Lock()
        self._calls = 0

    def record_query(self, src: str, registered: str, sub: str) -> Tuple[int, int]:
        """Return (queries from src in window, unique subdomains for src+domain in window)."""
        now = time.time()
        with self.lock:
            hist = self.query_history[src]
            hist.append(now)
            recent = sum(1 for t in hist if now - t < self.window)

            unique = 0
            if sub:
                uh = self.unique_history[(src, registered)]
                uh.append((now, sub))
                unique = len({s for t, s in uh if now - t < self.window})

            self._calls += 1
            if self._calls % 2000 == 0:
                self._prune(now)
            return recent, unique

    def _prune(self, now: float) -> None:
        """Drop idle sources so memory doesn't grow forever (lock held)."""
        cutoff = max(60.0, self.window * 6)
        for key in [k for k, h in self.query_history.items() if not h or now - h[-1] > cutoff]:
            del self.query_history[key]
        for key in [k for k, h in self.unique_history.items() if not h or now - h[-1][0] > cutoff]:
            del self.unique_history[key]

    def analyze_packet(self, packet) -> Optional[AnalysisResult]:
        if not packet.haslayer(DNS):
            return None
        parsed = extract_query(packet)
        if not parsed:
            return None
        domain, record_type = parsed
        if not domain:
            return None

        if packet.haslayer(IP):
            src, dst = packet[IP].src, packet[IP].dst
        elif packet.haslayer(IPv6):
            src, dst = packet[IPv6].src, packet[IPv6].dst
        else:
            src, dst = "unknown", "unknown"

        analysis = analyze_domain(domain, self.th)

        if is_allowlisted(domain, self.allowlist):
            analysis["allowlisted"] = True
            return AnalysisResult(
                timestamp=time.time(), source_ip=src, destination_ip=dst,
                domain=domain, record_type=record_type, entropy=analysis["entropy"],
                label_lengths=analysis["label_lengths"],
                total_domain_length=analysis["total_domain_length"],
                max_label_length=analysis["max_label_length"],
                subdomain_depth=analysis["subdomain_depth"],
                risk_score=0.0, risk_level=RiskLevel.NORMAL,
                action_taken="Allowlisted", details=analysis,
            )

        freq, unique = self.record_query(src, analysis["registered_domain"], analysis["subdomain"])
        score, level = calculate_risk_score(analysis, record_type, freq, unique, self.th)
        analysis["query_frequency"] = freq
        analysis["unique_subdomains"] = unique

        return AnalysisResult(
            timestamp=time.time(), source_ip=src, destination_ip=dst,
            domain=domain, record_type=record_type, entropy=analysis["entropy"],
            label_lengths=analysis["label_lengths"],
            total_domain_length=analysis["total_domain_length"],
            max_label_length=analysis["max_label_length"],
            subdomain_depth=analysis["subdomain_depth"],
            risk_score=score, risk_level=level, action_taken="Logged", details=analysis,
        )


# =============================================================================
# firewall - iptables management
# =============================================================================


class FirewallManager:
    """
    Blocks offending source IPs in a dedicated iptables chain.

    Safety features: chain is only created when auto_block is on, a never-block
    list protects loopback/own IPs/gateway/resolvers, blocks expire after a TTL,
    and every IP is validated before reaching iptables.
    """

    CHAIN = "DNS_EXFIL_WATCH"
    HOOKS = ("INPUT", "FORWARD")

    def __init__(self, auto_block: bool = False, interface: Optional[str] = None,
                 block_ttl: int = 600, never_block: Optional[List[str]] = None):
        self.auto_block = auto_block
        self.block_ttl = block_ttl
        self.blocked: Dict[str, float] = {}          # ip -> expiry (0 = permanent)
        self.lock = threading.RLock()                # re-entrant: flush -> unblock
        self.events: Deque[str] = deque(maxlen=20)
        self._ready: Dict[str, bool] = {}
        self._stop = threading.Event()
        self._reaper: Optional[threading.Thread] = None
        self.protected = self._build_protected(interface, never_block or [])

        if self.auto_block:
            for binary in ("iptables", "ip6tables"):
                self._ready[binary] = self._ensure_chain(binary)
            if not any(self._ready.values()):
                self._log("iptables unavailable - auto-block disabled")
                self.auto_block = False
            else:
                self._reaper = threading.Thread(target=self._reap_loop, daemon=True)
                self._reaper.start()

    # -- helpers -------------------------------------------------------------

    def _log(self, msg: str) -> None:
        self.events.append(f"{datetime.now():%H:%M:%S} {msg}")

    @staticmethod
    def _run(args: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(args, capture_output=True, text=True, timeout=5)

    @staticmethod
    def _build_protected(interface: Optional[str], extra: List[str]):
        nets = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
        candidates: List[str] = list(extra)
        try:
            if interface:
                candidates.append(get_if_addr(interface))
        except Exception:
            pass
        try:
            candidates.append(conf.route.route("0.0.0.0")[2])   # default gateway
        except Exception:
            pass
        try:
            with open("/etc/resolv.conf") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        candidates.append(parts[1].split("%")[0])
        except OSError:
            pass
        for c in candidates:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                continue
        return nets

    def is_protected(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_link_local:
            return True
        return any(addr in net for net in self.protected if net.version == addr.version)

    def _ensure_chain(self, binary: str) -> bool:
        try:
            if self._run([binary, "-w", "-n", "-L", self.CHAIN]).returncode != 0:
                if self._run([binary, "-w", "-N", self.CHAIN]).returncode != 0:
                    return False
            for hook in self.HOOKS:
                # -I ... 1 so earlier ACCEPT rules can't shadow the chain
                if self._run([binary, "-w", "-C", hook, "-j", self.CHAIN]).returncode != 0:
                    self._run([binary, "-w", "-I", hook, "1", "-j", self.CHAIN])
            return True
        except Exception as exc:
            self._log(f"{binary} setup failed: {exc}")
            return False

    @staticmethod
    def _binary_for(ip: str) -> str:
        return "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"

    # -- public API ----------------------------------------------------------

    def block_ip(self, ip: str) -> str:
        """Returns one of: disabled, invalid, protected, already, blocked, failed."""
        if not self.auto_block:
            return "disabled"
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return "invalid"
        if self.is_protected(ip):
            self._log(f"skip {ip} (protected)")
            return "protected"
        binary = self._binary_for(ip)
        if not self._ready.get(binary):
            return "failed"
        with self.lock:
            if ip in self.blocked:
                return "already"
            try:
                res = self._run([binary, "-w", "-A", self.CHAIN, "-s", ip, "-j", "DROP"])
            except Exception as exc:
                self._log(f"block {ip} error: {exc}")
                return "failed"
            if res.returncode != 0:
                self._log(f"block {ip} failed: {res.stderr.strip()[:60]}")
                return "failed"
            self.blocked[ip] = time.time() + self.block_ttl if self.block_ttl > 0 else 0.0
            self._log(f"BLOCKED {ip}")
            return "blocked"

    def unblock_ip(self, ip: str) -> bool:
        with self.lock:
            if ip not in self.blocked:
                return False
            try:
                res = self._run([self._binary_for(ip), "-w", "-D", self.CHAIN,
                                 "-s", ip, "-j", "DROP"])
            except Exception as exc:
                self._log(f"unblock {ip} error: {exc}")
                return False
            if res.returncode == 0:
                del self.blocked[ip]
                self._log(f"unblocked {ip}")
                return True
            self._log(f"unblock {ip} failed: {res.stderr.strip()[:60]}")
            return False

    def _reap_loop(self) -> None:
        while not self._stop.wait(2.0):
            now = time.time()
            with self.lock:
                expired = [ip for ip, exp in self.blocked.items() if exp and exp <= now]
            for ip in expired:
                self.unblock_ip(ip)

    def flush_rules(self) -> None:
        with self.lock:
            for ip in list(self.blocked):
                self.unblock_ip(ip)

    def list_blocked(self) -> List[Tuple[str, float]]:
        """[(ip, seconds_remaining)] - remaining is -1 for permanent blocks."""
        now = time.time()
        with self.lock:
            return [(ip, (exp - now) if exp else -1.0) for ip, exp in self.blocked.items()]

    def cleanup(self) -> None:
        self._stop.set()
        if not self._ready:
            return
        self.flush_rules()
        for binary, ready in self._ready.items():
            if not ready:
                continue
            try:
                for hook in self.HOOKS:
                    for _ in range(5):
                        if self._run([binary, "-w", "-D", hook, "-j", self.CHAIN]).returncode != 0:
                            break
                self._run([binary, "-w", "-F", self.CHAIN])
                self._run([binary, "-w", "-X", self.CHAIN])
            except Exception as exc:
                self._log(f"cleanup {binary} failed: {exc}")


# =============================================================================
# logger - SQLite persistence
# =============================================================================


class ThreatLogger:
    """Persistent threat log. By default only Warning and Exfiltration are stored."""

    def __init__(self, path: str, log_all: bool = False):
        self.path = path
        self.log_all = log_all
        self.lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                time_iso TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                domain TEXT,
                record_type TEXT,
                entropy REAL,
                max_label_length INTEGER,
                subdomain_depth INTEGER,
                risk_score REAL,
                risk_level TEXT,
                action_taken TEXT
            )""")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_ts ON threats(ts)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_src ON threats(source_ip)")
        self.conn.commit()

    def should_log(self, result: AnalysisResult) -> bool:
        return self.log_all or result.risk_level != RiskLevel.NORMAL

    def log(self, r: AnalysisResult) -> None:
        if not self.should_log(r):
            return
        with self.lock:
            self.conn.execute(
                "INSERT INTO threats (ts,time_iso,source_ip,destination_ip,domain,record_type,"
                "entropy,max_label_length,subdomain_depth,risk_score,risk_level,action_taken) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (r.timestamp, datetime.fromtimestamp(r.timestamp).isoformat(timespec="seconds"),
                 r.source_ip, r.destination_ip, r.domain, r.record_type, r.entropy,
                 r.max_label_length, r.subdomain_depth, r.risk_score,
                 r.risk_level.value, r.action_taken),
            )
            self.conn.commit()

    def recent(self, limit: int = 50) -> List[tuple]:
        with self.lock:
            cur = self.conn.execute(
                "SELECT time_iso,source_ip,domain,record_type,entropy,risk_score,risk_level,"
                "action_taken FROM threats ORDER BY id DESC LIMIT ?", (limit,))
            return cur.fetchall()

    def close(self) -> None:
        with self.lock:
            try:
                self.conn.commit()
                self.conn.close()
            except sqlite3.Error:
                pass


# =============================================================================
# sniffer - packet capture
# =============================================================================


class ResultBuffer:
    """Thread-safe bounded buffer of recent results for the dashboard."""

    def __init__(self, maxlen: int = 200):
        self._d: Deque[AnalysisResult] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def append(self, item: AnalysisResult) -> None:
        with self._lock:
            self._d.append(item)

    def snapshot(self, n: int) -> List[AnalysisResult]:
        with self._lock:
            return list(self._d)[-n:]


def new_stats() -> Dict:
    return {
        "total_packets": 0, "warnings": 0, "malicious_packets": 0,
        "total_quarantined": 0, "quarantined_ips": set(), "errors": 0,
        "start_time": time.time(),
    }


class DNSSniffer:
    """Captures DNS queries (UDP/TCP port 53), analyses and reacts to them."""

    def __init__(self, interface: Optional[str], pcap: Optional[str],
                 analyzer: DomainAnalyzer, firewall: FirewallManager,
                 logger: Optional[ThreatLogger], buffer: ResultBuffer,
                 stats: Dict, stats_lock: threading.Lock,
                 on_result: Optional[Callable[[AnalysisResult], None]] = None):
        self.interface = interface
        self.pcap = pcap
        self.analyzer = analyzer
        self.firewall = firewall
        self.logger = logger
        self.buffer = buffer
        self.stats = stats
        self.stats_lock = stats_lock
        self.on_result = on_result
        self.running = False
        self.finished = False
        self._async: Optional[AsyncSniffer] = None
        self._thread: Optional[threading.Thread] = None

    def _packet_callback(self, packet) -> None:
        if not self.running:
            return
        try:
            self._handle(packet)
        except Exception:
            with self.stats_lock:
                self.stats["errors"] += 1

    def _handle(self, packet) -> None:
        if not packet.haslayer(DNS):
            return
        if packet[DNS].qr != 0:          # queries only
            return
        if packet.haslayer(UDP):
            if packet[UDP].dport != 53:
                return
        elif packet.haslayer(TCP):
            if packet[TCP].dport != 53:
                return
        else:
            return

        with self.stats_lock:
            self.stats["total_packets"] += 1

        result = self.analyzer.analyze_packet(packet)
        if result is None:
            return

        if result.risk_level == RiskLevel.WARNING:
            with self.stats_lock:
                self.stats["warnings"] += 1

        elif result.risk_level == RiskLevel.EXFILTRATION:
            with self.stats_lock:
                self.stats["malicious_packets"] += 1
            status = self.firewall.block_ip(result.source_ip)
            if status in ("blocked", "already"):
                result.action_taken = "Blocked"
                with self.stats_lock:
                    if result.source_ip not in self.stats["quarantined_ips"]:
                        self.stats["quarantined_ips"].add(result.source_ip)
                        self.stats["total_quarantined"] += 1
            elif status == "protected":
                result.action_taken = "Protected (not blocked)"
            elif status == "failed":
                result.action_taken = "Block failed"

        if self.logger:
            self.logger.log(result)
        self.buffer.append(result)
        if self.on_result:
            self.on_result(result)

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self.running = True
        if self.pcap:
            self._thread = threading.Thread(target=self._offline_loop, daemon=True)
            self._thread.start()
        else:
            self._async = AsyncSniffer(
                iface=self.interface, filter="port 53",
                prn=self._packet_callback, store=False,
            )
            self._async.start()

    def _offline_loop(self) -> None:
        try:
            sniff(offline=self.pcap, prn=self._packet_callback, store=False)
        except Exception as exc:
            self.firewall.events.append(f"pcap error: {exc}")
        finally:
            self.finished = True

    def error(self) -> Optional[BaseException]:
        return getattr(self._async, "exception", None) if self._async else None

    def alive(self) -> bool:
        if self.pcap:
            return not self.finished
        return bool(self._async and getattr(self._async, "running", False))

    def stop(self) -> None:
        self.running = False
        if self._async is not None:
            try:
                if getattr(self._async, "running", False):
                    self._async.stop()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)


# =============================================================================
# dashboard + CLI
# =============================================================================

RISK_STYLE = {
    RiskLevel.NORMAL: "green",
    RiskLevel.WARNING: "yellow",
    RiskLevel.EXFILTRATION: "bold red",
}


def fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 3600:02d}:{seconds % 3600 // 60:02d}:{seconds % 60:02d}"


def build_dashboard(console: Console, args, stats: Dict, stats_lock: threading.Lock,
                    buffer: ResultBuffer, firewall: FirewallManager) -> Layout:
    with stats_lock:
        s = dict(stats)
    runtime = time.time() - s["start_time"]
    qps = s["total_packets"] / runtime if runtime > 0 else 0.0

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="top", size=9),
        Layout(name="queries"),
        Layout(name="events", size=7),
    )

    mode = "[bold red]AUTO-BLOCK[/]" if firewall.auto_block else "[green]MONITOR ONLY[/]"
    source = args.pcap or args.interface
    layout["header"].update(Panel(
        Text.from_markup(f"[bold cyan]DNS-ExfilWatch[/]  |  {mode}  |  source: {source}"),
        box=box.ROUNDED))

    stats_tbl = Table.grid(padding=(0, 2))
    stats_tbl.add_row("Queries analysed", f"{s['total_packets']:,}")
    stats_tbl.add_row("Warnings", f"[yellow]{s['warnings']:,}[/]")
    stats_tbl.add_row("Exfiltration hits", f"[bold red]{s['malicious_packets']:,}[/]")
    stats_tbl.add_row("IPs quarantined", f"{s['total_quarantined']}")
    stats_tbl.add_row("Rate", f"{qps:.1f} q/s")
    stats_tbl.add_row("Runtime", fmt_duration(runtime))
    stats_tbl.add_row("Errors", f"{s['errors']}")
    layout["top"].split_row(
        Layout(Panel(stats_tbl, title="Statistics", box=box.ROUNDED)),
        Layout(name="blocked"),
    )

    blocked_tbl = Table(box=None, expand=True)
    blocked_tbl.add_column("Blocked IP")
    blocked_tbl.add_column("Expires in", justify="right")
    for ip, remaining in firewall.list_blocked()[:6]:
        blocked_tbl.add_row(ip, "never" if remaining < 0 else f"{int(remaining)}s")
    layout["top"]["blocked"].update(Panel(blocked_tbl, title="Quarantine", box=box.ROUNDED))

    rows = max(5, console.size.height - 3 - 9 - 7 - 4)
    table = Table(box=box.SIMPLE_HEAD, expand=True)
    for col, kw in (("Time", {}), ("Source", {}), ("Type", {}),
                    ("Domain", {"overflow": "ellipsis", "no_wrap": True, "ratio": 1}),
                    ("Entropy", {"justify": "right"}), ("Score", {"justify": "right"}),
                    ("Risk", {}), ("Action", {})):
        table.add_column(col, **kw)
    for r in reversed(buffer.snapshot(rows)):
        style = RISK_STYLE[r.risk_level]
        table.add_row(
            datetime.fromtimestamp(r.timestamp).strftime("%H:%M:%S"),
            r.source_ip, r.record_type, r.domain,
            f"{r.entropy:.2f}", f"{r.risk_score:.0f}",
            Text(r.risk_level.value, style=style), r.action_taken,
        )
    layout["queries"].update(Panel(table, title="Live DNS Queries", box=box.ROUNDED))

    events = "\n".join(list(firewall.events)[-5:]) or "-"
    layout["events"].update(Panel(events, title="Events", box=box.ROUNDED))
    return layout


def show_history(console: Console, db_path: str, limit: int) -> None:
    if not os.path.exists(db_path):
        console.print(f"[red]No database at {db_path}[/]")
        return
    logger = ThreatLogger(db_path)
    table = Table(title=f"Last {limit} logged threats", box=box.SIMPLE_HEAD)
    for col in ("Time", "Source", "Domain", "Type", "Entropy", "Score", "Risk", "Action"):
        table.add_column(col, overflow="ellipsis")
    for t, src, dom, rt, ent, score, lvl, act in logger.recent(limit):
        style = RISK_STYLE.get(RiskLevel(lvl), "white")
        table.add_row(t, src, dom, rt, f"{ent:.2f}", f"{score:.0f}", Text(lvl, style=style), act)
    console.print(table)
    logger.close()


def load_allowlist(path: Optional[str]) -> List[str]:
    entries = list(DEFAULT_ALLOWLIST)
    if path:
        with open(path) as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    entries.append(line)
    return entries


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="DNS-ExfilWatch: DNS tunneling detection and active defense")
    p.add_argument("-i", "--interface", default=str(conf.iface), help="interface to sniff")
    p.add_argument("--pcap", help="replay a pcap file instead of live capture")
    p.add_argument("--auto-block", action="store_true",
                   help="block offending source IPs with iptables (needs root)")
    p.add_argument("--block-ttl", type=int, default=600,
                   help="seconds before a block expires; 0 = permanent (default 600)")
    p.add_argument("--never-block", action="append", default=[], metavar="IP/CIDR",
                   help="extra IPs/networks that must never be blocked (repeatable)")
    p.add_argument("--entropy-threshold", type=float, default=3.8)
    p.add_argument("--length-threshold", type=int, default=35, help="long label length")
    p.add_argument("--warn-threshold", type=float, default=35.0)
    p.add_argument("--exfil-threshold", type=float, default=60.0)
    p.add_argument("--allowlist", help="file of domain suffixes to ignore (one per line)")
    p.add_argument("--db", default="dns_exfilwatch.db", help="SQLite log path")
    p.add_argument("--log-all", action="store_true", help="log Normal queries too")
    p.add_argument("--no-dashboard", action="store_true", help="plain text output")
    p.add_argument("--history", type=int, metavar="N", help="show last N logged threats and exit")
    p.add_argument("--list-interfaces", action="store_true")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    console = Console()

    if args.list_interfaces:
        for name in get_if_list():
            console.print(name)
        return 0

    if args.history:
        show_history(console, args.db, args.history)
        return 0

    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    if not args.pcap and not is_root:
        console.print("[red]Live capture needs root (try sudo).[/]")
        return 1
    if args.auto_block and not is_root:
        console.print("[red]--auto-block needs root.[/]")
        return 1
    if args.auto_block and args.pcap:
        console.print("[red]--auto-block is disabled for --pcap replays "
                      "(it would block real hosts).[/]")
        return 1

    thresholds = Thresholds(args.entropy_threshold, args.length_threshold,
                            args.warn_threshold, args.exfil_threshold)
    try:
        allowlist = load_allowlist(args.allowlist)
    except OSError as exc:
        console.print(f"[red]Cannot read allowlist: {exc}[/]")
        return 1

    analyzer = DomainAnalyzer(thresholds, allowlist)
    firewall = FirewallManager(args.auto_block, args.interface, args.block_ttl, args.never_block)
    logger = ThreatLogger(args.db, args.log_all)
    buffer = ResultBuffer()
    stats = new_stats()
    stats_lock = threading.Lock()

    def plain_print(r: AnalysisResult) -> None:
        if r.risk_level != RiskLevel.NORMAL:
            console.print(
                f"[{RISK_STYLE[r.risk_level]}]{datetime.fromtimestamp(r.timestamp):%H:%M:%S} "
                f"{r.risk_level.value:<12} {r.source_ip} {r.record_type} "
                f"score={r.risk_score:.0f} H={r.entropy:.2f} {r.domain} [{r.action_taken}][/]",
                highlight=False)

    sniffer = DNSSniffer(args.interface, args.pcap, analyzer, firewall, logger, buffer,
                         stats, stats_lock,
                         on_result=plain_print if args.no_dashboard else None)

    stop_event = threading.Event()

    def handle_signal(signum, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    exit_code = 0
    try:
        sniffer.start()
        time.sleep(0.5)
        err = sniffer.error()
        if err is not None:
            console.print(f"[red]Sniffer failed: {err}[/]")
            return 1

        if args.no_dashboard:
            console.print(f"[cyan]DNS-ExfilWatch running on {args.pcap or args.interface} "
                          f"(Ctrl+C to stop)[/]")
            while not stop_event.is_set() and sniffer.alive():
                stop_event.wait(0.5)
        else:
            with Live(build_dashboard(console, args, stats, stats_lock, buffer, firewall),
                      console=console, refresh_per_second=4, screen=False) as live:
                while not stop_event.is_set() and sniffer.alive():
                    live.update(build_dashboard(console, args, stats, stats_lock,
                                                buffer, firewall))
                    stop_event.wait(0.25)
                live.update(build_dashboard(console, args, stats, stats_lock, buffer, firewall))

        err = sniffer.error()
        if err is not None:
            console.print(f"[red]Sniffer stopped with error: {err}[/]")
            exit_code = 1
    finally:
        sniffer.stop()
        firewall.cleanup()
        logger.close()

    with stats_lock:
        console.print(
            f"\n[bold]Summary:[/] {stats['total_packets']:,} queries, "
            f"{stats['warnings']:,} warnings, {stats['malicious_packets']:,} exfiltration hits, "
            f"{stats['total_quarantined']} IPs quarantined. Log: {args.db}")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())