#!/usr/bin/env python3
"""
DNS-ExfilWatch - Packet Ingestion & Queued Processing Engine (sniffer.py)
Author: Senior Cyber Security Engineer & Systems Software Developer
Platform: Kali Linux / Debian / Linux x86_64

Architecture:
    [ Network Interfaces: lo, eth0, wlan0 ]
                   │
                   ▼  (Dedicated Multi-Interface Capture Sockets)
        [ Packet Callback (Fast Path) ]
           ├── Loopback Link-Layer Unwrapper
           └── Universal Port 53 Scanner
                   │
                   ▼  (Thread-Safe FIFO Queue)
         [ Analysis Worker Thread ]
           ├── DNSAnalyzer (Shannon Entropy, Length, Heuristics)
           ├── ThreatLogger (SQLite Persistent Auditing)
           └── FirewallManager (Active Defense iptables Quarantine)
                   │
                   ▼
       [ UI Shared State / Live Table Buffer ]
"""

from __future__ import annotations

import collections
import logging
import platform
import queue
import socket
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Deque, List, Optional, Tuple

try:
    from scapy.all import conf, get_if_list, sniff
    from scapy.layers.dns import DNS, DNSQR, dnsqtypes
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from analyzer import AnalysisResult, DNSAnalyzer, RiskLevel, ThreatLogger
from firewall import FirewallManager

logger = logging.getLogger("DNS-ExfilWatch.Sniffer")


@dataclass
class RawDNSEvent:
    """Lightweight decoupled container holding parsed raw packet details."""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    qname: str
    qtype: str


class InterfaceCaptureWorker(threading.Thread):
    """
    Dedicated sniffing thread per network device (e.g. lo, eth0).
    Features automatic BPF fallback to guarantee packets are never missed.
    """

    def __init__(
        self,
        iface_name: Optional[str],
        packet_callback: Callable[[Any], None],
        stop_event: threading.Event,
        bpf_filter: str = "udp port 53 or tcp port 53",
        offline_pcap: Optional[str] = None,
    ) -> None:
        name = f"Capture-{iface_name if iface_name else 'PCAP'}"
        super().__init__(name=name, daemon=True)
        self.iface_name = iface_name
        self.packet_callback = packet_callback
        self.stop_event = stop_event
        self.bpf_filter = bpf_filter
        self.offline_pcap = offline_pcap
        self.error: Optional[str] = None
        self.is_active: bool = False

    def run(self) -> None:
        sniff_kwargs: dict = {
            "prn": self.packet_callback,
            "store": False,
            "stop_filter": lambda x: self.stop_event.is_set(),
        }

        if self.offline_pcap:
            sniff_kwargs["offline"] = self.offline_pcap
        elif self.iface_name:
            sniff_kwargs["iface"] = self.iface_name

        self.is_active = True

        # Tier 1: Sniff with kernel BPF filter
        try:
            sniff_bpf = dict(sniff_kwargs)
            sniff_bpf["filter"] = self.bpf_filter
            sniff(**sniff_bpf)
            return
        except Exception as bpf_err:
            logger.debug(
                "Interface %s: BPF filter failed (%s). Retrying in Python filter mode...",
                self.iface_name,
                bpf_err,
            )

        # Tier 2: Fallback without BPF filter (Python callback performs port 53 filtering)
        try:
            if not self.stop_event.is_set():
                sniff(**sniff_kwargs)
        except Exception as err:
            self.error = str(err)
            logger.debug("Interface %s capture error: %s", self.iface_name, err)
        finally:
            self.is_active = False


class SnifferEngine:
    """
    High-throughput, resilient packet sniffer with simultaneous multi-interface capture
    (listening on loopback and physical devices concurrently).
    """

    QTYPE_NAMES = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        10: "NULL",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        41: "OPT",
        255: "ANY",
    }

    def __init__(
        self,
        analyzer: DNSAnalyzer,
        firewall: FirewallManager,
        logger_db: ThreatLogger,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        bpf_filter: str = "udp port 53 or tcp port 53",
        history_len: int = 15,
        on_event_callback: Optional[Callable[[AnalysisResult], None]] = None,
    ) -> None:
        self.analyzer = analyzer
        self.firewall = firewall
        self.logger_db = logger_db
        self.interface = interface
        self.pcap_file = pcap_file
        self.bpf_filter = bpf_filter
        self.history_len = history_len
        self.on_event_callback = on_event_callback

        # Thread-safe pipeline queue
        self._event_queue: queue.Queue[Optional[RawDNSEvent]] = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._capture_workers: List[InterfaceCaptureWorker] = []

        # Interface tracking
        self.actual_interfaces: List[str] = []

        # Telemetry metrics
        self._metrics_lock = threading.Lock()
        self.raw_packets_received: int = 0
        self.total_packets_inspected: int = 0
        self.malicious_packets_flagged: int = 0
        self.warning_packets_flagged: int = 0
        self.recent_results: Deque[AnalysisResult] = collections.deque(maxlen=history_len)

        # Performance rate metrics
        self._start_time: float = time.time()
        self._last_rate_calc_time: float = time.time()
        self._last_rate_count: int = 0
        self.current_packet_rate: float = 0.0

    def _extract_qname_and_type(self, dns_layer: Any) -> Tuple[str, str]:
        """Safely extracts and decodes query domain and query type."""
        qname = "unknown"
        qtype = "A"

        try:
            if dns_layer.qd:
                raw_qname = dns_layer.qd.qname
                if isinstance(raw_qname, bytes):
                    qname = raw_qname.decode("utf-8", errors="replace")
                else:
                    qname = str(raw_qname)

                raw_qtype = dns_layer.qd.qtype
                if isinstance(raw_qtype, int):
                    qtype = self.QTYPE_NAMES.get(raw_qtype, str(raw_qtype))
                else:
                    qtype = str(raw_qtype)
        except Exception as e:
            logger.debug("DNS layer parsing error: %s", e)

        return qname.strip().rstrip("."), qtype

    def _packet_callback(self, pkt: Any) -> None:
        """
        Rock-solid packet callback on the capture fast-path.
        Unwraps raw loopback packets and parses DNS safely.
        """
        if self._stop_event.is_set():
            return

        try:
            with self._metrics_lock:
                self.raw_packets_received += 1

            # 1. Unpack Misinterpreted Link-Layers (Loopback 'lo' or Linux Cooked SLL)
            if not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
                raw = bytes(pkt)
                if len(raw) >= 20 and (raw[0] & 0xF0) == 0x40:
                    try:
                        pkt = IP(raw)
                    except Exception:
                        pass
                elif len(raw) >= 40 and (raw[0] & 0xF0) == 0x60:
                    try:
                        pkt = IPv6(raw)
                    except Exception:
                        pass
                elif len(raw) >= 36 and (raw[16] & 0xF0) == 0x40:
                    try:
                        pkt = IP(raw[16:])
                    except Exception:
                        pass

            # 2. Extract DNS & Protocol Layers
            dns = None
            proto = "UDP"
            src_port = 0
            dst_port = 53

            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if pkt.haslayer(TCP):
                    proto = "TCP"
                    src_port = pkt[TCP].sport
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    src_port = pkt[UDP].sport
                    dst_port = pkt[UDP].dport
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                if dst_port == 53 or src_port == 53:
                    proto = "UDP"
                    try:
                        raw_payload = bytes(udp.payload)
                        if raw_payload:
                            dns = DNS(raw_payload)
                    except Exception:
                        dns = None
            elif pkt.haslayer(TCP):
                tcp = pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                if dst_port == 53 or src_port == 53:
                    proto = "TCP"
                    try:
                        raw_payload = bytes(tcp.payload)
                        if len(raw_payload) > 2:
                            dns = DNS(raw_payload[2:])
                    except Exception:
                        dns = None

            # 3. Universal Byte-Scanner (fallback for non-standard encapsulated sockets)
            if dns is None:
                raw_bytes = bytes(pkt)
                for offset in range(0, min(len(raw_bytes) - 8, 48)):
                    sp = (raw_bytes[offset] << 8) | raw_bytes[offset + 1]
                    dp = (raw_bytes[offset + 2] << 8) | raw_bytes[offset + 3]
                    if dp == 53 or sp == 53:
                        u_len = (raw_bytes[offset + 4] << 8) | raw_bytes[offset + 5]
                        if 12 <= u_len <= len(raw_bytes) - offset:
                            payload = raw_bytes[offset + 8 : offset + u_len]
                            if len(payload) >= 12:
                                try:
                                    candidate = DNS(payload)
                                    if getattr(candidate, "qd", None):
                                        dns = candidate
                                        proto = "UDP"
                                        src_port = sp
                                        dst_port = dp
                                        break
                                except Exception:
                                    pass

            if dns is None:
                return

            # Only process queries (qr == 0), ignore responses (qr == 1)
            if getattr(dns, "qr", 0) != 0:
                return

            if not getattr(dns, "qd", None):
                return

            ts = float(pkt.time) if hasattr(pkt, "time") else time.time()
            src_ip = "127.0.0.1"
            dst_ip = "127.0.0.1"

            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            qname, qtype = self._extract_qname_and_type(dns)
            if not qname or qname == "unknown":
                return

            event = RawDNSEvent(
                timestamp=ts,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
                qname=qname,
                qtype=qtype,
            )

            try:
                self._event_queue.put_nowait(event)
            except queue.Full:
                try:
                    _ = self._event_queue.get_nowait()
                    self._event_queue.put_nowait(event)
                except Exception:
                    pass

        except Exception as e:
            logger.debug("Packet callback error: %s", e)

    def _worker_loop(self) -> None:
        """
        Consumer worker that processes queued DNS events, performs analysis,
        triggers firewall rules, and updates state.
        """
        while not self._stop_event.is_set() or not self._event_queue.empty():
            try:
                event = self._event_queue.get(timeout=0.2)
                if event is None:
                    break
            except queue.Empty:
                self._update_rates()
                continue

            try:
                # 1. Statistical & Heuristic Analysis
                result = self.analyzer.analyze(
                    src_ip=event.src_ip,
                    query_name=event.qname,
                    record_type=event.qtype,
                    timestamp=event.timestamp,
                )

                # 2. Active Defense & Action Logic
                action = "Allowed"
                if result.risk_level == RiskLevel.EXFILTRATION:
                    if self.firewall.enabled:
                        success, msg = self.firewall.quarantine_ip(event.src_ip)
                        action = "Blocked" if success else "Block-Failed"
                    else:
                        action = "Alert-Only"
                    self.logger_db.log_threat(result, action)
                elif result.risk_level == RiskLevel.WARNING:
                    action = "Logged"
                    self.logger_db.log_threat(result, action)

                result.action_taken = action

                # 3. Update Shared Telemetry State
                with self._metrics_lock:
                    self.total_packets_inspected += 1
                    if result.risk_level == RiskLevel.EXFILTRATION:
                        self.malicious_packets_flagged += 1
                    elif result.risk_level == RiskLevel.WARNING:
                        self.warning_packets_flagged += 1
                    self.recent_results.append(result)

                if self.on_event_callback:
                    try:
                        self.on_event_callback(result)
                    except Exception:
                        pass

            except Exception as e:
                logger.error("Error processing DNS event: %s", e)
            finally:
                self._event_queue.task_done()
                self._update_rates()

    def _update_rates(self) -> None:
        """Periodically calculates queries-per-second throughput."""
        now = time.time()
        elapsed = now - self._last_rate_calc_time
        if elapsed >= 1.0:
            with self._metrics_lock:
                current_count = self.total_packets_inspected
                delta = current_count - self._last_rate_count
                self.current_packet_rate = round(delta / elapsed, 1)
                self._last_rate_count = current_count
                self._last_rate_calc_time = now

    def _discover_target_interfaces(self) -> List[str]:
        """
        Discovers all real network devices on this machine.
        Eliminates the 'Interface any not found' crash by expanding to real devices.
        """
        if self.pcap_file:
            return []

        # If user explicitly requested an interface (e.g. -i eth0, -i lo)
        if self.interface:
            req = self.interface.strip()
            if req.lower() != "any":
                return [req]

        # If user passed 'any' or omitted -i:
        # Discover all real interfaces on this machine (including lo and eth0/wlan0)
        try:
            available = get_if_list()
            real_ifaces = [
                i for i in available
                if not i.startswith("docker")
                and not i.startswith("veth")
                and not i.startswith("br-")
            ]
            if "lo" not in real_ifaces and "lo" in available:
                real_ifaces.insert(0, "lo")
            if real_ifaces:
                return real_ifaces
        except Exception:
            pass

        # Fallback to conf.iface and lo
        fallback = ["lo"]
        try:
            primary = conf.iface.name if hasattr(conf.iface, "name") else str(conf.iface)
            if primary and primary != "lo" and primary not in fallback:
                fallback.append(primary)
        except Exception:
            pass

        return fallback

    def start(self) -> None:
        """Starts worker consumer thread and managed multi-interface capture threads."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not installed. Please run: pip install scapy")

        self._stop_event.clear()
        self._start_time = time.time()
        self._last_rate_calc_time = time.time()
        self._capture_workers.clear()

        # 1. Start Consumer Worker Thread
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="DNSExfilWorker",
            daemon=True,
        )
        self._worker_thread.start()

        # 2. Determine and Start Interface Workers
        if self.pcap_file:
            self.actual_interfaces = ["PCAP Replay"]
            worker = InterfaceCaptureWorker(
                iface_name=None,
                packet_callback=self._packet_callback,
                stop_event=self._stop_event,
                bpf_filter=self.bpf_filter,
                offline_pcap=self.pcap_file,
            )
            self._capture_workers.append(worker)
            worker.start()
        else:
            target_ifaces = self._discover_target_interfaces()
            self.actual_interfaces = target_ifaces

            for iface_name in target_ifaces:
                worker = InterfaceCaptureWorker(
                    iface_name=iface_name,
                    packet_callback=self._packet_callback,
                    stop_event=self._stop_event,
                    bpf_filter=self.bpf_filter,
                )
                self._capture_workers.append(worker)
                worker.start()

    def stop(self) -> None:
        """Signals sniffer workers and analysis thread to terminate cleanly."""
        self._stop_event.set()

        # Unblock worker queue
        try:
            self._event_queue.put_nowait(None)
        except Exception:
            pass

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=1.5)

        for worker in self._capture_workers:
            if worker.is_alive():
                worker.join(timeout=1.0)

        self._capture_workers.clear()

    @property
    def is_healthy(self) -> bool:
        """Returns True if at least one capture thread is running without fatal errors."""
        if not self._capture_workers:
            return False
        return any(w.is_alive() for w in self._capture_workers)

    @property
    def capture_errors(self) -> List[str]:
        """Returns any recorded capture errors across interface threads."""
        return [f"{w.iface_name}: {w.error}" for w in self._capture_workers if w.error]

    def get_metrics_snapshot(self) -> dict:
        """Returns thread-safe copy of current real-time telemetry metrics."""
        with self._metrics_lock:
            return {
                "raw_packets": self.raw_packets_received,
                "inspected": self.total_packets_inspected,
                "malicious": self.malicious_packets_flagged,
                "warning": self.warning_packets_flagged,
                "quarantined": self.firewall.quarantined_count,
                "packet_rate": self.current_packet_rate,
                "is_healthy": self.is_healthy,
                "capture_errors": self.capture_errors,
                "interfaces": self.actual_interfaces,
                "recent_results": list(self.recent_results),
            }
