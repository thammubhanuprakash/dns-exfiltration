#!/usr/bin/env python3
"""
DNS-ExfilWatch - Detection & Statistical Analysis Engine (analyzer.py)
Author: Senior Cyber Security Engineer & Systems Software Developer
Platform: Kali Linux / Debian / Linux x86_64

Mathematical Foundation:
    1. Shannon Entropy:
       H(X) = - \\sum_{i=1}^{n} P(x_i) \\log_2 P(x_i)
       Where P(x_i) represents the probability of byte/character x_i occurring
       in the domain label. Values > 3.8 strongly correlate with base64/base32/hex
       encoded data or encrypted ciphertext payloads.

    2. Structural Metrics:
       - Individual subdomain label length (RFC 1035 max 63 chars; legitimate <= 35)
       - Total FQDN length (RFC 1035 max 253 chars; legitimate <= 60)
       - Subdomain depth (number of nested label hierarchies)

    3. Behavioral & Temporal Metrics:
       - Source IP query frequency / burst velocity across a sliding time window
       - Non-standard exfiltration record type weighting (TXT, NULL, CNAME, ANY)

    4. Composite Weighted Scoring Model:
       RiskScore = (w_e * S_entropy) + (w_l * S_length) + (w_f * S_freq) + (w_r * S_record)
       Score >= 75: High-Severity DNS Exfiltration (Active Defense Trigger)
       50 <= Score < 75: Suspicious Warning
       Score < 50: Normal Traffic
"""

from __future__ import annotations

import collections
import math
import re
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Deque, Dict, List, Optional, Tuple


class RiskLevel(Enum):
    """Classification levels for inspected DNS queries."""
    NORMAL = "Normal"
    WARNING = "Warning"
    EXFILTRATION = "Exfiltration"


@dataclass
class DomainFeatures:
    """Extracted statistical and structural features of a queried domain name."""
    raw_fqdn: str
    clean_domain: str
    labels: List[str]
    longest_label: str
    longest_label_len: int
    total_length: int
    subdomain_depth: int
    highest_label_entropy: float
    full_domain_entropy: float
    vowel_ratio: float
    digit_ratio: float
    special_char_ratio: float


@dataclass
class AnalysisResult:
    """Comprehensive analytical evaluation of a single DNS query."""
    timestamp: float
    src_ip: str
    query_name: str
    record_type: str
    features: DomainFeatures
    entropy_score: float
    length_score: float
    frequency_score: float
    record_type_score: float
    composite_risk_score: float
    risk_level: RiskLevel
    reasons: List[str] = field(default_factory=list)
    action_taken: str = "Logged"

    @property
    def is_malicious(self) -> bool:
        """Convenience property identifying if query meets exfiltration criteria."""
        return self.risk_level == RiskLevel.EXFILTRATION


def calculate_shannon_entropy(data: str) -> float:
    """
    Computes the exact Shannon Entropy H(X) for a string:
        H(X) = - \\sum_{i=1}^{n} P(x_i) * log2(P(x_i))

    Args:
        data: Input string (e.g., domain label or subdomain chunk).

    Returns:
        float: Entropy value in bits per character. Range typically [0.0, 6.0+].
    """
    if not data:
        return 0.0

    length = len(data)
    frequencies = collections.Counter(data)
    entropy = 0.0

    for count in frequencies.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return round(entropy, 4)


def extract_domain_features(fqdn: str) -> DomainFeatures:
    """
    Deconstructs a Fully Qualified Domain Name (FQDN) into structural components
    and extracts statistical traits.

    Args:
        fqdn: Raw domain string from DNS question section.

    Returns:
        DomainFeatures dataclass populated with computed metrics.
    """
    clean_domain = fqdn.strip().rstrip(".").lower()
    if not clean_domain:
        clean_domain = "unknown"

    labels = [lbl for lbl in clean_domain.split(".") if lbl]
    if not labels:
        labels = [clean_domain]

    longest_label = max(labels, key=len)
    longest_label_len = len(longest_label)
    total_length = len(clean_domain)
    subdomain_depth = len(labels)

    label_entropies = [calculate_shannon_entropy(lbl) for lbl in labels]
    highest_label_entropy = max(label_entropies) if label_entropies else 0.0
    full_domain_entropy = calculate_shannon_entropy(clean_domain)

    # Character composition metrics on longest label (payload carrier)
    target_text = longest_label
    total_chars = max(len(target_text), 1)
    vowels = len(re.findall(r"[aeiou]", target_text))
    digits = len(re.findall(r"[0-9]", target_text))
    special = len(re.findall(r"[-_]", target_text))

    return DomainFeatures(
        raw_fqdn=fqdn,
        clean_domain=clean_domain,
        labels=labels,
        longest_label=longest_label,
        longest_label_len=longest_label_len,
        total_length=total_length,
        subdomain_depth=subdomain_depth,
        highest_label_entropy=highest_label_entropy,
        full_domain_entropy=full_domain_entropy,
        vowel_ratio=round(vowels / total_chars, 4),
        digit_ratio=round(digits / total_chars, 4),
        special_char_ratio=round(special / total_chars, 4),
    )


class IPVelocityTracker:
    """
    Thread-safe sliding-window velocity tracker for tracking query bursts per IP.
    """

    def __init__(self, window_seconds: float = 10.0) -> None:
        self.window_seconds = window_seconds
        self._history: Dict[str, Deque[float]] = collections.defaultdict(collections.deque)
        self._lock = threading.Lock()

    def record_query(self, src_ip: str, timestamp: Optional[float] = None) -> Tuple[int, float]:
        """
        Records a query timestamp for an IP and returns (recent_count, queries_per_second).
        """
        now = timestamp if timestamp is not None else time.time()
        with self._lock:
            q = self._history[src_ip]
            q.append(now)

            # Evict entries outside the sliding window
            threshold = now - self.window_seconds
            while q and q[0] < threshold:
                q.popleft()

            count = len(q)
            qps = count / self.window_seconds
            return count, round(qps, 2)

    def prune_stale_ips(self, max_idle_seconds: float = 120.0) -> None:
        """Cleans up internal dict entries for inactive IPs to conserve memory."""
        now = time.time()
        cutoff = now - max_idle_seconds
        with self._lock:
            stale = [ip for ip, q in self._history.items() if not q or q[-1] < cutoff]
            for ip in stale:
                del self._history[ip]


class DNSAnalyzer:
    """
    Production-grade mathematical and heuristic analysis engine for DNS tunneling
    and exfiltration detection.
    """

    # Record types prioritized in exfiltration attacks
    SUSPICIOUS_RECORD_TYPES = {
        "TXT": 90.0,   # High bandwidth downstream payload channel
        "NULL": 100.0, # Raw binary payload channel (e.g. iodine)
        "CNAME": 70.0, # Common for spoofed alias tunneling
        "ANY": 65.0,   # Tunnel enumeration & amplification
        "MX": 45.0,    # Occasional fallback
        "A": 25.0,     # Standard, but payload frequently carried in subdomain
        "AAAA": 25.0,  # Standard IPv6
    }

    # Model Weights (sum to 1.0)
    WEIGHT_ENTROPY = 0.40
    WEIGHT_LENGTH = 0.25
    WEIGHT_FREQUENCY = 0.20
    WEIGHT_RECORD = 0.15

    def __init__(
        self,
        entropy_threshold: float = 3.8,
        length_threshold: int = 35,
        total_length_threshold: int = 60,
        burst_threshold: int = 12,
        window_seconds: float = 10.0,
    ) -> None:
        """
        Args:
            entropy_threshold: Shannon entropy cut-off (default 3.8).
            length_threshold: Max normal character length of individual label (default 35).
            total_length_threshold: Max normal total length of FQDN (default 60).
            burst_threshold: Max acceptable queries from single IP in window_seconds.
            window_seconds: Sliding window span in seconds.
        """
        self.entropy_threshold = float(entropy_threshold)
        self.length_threshold = int(length_threshold)
        self.total_length_threshold = int(total_length_threshold)
        self.burst_threshold = int(burst_threshold)
        self.velocity_tracker = IPVelocityTracker(window_seconds=window_seconds)

    def analyze(
        self,
        src_ip: str,
        query_name: str,
        record_type: str,
        timestamp: Optional[float] = None,
    ) -> AnalysisResult:
        """
        Performs holistic multi-factor scoring on an incoming DNS query.

        Args:
            src_ip: Client source IP address.
            query_name: Queried domain string.
            record_type: Standard DNS query type (e.g. A, TXT, NULL).
            timestamp: Packet arrival epoch timestamp.

        Returns:
            AnalysisResult containing breakdown, composite score, and classification.
        """
        ts = timestamp if timestamp is not None else time.time()
        features = extract_domain_features(query_name)
        reasons: List[str] = []

        # 1. Entropy Scoring (0 - 100)
        # Evaluates highest label entropy (subdomain chunk)
        h_val = features.highest_label_entropy
        if h_val < 2.5:
            entropy_score = (h_val / 2.5) * 20.0
        elif h_val < self.entropy_threshold:
            entropy_score = 20.0 + ((h_val - 2.5) / (self.entropy_threshold - 2.5)) * 40.0
        else:
            # Above threshold: scales aggressively from 75 to 100
            overshoot = min(h_val - self.entropy_threshold, 1.5)
            entropy_score = 75.0 + (overshoot / 1.5) * 25.0
            reasons.append(
                f"High Shannon entropy ({h_val:.2f} > threshold {self.entropy_threshold:.2f})"
            )

        # 2. Length & Structural Scoring (0 - 100)
        length_score = 0.0
        if features.longest_label_len > self.length_threshold:
            excess = features.longest_label_len - self.length_threshold
            length_score += min(60.0, 30.0 + (excess * 2.0))
            reasons.append(
                f"Oversized label ({features.longest_label_len} chars > {self.length_threshold})"
            )

        if features.total_length > self.total_length_threshold:
            excess_total = features.total_length - self.total_length_threshold
            length_score += min(30.0, 15.0 + (excess_total * 0.5))
            reasons.append(
                f"Abnormal FQDN length ({features.total_length} chars > {self.total_length_threshold})"
            )

        if features.subdomain_depth >= 4:
            length_score += 15.0
            reasons.append(f"Deep subdomain nesting ({features.subdomain_depth} levels)")

        # Low vowel ratio indicates encoded ciphertext rather than natural language
        if features.longest_label_len > 15 and features.vowel_ratio < 0.15:
            length_score += 10.0
            reasons.append(f"Unnatural consonant clustering (vowel ratio {features.vowel_ratio:.2f})")

        length_score = min(100.0, length_score)

        # 3. Frequency & Velocity Scoring (0 - 100)
        recent_count, qps = self.velocity_tracker.record_query(src_ip, ts)
        if recent_count > self.burst_threshold:
            ratio = min(recent_count / self.burst_threshold, 3.0)
            frequency_score = 50.0 + (ratio - 1.0) * 25.0
            reasons.append(
                f"Query burst detected ({recent_count} queries in window, {qps:.1f} QPS)"
            )
        else:
            frequency_score = (recent_count / self.burst_threshold) * 40.0
        frequency_score = min(100.0, frequency_score)

        # 4. Record Type Scoring (0 - 100)
        normalized_rec = record_type.upper().strip()
        record_type_score = self.SUSPICIOUS_RECORD_TYPES.get(normalized_rec, 30.0)
        if normalized_rec in ("TXT", "NULL") and features.longest_label_len > 25:
            reasons.append(f"High-capacity exfil record type requested ({normalized_rec})")

        # 5. Composite Weighted Risk Score (0 - 100)
        composite = (
            (self.WEIGHT_ENTROPY * entropy_score)
            + (self.WEIGHT_LENGTH * length_score)
            + (self.WEIGHT_FREQUENCY * frequency_score)
            + (self.WEIGHT_RECORD * record_type_score)
        )

        # High-confidence tunneling signature: High entropy combined with oversized label
        if h_val >= self.entropy_threshold and features.longest_label_len >= self.length_threshold:
            composite = max(composite, 82.0)
            reasons.append("High-confidence tunneling signature: High entropy combined with oversized label")

        composite = round(min(100.0, max(0.0, composite)), 1)

        # Classification threshold
        if composite >= 75.0:
            level = RiskLevel.EXFILTRATION
        elif composite >= 50.0:
            level = RiskLevel.WARNING
        else:
            level = RiskLevel.NORMAL

        return AnalysisResult(
            timestamp=ts,
            src_ip=src_ip,
            query_name=features.clean_domain,
            record_type=normalized_rec,
            features=features,
            entropy_score=round(h_val, 2),
            length_score=round(length_score, 1),
            frequency_score=round(frequency_score, 1),
            record_type_score=round(record_type_score, 1),
            composite_risk_score=composite,
            risk_level=level,
            reasons=reasons,
        )


class ThreatLogger:
    """
    Thread-safe SQLite persistent store for recording detected security incidents.
    """

    def __init__(self, db_path: str = "exfilwatch.db") -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Initializes database schema with optimized indexing for live querying."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS threat_logs (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp REAL NOT NULL,
                        timestamp_iso TEXT NOT NULL,
                        src_ip TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        record_type TEXT NOT NULL,
                        entropy REAL NOT NULL,
                        risk_score REAL NOT NULL,
                        risk_level TEXT NOT NULL,
                        reasons TEXT NOT NULL,
                        action_taken TEXT NOT NULL
                    )
                    """
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_threat_ip ON threat_logs (src_ip)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_threat_level ON threat_logs (risk_level)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_threat_ts ON threat_logs (timestamp)"
                )
                conn.commit()

    def log_threat(self, result: AnalysisResult, action_taken: str) -> None:
        """Persists a suspicious or malicious DNS inspection event."""
        iso_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(result.timestamp))
        reasons_str = "; ".join(result.reasons) if result.reasons else "Baseline threshold"

        with self._lock:
            try:
                with self._get_connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        INSERT INTO threat_logs (
                            timestamp, timestamp_iso, src_ip, domain, record_type,
                            entropy, risk_score, risk_level, reasons, action_taken
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            result.timestamp,
                            iso_str,
                            result.src_ip,
                            result.query_name,
                            result.record_type,
                            result.entropy_score,
                            result.composite_risk_score,
                            result.risk_level.value,
                            reasons_str,
                            action_taken,
                        ),
                    )
                    conn.commit()
            except Exception as e:
                # Logging should never crash packet capture pipeline
                print(f"[!] SQLite ThreatLogger Error: {e}")

    def fetch_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieves recent high-severity or warning events."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    SELECT id, timestamp_iso, src_ip, domain, record_type,
                           entropy, risk_score, risk_level, reasons, action_taken
                    FROM threat_logs
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                )
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
