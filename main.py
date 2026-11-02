#!/usr/bin/env python3
"""
DNS-ExfilWatch - CLI Entry Point & Real-Time Security Operations Dashboard (main.py)
Author: Senior Cyber Security Engineer & Systems Software Developer
Platform: Kali Linux / Debian / Linux x86_64

Command Line Interface:
    sudo python3 main.py -i any --auto-block
    sudo python3 main.py -i lo
    python3 main.py --test
    python3 main.py --pcap sample_exfil.pcap
    python3 main.py --history 25
    sudo python3 main.py --flush-firewall
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from datetime import datetime
from typing import Any, List, Optional

# Ensure module resolution works when invoked from global PATH (e.g., /usr/local/bin)
SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Rich CLI formatting library
try:
    from rich import box
    from rich.align import Align
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

from analyzer import AnalysisResult, DNSAnalyzer, RiskLevel, ThreatLogger
from firewall import FirewallManager
from sniffer import SnifferEngine

BANNER = r"""
  ██████╗ ███╗   ██╗███████╗    ███████╗██╗  ██╗███████╗██╗██╗     ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
  ██╔══██╗████╗  ██║██╔════╝    ██╔════╝╚██╗██╔╝██╔════╝██║██║     ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
  ██║  ██║██╔██╗ ██║███████╗    █████╗   ╚███╔╝ █████╗  ██║██║     ██║ █╗ ██║███████║   ██║   ██║     ███████║
  ██║  ██║██║╚██╗██║╚════██║    ██╔══╝   ██╔██╗ ██╔══╝  ██║██║     ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
  ██████╔╝██║ ╚████║███████║    ███████╗██╔╝ ██╗██║     ██║███████╗╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═══╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
"""


class DashboardUI:
    """
    Renders a live terminal interface using the Python Rich library.
    """

    def __init__(
        self,
        console: Console,
        interface: str,
        entropy_thresh: float,
        length_thresh: int,
        auto_block: bool,
    ) -> None:
        self.console = console
        self.interface = interface
        self.entropy_thresh = entropy_thresh
        self.length_thresh = length_thresh
        self.auto_block = auto_block
        self.start_time = time.time()

    def generate_header(self, metrics: dict) -> Panel:
        """Constructs top header bar with system configuration status."""
        uptime = int(time.time() - self.start_time)
        mins, secs = divmod(uptime, 60)
        hrs, mins = divmod(mins, 60)
        uptime_str = f"{hrs:02d}:{mins:02d}:{secs:02d}"

        mode_badge = (
            "[bold white on red] ACTIVE DEFENSE (AUTO-BLOCK) [/]"
            if self.auto_block
            else "[bold black on yellow] PASSIVE AUDIT (MONITOR ONLY) [/]"
        )

        if metrics.get("is_healthy"):
            status_str = "[bold green]LISTENING[/bold green]"
        elif metrics.get("capture_errors"):
            status_str = f"[bold red]ERR: {metrics.get('capture_errors')[0]}[/bold red]"
        else:
            status_str = "[bold green]LISTENING[/bold green]"

        raw_pkts = metrics.get("raw_packets", 0)
        ifaces = ", ".join(metrics.get("interfaces", [self.interface]))

        header_text = Text()
        header_text.append("DNS-ExfilWatch ", style="bold cyan")
        header_text.append("v2.5  |  ", style="dim white")
        header_text.append(f"Interface: {ifaces}  |  ", style="bold green")
        header_text.append(f"Status: ", style="white")
        header_text.append(status_str)
        header_text.append(f" (Raw Pkts: {raw_pkts})  |  ", style="magenta")
        header_text.append(f"Entropy Thr: {self.entropy_thresh:.2f}  |  ", style="dim white")
        header_text.append(f"Uptime: {uptime_str}", style="white")

        grid = Table.grid(expand=True)
        grid.add_column(justify="left", ratio=7)
        grid.add_column(justify="right", ratio=3)
        grid.add_row(header_text, mode_badge)

        return Panel(grid, box=box.ROUNDED, style="cyan")

    def generate_stats_panel(self, metrics: dict) -> Panel:
        """Constructs metric overview cards."""
        table = Table(box=box.SIMPLE, expand=True)
        table.add_column("Inspected Queries", justify="center", style="cyan")
        table.add_column("Warning Anomaly", justify="center", style="yellow")
        table.add_column("Exfil Detections", justify="center", style="bold red")
        table.add_column("Quarantined IPs", justify="center", style="bold magenta")
        table.add_column("Capture Velocity", justify="center", style="green")

        inspected = f"[bold white]{metrics.get('inspected', 0)}[/]"
        warning = f"[bold yellow]{metrics.get('warning', 0)}[/]"
        malicious = f"[bold red]{metrics.get('malicious', 0)}[/]"
        quarantined = f"[bold magenta]{metrics.get('quarantined', 0)}[/]"
        rate = f"[bold green]{metrics.get('packet_rate', 0.0):.1f} pkt/s[/]"

        table.add_row(inspected, warning, malicious, quarantined, rate)
        return Panel(table, title="[bold]Real-Time Traffic Statistics[/bold]", box=box.ROUNDED)

    def generate_events_table(self, recent_results: List[AnalysisResult]) -> Panel:
        """Constructs live rolling summary table of inspected DNS transactions."""
        table = Table(box=box.ROUNDED, expand=True)
        table.add_column("Timestamp", justify="center", style="dim", width=10)
        table.add_column("Source IP", justify="left", style="white", width=16)
        table.add_column("Type", justify="center", width=7)
        table.add_column("Entropy", justify="right", width=9)
        table.add_column("Risk", justify="right", width=8)
        table.add_column("Classification", justify="center", width=14)
        table.add_column("Queried Domain", justify="left", ratio=4)
        table.add_column("Defense Action", justify="center", width=14)

        if not recent_results:
            table.add_row(
                "-",
                "-",
                "-",
                "-",
                "-",
                "[dim]Listening on port 53 (waiting for queries)...[/dim]",
                "-",
                "-",
            )
        else:
            for item in reversed(recent_results):
                t_str = datetime.fromtimestamp(item.timestamp).strftime("%H:%M:%S")

                domain_disp = item.query_name
                if len(domain_disp) > 42:
                    domain_disp = domain_disp[:18] + "..." + domain_disp[-21:]

                if item.entropy_score >= self.entropy_thresh:
                    ent_str = f"[bold red]{item.entropy_score:.2f}[/]"
                elif item.entropy_score >= 3.0:
                    ent_str = f"[yellow]{item.entropy_score:.2f}[/]"
                else:
                    ent_str = f"[green]{item.entropy_score:.2f}[/]"

                if item.risk_level == RiskLevel.EXFILTRATION:
                    lvl_badge = "[bold white on red] EXFILTRATION [/]"
                    action_style = "[bold red]"
                elif item.risk_level == RiskLevel.WARNING:
                    lvl_badge = "[bold black on yellow]  WARNING   [/]"
                    action_style = "[yellow]"
                else:
                    lvl_badge = "[green]   NORMAL   [/]"
                    action_style = "[dim green]"

                score_str = f"{item.composite_risk_score:.0f}/100"
                if item.composite_risk_score >= 75:
                    score_disp = f"[bold red]{score_str}[/]"
                elif item.composite_risk_score >= 50:
                    score_disp = f"[yellow]{score_str}[/]"
                else:
                    score_disp = f"[green]{score_str}[/]"

                action_disp = f"{action_style}{item.action_taken}[/]"

                table.add_row(
                    t_str,
                    item.src_ip,
                    item.record_type,
                    ent_str,
                    score_disp,
                    lvl_badge,
                    domain_disp,
                    action_disp,
                )

        return Panel(table, title="[bold]Live DNS Query Inspection Stream[/bold]", box=box.ROUNDED)

    def generate_alerts_panel(self, firewall: FirewallManager, recent_results: List[AnalysisResult]) -> Panel:
        """Constructs bottom defense & quarantine status panel."""
        quarantined_ips = firewall.quarantined_list

        content = Text()
        if quarantined_ips:
            content.append("[Active Firewall Quarantines]: ", style="bold red")
            content.append(", ".join(quarantined_ips), style="bold yellow")
            content.append(f" (Total: {len(quarantined_ips)})\n")
        else:
            content.append("[Active Firewall Quarantines]: ", style="dim")
            content.append("No active IP bans\n", style="green")

        exfil_threats = [r for r in recent_results if r.is_malicious]
        if exfil_threats:
            latest = exfil_threats[-1]
            content.append("[Latest Alert Trigger]: ", style="bold red")
            content.append(f"IP {latest.src_ip} -> {latest.query_name} | ", style="white")
            reasons_txt = ", ".join(latest.reasons) if latest.reasons else "Risk score exceeded 75"
            content.append(f"Reason: {reasons_txt}", style="bold yellow")
        else:
            content.append("[Threat Status]: ", style="dim")
            content.append("No active exfiltration detected in recent window", style="dim green")

        return Panel(content, title="[bold]Active Defense & Intrusion Response[/bold]", box=box.ROUNDED)

    def render_layout(self, metrics: dict, firewall: FirewallManager) -> Layout:
        """Assembles all UI components into a responsive layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="stats", size=5),
            Layout(name="body", ratio=1),
            Layout(name="footer", size=4),
        )

        layout["header"].update(self.generate_header(metrics))
        layout["stats"].update(self.generate_stats_panel(metrics))
        layout["body"].update(self.generate_events_table(metrics.get("recent_results", [])))
        layout["footer"].update(self.generate_alerts_panel(firewall, metrics.get("recent_results", [])))
        return layout


def print_banner(console: Console) -> None:
    """Displays ASCII branding banner."""
    console.print(BANNER, style="bold cyan")
    console.print(
        Align.center(
            "[bold white]Automated DNS Tunneling Exfiltration Detection & Active iptables Defense Engine[/]"
        )
    )
    console.print(
        Align.center(
            "[dim cyan]Designed for Kali Linux  |  Linux Network Defense & Forensics[/]\n"
        )
    )


def handle_self_test(console: Console, db_path: str) -> None:
    """Runs a complete diagnostic test verifying all modules end-to-end."""
    console.print("\n[bold cyan]=== DNS-ExfilWatch End-to-End Diagnostic Self-Test ===[/bold cyan]\n")

    # 1. Test Shannon Entropy & Analyzer
    analyzer = DNSAnalyzer(entropy_threshold=3.8, length_threshold=35)
    sample_domain = "sq01-WW91clBhc3N3b3JkIQ01OzXYZ987654321.c2-exfil-listener.net"
    res = analyzer.analyze("192.168.1.55", sample_domain, "TXT")

    if res.entropy_score >= 3.8 and res.risk_level == RiskLevel.EXFILTRATION:
        console.print(
            f"  [bold green][✔] Shannon Entropy Engine:[/] OK (Entropy: {res.entropy_score:.2f} bits, Risk Score: {res.composite_risk_score:.0f}/100 -> EXFILTRATION)"
        )
    else:
        console.print(
            f"  [bold red][✘] Shannon Entropy Engine:[/] Unexpected result ({res.entropy_score:.2f})"
        )

    # 2. Test SQLite Database Storage
    try:
        logger = ThreatLogger(db_path=db_path)
        logger.log_threat(res, "SelfTest-Logged")
        records = logger.fetch_recent_threats(limit=1)
        if records and records[0]["domain"] == res.query_name:
            console.print(f"  [bold green][✔] SQLite Threat Logger:[/] OK (Database verified at '{db_path}')")
        else:
            console.print("  [bold red][✘] SQLite Threat Logger:[/] Record verification failed")
    except Exception as e:
        console.print(f"  [bold red][✘] SQLite Threat Logger:[/] Error: {e}")

    # 3. Test Firewall Validation
    try:
        fw = FirewallManager(enabled=False)
        is_prot = fw.is_ip_protected("127.0.0.1")
        if is_prot:
            console.print("  [bold green][✔] Active Defense Engine:[/] OK (Self-lockout protection active)")
        else:
            console.print("  [bold red][✘] Active Defense Engine:[/] Loopback protection failed")
    except Exception as e:
        console.print(f"  [bold red][✘] Active Defense Engine:[/] Error: {e}")

    # 4. Test Native Wire Packet Generator
    try:
        from simulate_attack import build_dns_query_packet
        pkt_bytes = build_dns_query_packet("sample.test.internal", "TXT")
        if len(pkt_bytes) > 20:
            console.print("  [bold green][✔] DNS RFC 1035 Packet Engine:[/] OK (Native UDP payload encoder functional)")
    except Exception as e:
        console.print(f"  [bold red][✘] DNS Packet Generator:[/] Error: {e}")

    console.print("\n[bold green][✔] All diagnostic checks passed successfully![/bold green]\n")


def handle_history_query(db_path: str, count: int, console: Console) -> None:
    """Queries and renders historical threat log records from SQLite."""
    logger_db = ThreatLogger(db_path=db_path)
    records = logger_db.fetch_recent_threats(limit=count)

    console.print(
        f"\n[bold cyan]=== DNS-ExfilWatch Threat History (Last {len(records)} Events) ===[/bold cyan]\n"
    )
    if not records:
        console.print("[yellow]No threats recorded in the database yet.[/yellow]\n")
        return

    table = Table(box=box.ROUNDED, expand=True)
    table.add_column("ID", justify="center", width=5)
    table.add_column("Timestamp", justify="center", width=20)
    table.add_column("Source IP", justify="left", width=16)
    table.add_column("Type", justify="center", width=6)
    table.add_column("Entropy", justify="right", width=9)
    table.add_column("Risk", justify="right", width=6)
    table.add_column("Level", justify="center", width=14)
    table.add_column("Domain", justify="left", ratio=3)
    table.add_column("Action", justify="center", width=12)

    for r in records:
        lvl_style = "bold red" if r["risk_level"] == "Exfiltration" else "yellow"
        table.add_row(
            str(r["id"]),
            str(r["timestamp_iso"]),
            str(r["src_ip"]),
            str(r["record_type"]),
            f"{r['entropy']:.2f}",
            f"{r['risk_score']:.0f}",
            f"[{lvl_style}]{r['risk_level']}[/{lvl_style}]",
            str(r["domain"]),
            str(r["action_taken"]),
        )

    console.print(table)
    console.print()


def handle_flush_standalone(console: Console) -> None:
    """Standalone utility to purge any existing DNS-ExfilWatch iptables rules."""
    firewall = FirewallManager(enabled=True)
    if not firewall.is_linux:
        console.print("[yellow]Notice: Not running on Linux. iptables flush skipped.[/yellow]")
        return
    if not firewall.has_root:
        console.print("[bold red]Error: Root privileges required to flush iptables rules. Use sudo.[/bold red]")
        sys.exit(1)

    console.print("[bold yellow]Scanning and flushing DNS-ExfilWatch iptables rules...[/bold yellow]")
    cleaned = firewall.flush_all_labeled_rules()
    console.print(f"[bold green]Successfully flushed {cleaned} quarantine rules from iptables.[/bold green]")


def main() -> None:
    """CLI Entry Point."""
    parser = argparse.ArgumentParser(
        description="DNS-ExfilWatch: Real-Time DNS Tunneling Detection & Active Defense for Kali Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 main.py -i any --auto-block
  sudo python3 main.py -i lo
  python3 main.py --test
  python3 main.py --pcap capture.pcap
  python3 main.py --history 50
  sudo python3 main.py --flush-firewall
        """,
    )

    parser.add_argument(
        "-i",
        "--interface",
        type=str,
        default=None,
        help="Network interface to sniff (e.g. any, eth0, lo). Default: auto-detect all interfaces",
    )
    parser.add_argument(
        "-e",
        "--entropy",
        type=float,
        default=3.8,
        help="Shannon entropy threshold for domain labels (default: 3.8)",
    )
    parser.add_argument(
        "-l",
        "--length",
        type=int,
        default=35,
        help="Maximum normal label length threshold (default: 35)",
    )
    parser.add_argument(
        "--total-length",
        type=int,
        default=60,
        help="Maximum normal FQDN total length threshold (default: 60)",
    )
    parser.add_argument(
        "--auto-block",
        action="store_true",
        help="Active Defense: Automatically invoke iptables to drop traffic from malicious source IPs",
    )
    parser.add_argument(
        "--pcap",
        type=str,
        default=None,
        help="Analyze an offline PCAP file instead of live capture",
    )
    parser.add_argument(
        "--db",
        type=str,
        default="exfilwatch.db",
        help="Path to SQLite threat database file (default: exfilwatch.db)",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable the live Rich dashboard and output standard text logs",
    )
    parser.add_argument(
        "--history",
        type=int,
        nargs="?",
        const=25,
        help="Display recent threat history from the database and exit",
    )
    parser.add_argument(
        "--flush-firewall",
        action="store_true",
        help="Flush all active DNS-ExfilWatch iptables quarantine rules and exit",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Execute self-test diagnostic suite verifying all algorithms and DB",
    )

    args = parser.parse_args()
    console = Console()

    # Determine database path
    effective_db = args.db
    if effective_db == "exfilwatch.db" and not os.path.exists("exfilwatch.db"):
        effective_db = os.path.join(SCRIPT_DIR, "exfilwatch.db")

    # Standalone utilities
    if args.flush_firewall:
        handle_flush_standalone(console)
        return

    if args.history is not None:
        handle_history_query(effective_db, args.history, console)
        return

    if args.test:
        handle_self_test(console, effective_db)
        return

    # Root validation for live capture and active defense
    is_linux = sys.platform.startswith("linux")
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    if args.auto_block and not is_root and is_linux:
        console.print(
            "[bold red][!] Active defense (--auto-block) requires root permissions to execute iptables.[/bold red]"
        )
        console.print("[yellow]    Please execute with: sudo python3 main.py ...[/yellow]\n")
        sys.exit(1)

    print_banner(console)

    if not args.pcap and not is_root and is_linux:
        console.print(
            "[yellow][*] Warning: Live promiscuous packet capture without root may fail on some Linux interfaces.[/yellow]"
        )
        console.print("[dim]    Run with sudo if no packets appear.[/dim]\n")

    # Initialize subsystems
    analyzer = DNSAnalyzer(
        entropy_threshold=args.entropy,
        length_threshold=args.length,
        total_length_threshold=args.total_length,
    )

    firewall = FirewallManager(enabled=args.auto_block)
    logger_db = ThreatLogger(db_path=effective_db)

    # Determine default interface representation
    iface_display = args.pcap if args.pcap else (args.interface if args.interface else "All Interfaces (Auto)")

    # Plain text callback if dashboard disabled
    def plain_log_callback(res: AnalysisResult) -> None:
        iso = datetime.fromtimestamp(res.timestamp).strftime("%Y-%m-%d %H:%M:%S")
        if res.risk_level != RiskLevel.NORMAL:
            console.print(
                f"[{iso}] [bold red]{res.risk_level.value.upper()}[/] "
                f"IP={res.src_ip} Domain={res.query_name} Type={res.record_type} "
                f"Entropy={res.entropy_score:.2f} Risk={res.composite_risk_score:.0f} "
                f"Action={res.action_taken}"
            )
        else:
            console.print(
                f"[{iso}] [green]NORMAL[/] IP={res.src_ip} Domain={res.query_name} (Entropy={res.entropy_score:.2f})"
            )

    event_callback = plain_log_callback if args.no_dashboard else None

    # Sniffer engine initialization
    sniffer = SnifferEngine(
        analyzer=analyzer,
        firewall=firewall,
        logger_db=logger_db,
        interface=args.interface,
        pcap_file=args.pcap,
        on_event_callback=event_callback,
    )

    shutdown_flag = False

    def signal_handler(signum: int, frame: Any) -> None:
        nonlocal shutdown_flag
        shutdown_flag = True

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    console.print(
        f"[bold green][+] Starting Sniffer Engine on {iface_display}...[/bold green]"
    )
    if args.auto_block:
        console.print(
            "[bold red][!] ACTIVE DEFENSE ENABLED: Hostile IPs will be dynamically banned via iptables.[/bold red]"
        )
    else:
        console.print(
            "[cyan][i] Passive Audit Mode: Malicious traffic will be logged without blocking.[/cyan]"
        )

    try:
        sniffer.start()
        active_ifaces_str = ", ".join(sniffer.actual_interfaces)
        console.print(f"[bold green][+] Sniffer listening on: {active_ifaces_str}[/bold green]")
    except Exception as e:
        console.print(f"[bold red]Failed to start packet sniffer: {e}[/bold red]")
        sys.exit(1)

    time.sleep(0.5)

    dashboard = DashboardUI(
        console=console,
        interface=iface_display,
        entropy_thresh=args.entropy,
        length_thresh=args.length,
        auto_block=args.auto_block,
    )

    try:
        if not args.no_dashboard:
            with Live(
                dashboard.render_layout(sniffer.get_metrics_snapshot(), firewall),
                console=console,
                screen=True,
                refresh_per_second=4,
            ) as live:
                while not shutdown_flag:
                    metrics = sniffer.get_metrics_snapshot()
                    live.update(dashboard.render_layout(metrics, firewall))
                    time.sleep(0.25)
        else:
            console.print("[dim]Streaming packet logs in real time (Ctrl+C to stop)...[/dim]")
            while not shutdown_flag:
                time.sleep(0.5)

    except KeyboardInterrupt:
        pass
    finally:
        console.print("\n[bold yellow][*] Shutting down DNS-ExfilWatch sniffer engine...[/bold yellow]")
        sniffer.stop()

        if args.auto_block and firewall.quarantined_count > 0:
            console.print(
                f"\n[bold red][!] Session Quarantine Active:[/] {firewall.quarantined_count} IP(s) were blocked:"
            )
            for q_ip in firewall.quarantined_list:
                console.print(f"    - [red]{q_ip}[/]")

            console.print(
                "\n[bold cyan]Would you like to flush (unban) these iptables rules now? [Y/n]: [/bold cyan]",
                end="",
            )
            try:
                choice = sys.stdin.readline().strip().lower()
                if choice in ("", "y", "yes"):
                    flushed = firewall.flush_session_rules()
                    console.print(f"[bold green][+] Flushed {flushed} iptables session rules.[/bold green]")
                else:
                    console.print("[yellow][*] Quarantine rules retained in iptables.[/yellow]")
            except Exception:
                flushed = firewall.flush_session_rules()
                console.print(f"[bold green][+] Flushed {flushed} iptables session rules.[/bold green]")

        metrics = sniffer.get_metrics_snapshot()
        console.print("\n[bold cyan]=== Run Session Summary ===[/bold cyan]")
        console.print(f"Raw Packets Received:       {metrics['raw_packets']}")
        console.print(f"Total Packets Inspected:    {metrics['inspected']}")
        console.print(f"Suspicious Anomalies:       {metrics['warning']}")
        console.print(f"Exfiltration Incidents:     {metrics['malicious']}")
        console.print(f"Total IPs Quarantined:      {metrics['quarantined']}")
        console.print(f"Database Log File:          {effective_db}")
        console.print("[bold green][+] DNS-ExfilWatch terminated cleanly.[/bold green]\n")


if __name__ == "__main__":
    main()
