# DNS-ExfilWatch 🛡️
### Real-Time DNS Tunneling Detection & Active iptables Defense Engine for Kali Linux

[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Debian-blue.svg)](https://www.kali.org/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Packet%20Engine-Scapy-red.svg)](https://scapy.net/)
[![Rich](https://img.shields.io/badge/UI-Rich%20Terminal-orange.svg)](https://github.com/Textualize/rich)
[![Defense](https://img.shields.io/badge/Active%20Defense-Linux%20iptables-lightgrey.svg)](https://netfilter.org/)

---

## 1. Executive Summary & Threat Landscape

DNS tunneling is a prominent cyber espionage and data exfiltration technique employed by Advanced Persistent Threats (APTs) and modern malware (e.g., *Iodine*, *dnscat2*, *Cobalt Strike* DNS beacons). Because recursive DNS resolution requires standard enterprise firewalls to allow outbound UDP/TCP port 53 traffic, adversaries weaponize DNS lookups by encoding stolen data into subdomains:

$$\text{Attacker Client} \xrightarrow{\texttt{sq01-WW91clBhc3N3b3JkIQ.attacker-c2.net}} \text{Recursive Resolver} \xrightarrow{} \text{Authoritative Attacker Nameserver}$$

**DNS-ExfilWatch** is a production-grade, modular network defense utility developed natively for Kali Linux. It inspects live DNS traffic in promiscuous mode, executes statistical and heuristic anomaly analysis (Shannon entropy, structural depth, burst frequency, and record anomaly scoring), and automates dynamic quarantine via Linux kernel `iptables` drop rules.

---

## 2. Mathematical & Algorithmic Detection Engine

### 2.1 Shannon Entropy Calculation
Natural language domain names (e.g., `google.com`, `wikipedia.org`) exhibit predictable character repetition and low entropy. In contrast, Base64, Base32, or encrypted ciphertext payloads packed into subdomain labels maximize information density and randomness.

The exact Shannon Entropy $H(X)$ is computed as:

$$H(X) = - \sum_{i=1}^{n} P(x_i) \log_2 P(x_i)$$

Where:
- $X$ is the analyzed domain label.
- $x_i$ is a unique character in the label.
- $P(x_i) = \frac{\text{count}(x_i)}{N}$ is the empirical probability of character $x_i$ occurring.
- $N$ is the total length of the label.

| Domain Name / Label | Character Set | Typical Shannon Entropy $H(X)$ | Classification |
|---|---|---|---|
| `www.google.com` | English dictionary words | $2.15 - 2.50$ | Baseline / Normal |
| `updates.kali.org` | Technical keywords | $2.40 - 2.80$ | Baseline / Normal |
| `sq01-WW91clBhc3N3b3JkIQ.c2.net` | Base64 encoded payload | $3.95 - 4.60$ | **Exfiltration** |
| `a9f4c3b2e1d09876543210ab.c2.net` | Hexadecimal ciphertext | $3.85 - 4.30$ | **Exfiltration** |

### 2.2 Structural Length & Depth Heuristics
- **Label Length Anomaly**: While RFC 1035 allows up to 63 octets per label, standard domains rarely exceed 25 characters. DNS-ExfilWatch flags individual labels exceeding 35 characters.
- **FQDN Total Length**: Total FQDNs exceeding 60 characters (RFC 1035 allows up to 253 octets) receive significant length penalty scores.
- **Subdomain Depth**: Label hierarchies deeper than 4 levels (e.g., `a.b.c.d.domain.com`) are flagged as potential nested chunk streams.
- **Vowel / Consonant Ratio**: Encoded base64 and hex strings have low vowel ratios ($< 15\%$), distinguishing them from natural language.

### 2.3 Temporal Frequency & Burst Velocity
Exfiltration tools (such as `dnscat2`) transmit data in bursts of rapid queries. DNS-ExfilWatch maintains a thread-safe sliding-window velocity tracker (`IPVelocityTracker`) over a rolling 10-second window to compute real-time Queries Per Second (QPS) per source IP.

### 2.4 Suspicious Record Type Weights
- **TXT (Type 16)**: Highest exfiltration risk (used for bidirectional C2 downlinks and payload chunks).
- **NULL (Type 10)**: Raw binary payloads (e.g., `iodine`).
- **CNAME (Type 5)**: Hostname spoofing and aliasing channels.
- **A (Type 1) / AAAA (Type 28)**: Low base risk, but evaluated when combined with high entropy.

### 2.5 Composite Risk Scoring Model
The system computes a composite risk score $S \in [0, 100]$:

$$\text{RiskScore} = (0.40 \times S_{\text{entropy}}) + (0.25 \times S_{\text{length}}) + (0.20 \times S_{\text{frequency}}) + (0.15 \times S_{\text{record}})$$

- **$S \ge 75$**: **High-Severity DNS Exfiltration** $\rightarrow$ Triggers alert and optional active defense quarantine.
- **$50 \le S < 75$**: **Suspicious Warning** $\rightarrow$ Logged to database for forensics.
- **$S < 50$**: **Normal Traffic** $\rightarrow$ Allowed without disruption.

---

## 3. Modular Architecture

```
DNS-ExfilWatch/
├── analyzer.py          # Shannon entropy algorithms, length scoring, heuristics, SQLite logger
├── firewall.py          # Safe iptables active quarantine, IP validation, rule rollback
├── sniffer.py           # Scapy asynchronous packet sniffer & producer-consumer worker queue
├── main.py              # CLI entry point, argparse, Rich live dashboard & signal handler
├── simulate_attack.sh   # Live demo/viva attack simulation bash script (benign + exfil + burst)
├── requirements.txt     # Python dependencies (scapy, rich)
└── README.md            # Technical manual & operations guide
```

---

## 4. Kali Linux Installation & Setup

### Option A: One-Command Global Install (CLI & Search Bar Integration)
To register `DNS-ExfilWatch` as a native command in terminal AND in the **Kali Application Search Bar** (under `08 - Sniffing & Spoofing`):
```bash
cd ~/Desktop/DNS-ExfilWatch
chmod +x install.sh
sudo ./install.sh
```
Once installed:
- **In Kali Search Bar**: Press the `Super` (Windows) key and type `dns` or `exfil` to launch with one click!
- **In Terminal**: Run `sudo dns-exfilwatch -i any --auto-block` from any path.

---

### Option B: Manual In-Place Setup

#### Step 1: Install System Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip dnsutils iptables
```

#### Step 2: Install Python Libraries
```bash
cd ~/Desktop/DNS-ExfilWatch
pip3 install -r requirements.txt --break-system-packages
```

#### Step 3: Set Execution Permissions
```bash
chmod +x main.py simulate_attack.sh
```

---

## 5. Operations & Usage Guide

If installed globally via `install.sh`, replace `python3 main.py` with `dns-exfilwatch`!

### 5.1 Passive Audit Mode (Monitoring Only)
Sniffs live traffic on an interface (e.g., `eth0`, `wlan0`, or `any`) without executing firewall blocks:
```bash
sudo dns-exfilwatch -i any
# OR manually: sudo python3 main.py -i any
```

### 5.2 Active Defense Mode (Automated iptables Quarantine)
Inspects traffic and dynamically executes `iptables -I INPUT 1 -s <MALICIOUS_IP> -j DROP` when composite risk score $\ge 75$:
```bash
sudo dns-exfilwatch -i any --auto-block
# OR manually: sudo python3 main.py -i any --auto-block
```

### 5.3 Custom Thresholds Tuning
Tune entropy and length thresholds to suit strict enterprise environments:
```bash
sudo python3 main.py -i eth0 -e 3.6 -l 30 --auto-block
```

### 5.4 Offline Forensics & PCAP Analysis
Replay an existing packet capture file for incident response investigation:
```bash
python3 main.py --pcap sample_exfil.pcap
```

### 5.5 Forensic Audit History
Query persistent threat logs saved in the SQLite database (`exfilwatch.db`):
```bash
python3 main.py --history 50
```

### 5.6 Emergency Firewall Cleanup
Flush all residual quarantine rules inserted by DNS-ExfilWatch:
```bash
sudo python3 main.py --flush-firewall
```

---

## 6. Live Viva & Demonstration Walkthrough

Follow these steps to demonstrate the tool during an evaluation, presentation, or viva:

### Terminal 1: Launch DNS-ExfilWatch with Active Defense
```bash
sudo python3 main.py -i any --auto-block
```
The **Rich Terminal Dashboard** will render, showing:
- Active Defense mode enabled.
- Real-time traffic statistics (Packets, Warnings, Exfil Alerts, Quarantined IPs).
- Live query stream table.

### Terminal 2: Run the Attack Simulator
In a second terminal window, trigger the automated attack script:
```bash
./simulate_attack.sh -s 127.0.0.1 -m all
```

#### What Happens During the Demo:
1. **Stage 1 (Benign Traffic)**: The script queries `google.com`, `github.com`, etc.
   - *Observation*: Tool computes entropy $< 2.5$, risk $< 40$, classified as **NORMAL (ALLOWED)**.
2. **Stage 2 (Exfiltration Attack)**: The script chunks base64-encoded confidential credentials into subdomains (`sq01-WW91cl...c2-exfil-listener.net`).
   - *Observation*: Entropy spikes to $> 4.10$, label length exceeds 35, composite risk score hits **$\ge 80$**, classified as **EXFILTRATION**.
   - *Active Defense*: Offending source IP is blocked in `iptables`.
3. **Stage 3 (Burst Flooding)**: High-speed queries trigger velocity alerts.

### Terminal 3: Verify iptables Drop Rules (Optional)
Inspect the Linux kernel firewall to verify the live drop rule:
```bash
sudo iptables -L INPUT -n -v
```
You will observe:
```
DROP  all  --  <ATTACKER_IP>  0.0.0.0/0  /* DNS-ExfilWatch Quarantine */
```

### Safe Teardown:
Press `Ctrl+C` in Terminal 1. The built-in signal handler prompts you to automatically flush the quarantine rule so your test environment is restored cleanly!
