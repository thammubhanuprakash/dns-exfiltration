#!/usr/bin/env bash
# ==============================================================================
# DNS-ExfilWatch - Global System Installer for Kali Linux
# Author: Senior Cyber Security Engineer & Systems Software Developer
# Platform: Kali Linux / Debian / Ubuntu
#
# Purpose:
#   1. Installs DNS-ExfilWatch as a first-class, system-wide command in Kali Linux
#      (accessible via terminal: dns-exfilwatch).
#   2. Integrates with Kali Linux Application Search Bar & Whisker Menu
#      (Category: 08 - Sniffing & Spoofing).
#
# Usage:
#   sudo ./install.sh             # Install globally + Search Bar launcher
#   sudo ./install.sh --uninstall # Remove from system
# ==============================================================================

set -e

# ANSI Colors
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
CYAN="\033[1;36m"
WHITE="\033[1;37m"
BOLD="\033[1m"
RESET="\033[0m"

INSTALL_DIR="/opt/dns-exfilwatch"
BIN_LINK="/usr/local/bin/dns-exfilwatch"
SIM_LINK="/usr/local/bin/dns-exfilwatch-sim"
DESKTOP_ENTRY_DIR="/usr/share/applications"
ICON_DIR_SCALABLE="/usr/share/icons/hicolor/scalable/apps"
ICON_DIR_PIXMAPS="/usr/share/pixmaps"
SCRIPT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Verify root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Error: Installation requires root privileges.${RESET}"
    echo -e "${YELLOW}[*] Please run: sudo ./install.sh${RESET}"
    exit 1
fi

uninstall_tool() {
    echo -e "${YELLOW}[*] Uninstalling DNS-ExfilWatch from Kali Linux...${RESET}"
    rm -f "$BIN_LINK"
    rm -f "$SIM_LINK"
    rm -f "$DESKTOP_ENTRY_DIR/dns-exfilwatch.desktop"
    rm -f "$DESKTOP_ENTRY_DIR/dns-exfilwatch-sim.desktop"
    rm -f "$ICON_DIR_SCALABLE/dns-exfilwatch.svg"
    rm -f "$ICON_DIR_PIXMAPS/dns-exfilwatch.svg"
    rm -rf "$INSTALL_DIR"

    # Refresh desktop and icon database
    command -v update-desktop-database &> /dev/null && update-desktop-database "$DESKTOP_ENTRY_DIR" 2>/dev/null || true
    command -v gtk-update-icon-cache &> /dev/null && gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true

    echo -e "${GREEN}[+] Successfully removed DNS-ExfilWatch from system and application menus.${RESET}"
    exit 0
}

if [ "$1" = "--uninstall" ] || [ "$1" = "-u" ]; then
    uninstall_tool
fi

echo -e "${CYAN}"
echo "======================================================================"
echo "      Installing DNS-ExfilWatch into Kali Linux (CLI & Search Bar)    "
echo "======================================================================"
echo -e "${RESET}"

# Step 1: Install System Packages
echo -e "${YELLOW}[1/5] Checking and installing system dependencies...${RESET}"
apt-get update -qq
apt-get install -y -qq python3 python3-pip dnsutils iptables > /dev/null 2>&1
echo -e "${GREEN}[+] System dependencies verified (python3, pip, dnsutils, iptables).${RESET}"

# Step 2: Install Python Packages
echo -e "${YELLOW}[2/5] Installing Python requirements (Scapy, Rich)...${RESET}"
if [ -f "$SCRIPT_SRC/requirements.txt" ]; then
    pip3 install -r "$SCRIPT_SRC/requirements.txt" --break-system-packages -q
else
    pip3 install scapy rich --break-system-packages -q
fi
echo -e "${GREEN}[+] Python packages installed successfully.${RESET}"

# Step 3: Copy Files to /opt/dns-exfilwatch
echo -e "${YELLOW}[3/5] Deploying core files to ${INSTALL_DIR}...${RESET}"
mkdir -p "$INSTALL_DIR"
cp -r "$SCRIPT_SRC"/* "$INSTALL_DIR"/ 2>/dev/null || true
chmod +x "$INSTALL_DIR/main.py"
chmod +x "$INSTALL_DIR/simulate_attack.sh"
[ -f "$INSTALL_DIR/simulate_attack.py" ] && chmod +x "$INSTALL_DIR/simulate_attack.py"

# Step 4: Create Global CLI Commands in /usr/local/bin
echo -e "${YELLOW}[4/5] Creating global CLI commands in /usr/local/bin/...${RESET}"

# Wrapper for main tool
cat << 'EOF' > "$BIN_LINK"
#!/usr/bin/env bash
python3 /opt/dns-exfilwatch/main.py "$@"
EOF
chmod +x "$BIN_LINK"

# Wrapper for attack simulator
cat << 'EOF' > "$SIM_LINK"
#!/usr/bin/env bash
/opt/dns-exfilwatch/simulate_attack.sh "$@"
EOF
chmod +x "$SIM_LINK"
echo -e "${GREEN}[+] Global commands created: 'dns-exfilwatch' and 'dns-exfilwatch-sim'.${RESET}"

# Step 5: Install Desktop Launchers and Icons into Search Bar / App Menu
echo -e "${YELLOW}[5/5] Registering with Kali Application Search Bar & Categories...${RESET}"

# Install SVG Icon
mkdir -p "$ICON_DIR_SCALABLE" "$ICON_DIR_PIXMAPS"
if [ -f "$SCRIPT_SRC/dns-exfilwatch.svg" ]; then
    cp "$SCRIPT_SRC/dns-exfilwatch.svg" "$ICON_DIR_SCALABLE/dns-exfilwatch.svg"
    cp "$SCRIPT_SRC/dns-exfilwatch.svg" "$ICON_DIR_PIXMAPS/dns-exfilwatch.svg"
fi

# Install Desktop Entry for Main Tool
cat << 'EOF' > "$DESKTOP_ENTRY_DIR/dns-exfilwatch.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=DNS-ExfilWatch
GenericName=DNS Tunneling Detection & Active Defense
Comment=Real-Time DNS Exfiltration Intrusion Detection & iptables Quarantine
Exec=x-terminal-emulator -e "bash -c 'sudo /usr/local/bin/dns-exfilwatch -i any --auto-block; bash'"
Icon=dns-exfilwatch
Terminal=false
Categories=08-sniffing-spoofing;Security;Network;System;
Keywords=dns;exfil;tunnel;exfiltration;firewall;iptables;sniff;watch;security;defense;
StartupNotify=true
EOF

# Install Desktop Entry for Attack Simulator
cat << 'EOF' > "$DESKTOP_ENTRY_DIR/dns-exfilwatch-sim.desktop"
[Desktop Entry]
Version=1.0
Type=Application
Name=DNS-ExfilWatch Attack Simulator
GenericName=DNS Tunneling Attack Simulator
Comment=Simulates chunked Base64 DNS exfiltration queries for testing and viva demos
Exec=x-terminal-emulator -e "bash -c '/usr/local/bin/dns-exfilwatch-sim -m all; bash'"
Icon=dns-exfilwatch
Terminal=false
Categories=08-sniffing-spoofing;Security;Network;System;
Keywords=dns;attack;simulator;exfil;tunnel;viva;demo;
StartupNotify=true
EOF

chmod 644 "$DESKTOP_ENTRY_DIR/dns-exfilwatch.desktop"
chmod 644 "$DESKTOP_ENTRY_DIR/dns-exfilwatch-sim.desktop"

# Force desktop search database & icon caches to refresh immediately
if command -v update-desktop-database &> /dev/null; then
    update-desktop-database "$DESKTOP_ENTRY_DIR" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache &> /dev/null; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
fi

echo -e "${GREEN}[+] Desktop search entries and cybersecurity icon registered.${RESET}"

echo ""
echo -e "${GREEN}======================================================================${RESET}"
echo -e "${GREEN}${BOLD}[✔] Installation Complete! DNS-ExfilWatch is now fully integrated.${RESET}"
echo -e "${GREEN}======================================================================${RESET}"
echo ""
echo -e "${WHITE}1. ${BOLD}In Kali Search Bar:${RESET} Press the 'Super' (Windows) key or open the"
echo -e "   Kali Application Menu and search for: ${CYAN}dns${RESET}, ${CYAN}exfil${RESET}, or ${CYAN}dns-exfilwatch${RESET}."
echo ""
echo -e "2. ${BOLD}In Terminal (from ANY folder):${RESET}"
echo -e "   ${CYAN}sudo dns-exfilwatch -i any --auto-block${RESET}   # Real-time capture & quarantine"
echo -e "   ${CYAN}dns-exfilwatch --help${RESET}                     # View command-line flags"
echo -e "   ${CYAN}dns-exfilwatch --history 50${RESET}               # View SQLite threat logs"
echo -e "   ${CYAN}dns-exfilwatch-sim -m all${RESET}                 # Run live attack simulation"
echo ""
echo -e "${YELLOW}To uninstall:${RESET} sudo ./install.sh --uninstall\n"
