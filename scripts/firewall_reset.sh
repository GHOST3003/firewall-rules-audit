#!/bin/bash
# ============================================================================
# FIREWALL RESET SCRIPT
# ============================================================================
# Flushes all iptables rules and sets default policies to ACCEPT.
# Use this to restore the firewall to a completely open state.
#
# ⚠️  WARNING: Running this script will remove ALL firewall protection!
#     Only use in a lab environment or when reconfiguring the firewall.
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root (sudo).${NC}"
    exit 1
fi

echo -e "${YELLOW}⚠️  WARNING: This will remove ALL firewall rules!${NC}"
echo -e "${YELLOW}   The system will be UNPROTECTED after this.${NC}"
echo ""
read -p "Are you sure? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    echo -e "${GREEN}[+] Aborted. No changes made.${NC}"
    exit 0
fi

echo -e "${YELLOW}[*] Flushing all iptables rules...${NC}"

# Set default policies to ACCEPT (allow all)
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# Flush all rules in all tables
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -t raw -F

# Delete all user-defined chains
iptables -X
iptables -t nat -X
iptables -t mangle -X
iptables -t raw -X

# Zero all counters
iptables -Z

echo -e "${GREEN}[+] All firewall rules have been flushed.${NC}"
echo -e "${RED}[!] System is now UNPROTECTED. Apply new rules immediately.${NC}"
