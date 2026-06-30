#!/bin/bash
# ============================================================================
# FIREWALL STATUS SCRIPT
# ============================================================================
# Displays current iptables rules in a formatted, readable output.
# Useful for verification and documentation purposes.
# ============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root (sudo).${NC}"
    exit 1
fi

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  FIREWALL STATUS REPORT                    ${NC}"
echo -e "${CYAN}  Generated: $(date)     ${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# ---- Filter Table (Main Firewall Rules) ----
echo -e "${BOLD}${GREEN}═══ FILTER TABLE (Main Rules) ═══${NC}"
echo ""
iptables -L -n -v --line-numbers
echo ""

# ---- NAT Table ----
echo -e "${BOLD}${GREEN}═══ NAT TABLE ═══${NC}"
echo ""
iptables -t nat -L -n -v --line-numbers
echo ""

# ---- Mangle Table ----
echo -e "${BOLD}${GREEN}═══ MANGLE TABLE ═══${NC}"
echo ""
iptables -t mangle -L -n -v --line-numbers
echo ""

# ---- Rule Count Summary ----
echo -e "${BOLD}${YELLOW}═══ RULE COUNT SUMMARY ═══${NC}"
echo ""
echo -e "  Filter table rules : $(iptables -L -n | grep -c '^[A-Z]' 2>/dev/null || echo 'N/A')"
echo -e "  NAT table rules    : $(iptables -t nat -L -n | grep -c '^[A-Z]' 2>/dev/null || echo 'N/A')"
echo -e "  Mangle table rules : $(iptables -t mangle -L -n | grep -c '^[A-Z]' 2>/dev/null || echo 'N/A')"
echo ""

# ---- Default Policies ----
echo -e "${BOLD}${YELLOW}═══ DEFAULT POLICIES ═══${NC}"
echo ""
iptables -L -n | grep "^Chain" | while read -r line; do
    chain=$(echo "$line" | awk '{print $2}')
    policy=$(echo "$line" | grep -oP '\(policy \K[A-Z]+')
    if [[ "$policy" == "DROP" ]]; then
        echo -e "  $chain: ${GREEN}$policy ✅ (Secure)${NC}"
    elif [[ "$policy" == "ACCEPT" ]]; then
        echo -e "  $chain: ${RED}$policy ❌ (Insecure - allows all)${NC}"
    else
        echo -e "  $chain: $policy"
    fi
done
echo ""

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  Status report complete.                   ${NC}"
echo -e "${CYAN}============================================${NC}"
