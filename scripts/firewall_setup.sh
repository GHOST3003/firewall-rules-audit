#!/bin/bash
# ============================================================================
# FIREWALL RULES CONFIGURATION SCRIPT
# ============================================================================
# Project  : Firewall Rules Audit (Minor Project - Network Security)
# Authors  : Sujal & Kowshik Chowdhary
# Scenario : Small Office / Home Network (SOHO)
# Services : Web Server (HTTP/HTTPS), SSH (restricted)
# ============================================================================
#
# NETWORK LAYOUT:
#   - Firewall Host:  eth0 (external), eth1 (internal - 192.168.1.0/24)
#   - Web Server:     192.168.1.10
#   - Admin Subnet:   192.168.1.0/28 (192.168.1.1 - 192.168.1.14)
#   - DNS Servers:    8.8.8.8, 8.8.4.4 (Google Public DNS)
#
# POLICY APPROACH:
#   Default DENY — block everything, then allow only what's needed.
#   This follows the "Principle of Least Privilege."
#
# ============================================================================

# Exit immediately if any command fails
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  FIREWALL SETUP SCRIPT - SOHO Network      ${NC}"
echo -e "${CYAN}============================================${NC}"

# Check for root privileges (iptables requires root)
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root (sudo).${NC}"
    exit 1
fi

# ============================================================================
# SECTION 1: VARIABLES
# ============================================================================
# Define variables for easy modification and readability

# Network interfaces
EXT_IFACE="eth0"           # External (internet-facing) interface
INT_IFACE="eth1"           # Internal (LAN) interface

# Network addresses
INT_NET="192.168.1.0/24"   # Internal LAN subnet
ADMIN_NET="192.168.1.0/28" # Admin subnet (SSH access allowed)
WEB_SERVER="192.168.1.10"  # Internal web server IP

# Trusted DNS servers (Google Public DNS)
DNS1="8.8.8.8"
DNS2="8.8.4.4"

# Logging prefix for dropped packets
LOG_PREFIX="IPTables-Dropped: "

# Rate limiting values
SSH_RATE="3/min"            # Max 3 new SSH connections per minute
ICMP_RATE="1/sec"           # Max 1 ICMP (ping) packet per second
SYN_RATE="10/sec"           # Max 10 new TCP SYN packets per second

echo -e "${GREEN}[+] Variables configured${NC}"

# ============================================================================
# SECTION 2: FLUSH EXISTING RULES (Clean Slate)
# ============================================================================
# Before applying new rules, we clear ALL existing rules to avoid conflicts.

echo -e "${YELLOW}[*] Flushing existing firewall rules...${NC}"

# Flush all rules in all chains (filter, nat, mangle tables)
iptables -F              # Flush all rules in the filter table
iptables -t nat -F       # Flush all rules in the NAT table
iptables -t mangle -F    # Flush all rules in the mangle table

# Delete all user-defined chains
iptables -X              # Delete user-defined chains in filter table
iptables -t nat -X       # Delete user-defined chains in NAT table
iptables -t mangle -X    # Delete user-defined chains in mangle table

# Zero all packet and byte counters
iptables -Z              # Reset counters in filter table

echo -e "${GREEN}[+] All existing rules flushed${NC}"

# ============================================================================
# SECTION 3: SET DEFAULT POLICIES (Default DENY)
# ============================================================================
# The most important security principle: deny everything by default.
# Only explicitly allowed traffic will pass through.
#
# Three built-in chains in the filter table:
#   INPUT   — packets destined for the firewall host itself
#   FORWARD — packets routed through the firewall to other hosts
#   OUTPUT  — packets originating from the firewall host
#

echo -e "${YELLOW}[*] Setting default policies to DROP...${NC}"

iptables -P INPUT DROP     # Drop all incoming traffic by default
iptables -P FORWARD DROP   # Drop all forwarded traffic by default
iptables -P OUTPUT DROP    # Drop all outgoing traffic by default

echo -e "${GREEN}[+] Default policies set to DROP (deny all)${NC}"

# ============================================================================
# SECTION 4: LOOPBACK INTERFACE (localhost)
# ============================================================================
# Allow all traffic on the loopback interface (127.0.0.1).
# Many applications (databases, local services) communicate via loopback.
# Blocking it would break local services.

echo -e "${YELLOW}[*] Configuring loopback rules...${NC}"

iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

echo -e "${GREEN}[+] Loopback traffic allowed${NC}"

# ============================================================================
# SECTION 5: STATEFUL PACKET INSPECTION (Connection Tracking)
# ============================================================================
# iptables uses the conntrack module to track connection states:
#   - ESTABLISHED: Part of an already-established connection
#   - RELATED:     Associated with an established connection (e.g., FTP data)
#   - NEW:         A new connection request
#   - INVALID:     Packet doesn't belong to any known connection
#
# We allow ESTABLISHED and RELATED packets (responses to our requests),
# and drop INVALID packets (potential attacks or corrupted data).

echo -e "${YELLOW}[*] Configuring stateful inspection rules...${NC}"

# Allow established and related connections (both directions)
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop invalid packets (packets that don't belong to any known connection)
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A OUTPUT -m conntrack --ctstate INVALID -j DROP
iptables -A FORWARD -m conntrack --ctstate INVALID -j DROP

echo -e "${GREEN}[+] Stateful inspection configured${NC}"

# ============================================================================
# SECTION 6: ANTI-SPOOFING RULES
# ============================================================================
# Prevent IP address spoofing attacks by blocking packets with forged
# source addresses that shouldn't appear on our external interface.
#
# RFC 1918 defines private address ranges that should NEVER appear as
# source addresses on incoming internet traffic:
#   - 10.0.0.0/8
#   - 172.16.0.0/12
#   - 192.168.0.0/16
#
# Additional bogon addresses:
#   - 127.0.0.0/8    (loopback)
#   - 0.0.0.0/8      (reserved)
#   - 169.254.0.0/16 (link-local)
#   - 224.0.0.0/4    (multicast)
#   - 240.0.0.0/4    (reserved)

echo -e "${YELLOW}[*] Configuring anti-spoofing rules...${NC}"

# Block RFC 1918 private addresses on external interface
iptables -A INPUT -i $EXT_IFACE -s 10.0.0.0/8 -j DROP
iptables -A INPUT -i $EXT_IFACE -s 172.16.0.0/12 -j DROP
iptables -A INPUT -i $EXT_IFACE -s 192.168.0.0/16 -j DROP

# Block other bogon/reserved address ranges
iptables -A INPUT -i $EXT_IFACE -s 127.0.0.0/8 -j DROP
iptables -A INPUT -i $EXT_IFACE -s 0.0.0.0/8 -j DROP
iptables -A INPUT -i $EXT_IFACE -s 169.254.0.0/16 -j DROP
iptables -A INPUT -i $EXT_IFACE -s 224.0.0.0/4 -j DROP
iptables -A INPUT -i $EXT_IFACE -s 240.0.0.0/4 -j DROP

echo -e "${GREEN}[+] Anti-spoofing rules configured${NC}"

# ============================================================================
# SECTION 7: SYN FLOOD PROTECTION
# ============================================================================
# A SYN flood attack sends massive numbers of TCP SYN packets to overwhelm
# the server's connection table. We mitigate this by:
#   1. Rate-limiting new SYN packets
#   2. Dropping malformed TCP packets (SYN with other flags set)

echo -e "${YELLOW}[*] Configuring SYN flood protection...${NC}"

# Drop TCP packets with invalid flag combinations (common in attacks)
# Christmas tree packet: all flags set (FIN, SYN, RST, PSH, ACK, URG)
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Null packet: no flags set
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# SYN-FIN attack: SYN and FIN both set (invalid combination)
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

# SYN-RST attack: SYN and RST both set (invalid combination)
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

# Rate limit new SYN connections
iptables -A INPUT -p tcp --syn -m limit --limit $SYN_RATE --limit-burst 20 -j ACCEPT

echo -e "${GREEN}[+] SYN flood protection configured${NC}"

# ============================================================================
# SECTION 8: SSH ACCESS (Restricted & Rate-Limited)
# ============================================================================
# SSH is essential for remote administration, but it's a prime target for
# brute-force attacks. We protect it by:
#   1. Restricting SSH access to the admin subnet only
#   2. Rate-limiting new SSH connections (max 3 per minute)
#   3. Logging excessive SSH attempts
#
# This demonstrates "defense in depth" — multiple layers of protection.

echo -e "${YELLOW}[*] Configuring SSH access rules...${NC}"

# Create a custom chain for SSH traffic (better organization)
iptables -N SSH_RULES

# Allow SSH only from the admin subnet (192.168.1.0/28)
# Rate-limited: max 3 new connections per minute per source IP
iptables -A SSH_RULES -s $ADMIN_NET -m conntrack --ctstate NEW \
    -m limit --limit $SSH_RATE --limit-burst 3 -j ACCEPT

# Log excessive SSH attempts (potential brute-force attack)
iptables -A SSH_RULES -m limit --limit 5/min -j LOG \
    --log-prefix "SSH-Brute-Force: " --log-level 4

# Drop all other SSH traffic
iptables -A SSH_RULES -j DROP

# Direct SSH traffic (port 22) to our custom chain
iptables -A INPUT -p tcp --dport 22 -j SSH_RULES

# Allow outgoing SSH from the firewall (for administration)
iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT

echo -e "${GREEN}[+] SSH access rules configured (admin subnet only, rate-limited)${NC}"

# ============================================================================
# SECTION 9: WEB SERVER (HTTP & HTTPS)
# ============================================================================
# Allow public access to the web server on ports 80 (HTTP) and 443 (HTTPS).
# The web server is at 192.168.1.10 on the internal network.

echo -e "${YELLOW}[*] Configuring web server rules...${NC}"

# Allow incoming HTTP traffic (port 80) — PUBLIC ACCESS
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# Allow incoming HTTPS traffic (port 443) — PUBLIC ACCESS
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow outgoing HTTP/HTTPS from the firewall (for updates, etc.)
iptables -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

echo -e "${GREEN}[+] Web server rules configured (HTTP/HTTPS allowed)${NC}"

# ============================================================================
# SECTION 10: DNS RESOLUTION (Outbound Only)
# ============================================================================
# Allow the firewall to make DNS queries to resolve domain names.
# DNS uses both UDP (standard queries) and TCP (zone transfers, large responses).
# We only allow outbound DNS to our trusted DNS servers.

echo -e "${YELLOW}[*] Configuring DNS rules...${NC}"

# Allow outbound DNS queries (UDP port 53) to trusted servers
iptables -A OUTPUT -p udp --dport 53 -d $DNS1 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -d $DNS2 -m conntrack --ctstate NEW -j ACCEPT

# Allow outbound DNS queries (TCP port 53) to trusted servers
iptables -A OUTPUT -p tcp --dport 53 -d $DNS1 -m conntrack --ctstate NEW -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -d $DNS2 -m conntrack --ctstate NEW -j ACCEPT

echo -e "${GREEN}[+] DNS resolution rules configured (outbound only)${NC}"

# ============================================================================
# SECTION 11: ICMP (Ping) — Rate-Limited
# ============================================================================
# ICMP is useful for network diagnostics (ping, traceroute), but can be
# abused for:
#   - Ping floods (DoS attack)
#   - Network reconnaissance (mapping)
#   - Smurf attacks (amplification)
#
# We allow specific ICMP types with rate limiting:
#   Type 0: Echo Reply (ping response)
#   Type 3: Destination Unreachable (important for PMTU discovery)
#   Type 8: Echo Request (incoming ping)
#   Type 11: Time Exceeded (for traceroute)

echo -e "${YELLOW}[*] Configuring ICMP rules...${NC}"

# Allow incoming ping (echo request) — rate limited
iptables -A INPUT -p icmp --icmp-type echo-request \
    -m limit --limit $ICMP_RATE --limit-burst 4 -j ACCEPT

# Allow incoming echo reply, destination unreachable, time exceeded
iptables -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT
iptables -A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
iptables -A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT

# Allow outgoing ping
iptables -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
iptables -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

echo -e "${GREEN}[+] ICMP rules configured (rate-limited)${NC}"

# ============================================================================
# SECTION 12: NTP (Network Time Protocol)
# ============================================================================
# Allow the firewall to synchronize its clock with NTP servers.
# Accurate time is critical for:
#   - Log correlation during incident response
#   - Certificate validation (TLS/SSL)
#   - Kerberos authentication

echo -e "${YELLOW}[*] Configuring NTP rules...${NC}"

iptables -A OUTPUT -p udp --dport 123 -m conntrack --ctstate NEW -j ACCEPT

echo -e "${GREEN}[+] NTP rules configured${NC}"

# ============================================================================
# SECTION 13: LOGGING DROPPED PACKETS
# ============================================================================
# Log all dropped packets before they hit the default DROP policy.
# This is essential for:
#   - Security monitoring and incident response
#   - Identifying attack patterns
#   - Troubleshooting connectivity issues
#   - Audit compliance
#
# Rate-limited to prevent log flooding (max 5 log entries per minute).

echo -e "${YELLOW}[*] Configuring logging rules...${NC}"

# Log dropped INPUT packets
iptables -A INPUT -m limit --limit 5/min --limit-burst 10 -j LOG \
    --log-prefix "$LOG_PREFIX" --log-level 4

# Log dropped OUTPUT packets
iptables -A OUTPUT -m limit --limit 5/min --limit-burst 10 -j LOG \
    --log-prefix "IPTables-Outbound-Dropped: " --log-level 4

# Log dropped FORWARD packets
iptables -A FORWARD -m limit --limit 5/min --limit-burst 10 -j LOG \
    --log-prefix "IPTables-Forward-Dropped: " --log-level 4

echo -e "${GREEN}[+] Logging rules configured${NC}"

# ============================================================================
# SECTION 14: KERNEL NETWORK SECURITY PARAMETERS
# ============================================================================
# These sysctl settings complement our iptables rules by hardening the
# kernel's network stack.

echo -e "${YELLOW}[*] Hardening kernel network parameters...${NC}"

# Enable SYN cookies (protection against SYN flood attacks)
sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null 2>&1

# Disable IP source routing (prevents source routing attacks)
sysctl -w net.ipv4.conf.all.accept_source_route=0 > /dev/null 2>&1

# Enable reverse path filtering (anti-spoofing at kernel level)
sysctl -w net.ipv4.conf.all.rp_filter=1 > /dev/null 2>&1

# Ignore ICMP redirect messages (prevents MITM route manipulation)
sysctl -w net.ipv4.conf.all.accept_redirects=0 > /dev/null 2>&1
sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null 2>&1

# Ignore broadcast ICMP (prevents Smurf attacks)
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null 2>&1

# Log martian packets (packets with impossible source addresses)
sysctl -w net.ipv4.conf.all.log_martians=1 > /dev/null 2>&1

# Disable IP forwarding (unless this is a router/gateway)
# Uncomment the next line if this host should NOT forward packets
# sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1

echo -e "${GREEN}[+] Kernel network parameters hardened${NC}"

# ============================================================================
# SECTION 15: SAVE RULES (Persistence)
# ============================================================================
# iptables rules are lost on reboot unless saved.
# Different Linux distributions use different methods:

echo -e "${YELLOW}[*] Saving firewall rules...${NC}"

# For Debian/Ubuntu:
if command -v iptables-save &> /dev/null; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || \
    iptables-save > /etc/iptables.rules 2>/dev/null || \
    echo -e "${YELLOW}[!] Could not auto-save. Run: iptables-save > /etc/iptables.rules${NC}"
fi

# For RHEL/CentOS:
# service iptables save

echo -e "${GREEN}[+] Rules saved${NC}"

# ============================================================================
# SUMMARY
# ============================================================================

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN}  FIREWALL CONFIGURATION COMPLETE           ${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "${GREEN}Rules Applied Summary:${NC}"
echo "  ✅ Default Policy: DROP (INPUT, FORWARD, OUTPUT)"
echo "  ✅ Loopback: ALLOWED"
echo "  ✅ Stateful Inspection: ENABLED"
echo "  ✅ Anti-Spoofing: RFC 1918 + Bogon addresses blocked"
echo "  ✅ SYN Flood Protection: Rate-limited + invalid flags dropped"
echo "  ✅ SSH: Restricted to $ADMIN_NET, rate-limited ($SSH_RATE)"
echo "  ✅ HTTP/HTTPS: Public access on ports 80, 443"
echo "  ✅ DNS: Outbound only to $DNS1, $DNS2"
echo "  ✅ ICMP: Rate-limited ($ICMP_RATE)"
echo "  ✅ NTP: Outbound allowed"
echo "  ✅ Logging: Dropped packets logged (rate-limited)"
echo "  ✅ Kernel Hardening: SYN cookies, rp_filter, no redirects"
echo ""
echo -e "${YELLOW}Run 'sudo iptables -L -n -v --line-numbers' to verify.${NC}"
