#!/usr/bin/env python3
import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
"""
============================================================================
FIREWALL RULES AUDIT SCRIPT
============================================================================
Project  : Firewall Rules Audit (Minor Project - Network Security)
Authors  : Sujal & Kowshik Chowdhary

Description:
    This script parses the output of 'iptables -L -n -v --line-numbers'
    and performs a comprehensive security audit of the firewall rules.
    
    It checks for:
    - Default deny policies
    - Stateful inspection (conntrack)
    - Anti-spoofing rules
    - SSH hardening
    - Rate limiting
    - Logging configuration
    - Common misconfigurations
    - Egress filtering
    - ICMP restrictions

Usage:
    # Option 1: Audit from live iptables (requires root)
    sudo iptables -L -n -v --line-numbers > audit/sample_iptables_output.txt
    python3 audit/audit_firewall.py

    # Option 2: Audit the bundled sample output
    python3 audit/audit_firewall.py
============================================================================
"""

import re
import sys
import os
from datetime import datetime
from collections import defaultdict


# ============================================================================
# ANSI COLOR CODES (for terminal output formatting)
# ============================================================================
class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


# ============================================================================
# STATUS INDICATORS
# ============================================================================
PASS = f"{Colors.GREEN}✅ PASS{Colors.RESET}"
FAIL = f"{Colors.RED}❌ FAIL{Colors.RESET}"
WARN = f"{Colors.YELLOW}⚠️  WARNING{Colors.RESET}"
INFO = f"{Colors.BLUE}ℹ️  INFO{Colors.RESET}"


# ============================================================================
# FIREWALL RULE PARSER
# ============================================================================
class FirewallRule:
    """Represents a single iptables rule parsed from the output."""
    
    def __init__(self, raw_line, chain_name):
        self.raw = raw_line.strip()
        self.chain = chain_name
        self.packets = 0
        self.bytes = 0
        self.target = ""
        self.protocol = ""
        self.opt = ""
        self.in_iface = ""
        self.out_iface = ""
        self.source = ""
        self.destination = ""
        self.details = ""
        self._parse()
    
    def _parse(self):
        """Parse a single iptables rule line into its components."""
        # Match the standard iptables -L -n -v output format
        # Format: pkts bytes target prot opt in out source destination [options]
        parts = self.raw.split()
        if len(parts) >= 9:
            try:
                self.packets = int(parts[0])
                self.bytes = int(parts[1])
            except ValueError:
                pass
            self.target = parts[2]
            self.protocol = parts[3]
            self.opt = parts[4]
            self.in_iface = parts[5]
            self.out_iface = parts[6]
            self.source = parts[7]
            self.destination = parts[8]
            if len(parts) > 9:
                self.details = " ".join(parts[9:])
    
    def __str__(self):
        return (f"[{self.chain}] {self.target:10s} {self.protocol:5s} "
                f"{self.source:20s} -> {self.destination:20s} {self.details}")


class FirewallParser:
    """Parses complete iptables output into structured data."""
    
    def __init__(self, iptables_output):
        self.raw_output = iptables_output
        self.chains = {}          # chain_name -> {"policy": str, "rules": [FirewallRule]}
        self.all_rules = []       # flat list of all rules
        self._parse()
    
    def _parse(self):
        """Parse the full iptables output into chains and rules."""
        current_chain = None
        
        for line in self.raw_output.split('\n'):
            line = line.strip()
            
            # Match chain header: "Chain INPUT (policy DROP 0 packets, 0 bytes)"
            chain_match = re.match(
                r'Chain\s+(\S+)\s+\(policy\s+(\S+).*\)', line
            )
            if chain_match:
                chain_name = chain_match.group(1)
                policy = chain_match.group(2)
                current_chain = chain_name
                self.chains[chain_name] = {
                    "policy": policy,
                    "rules": []
                }
                continue
            
            # Match user-defined chain: "Chain SSH_RULES (1 references)"
            user_chain_match = re.match(
                r'Chain\s+(\S+)\s+\((\d+)\s+references?\)', line
            )
            if user_chain_match:
                chain_name = user_chain_match.group(1)
                current_chain = chain_name
                self.chains[chain_name] = {
                    "policy": "N/A (user-defined)",
                    "rules": []
                }
                continue
            
            # Skip header lines
            if line.startswith('pkts') or line.startswith('num') or not line:
                continue
            
            # Parse rule lines (start with a number)
            if current_chain and re.match(r'^\d', line):
                rule = FirewallRule(line, current_chain)
                self.chains[current_chain]["rules"].append(rule)
                self.all_rules.append(rule)
    
    def get_chain_rules(self, chain_name):
        """Get all rules for a specific chain."""
        if chain_name in self.chains:
            return self.chains[chain_name]["rules"]
        return []
    
    def get_chain_policy(self, chain_name):
        """Get the default policy for a specific chain."""
        if chain_name in self.chains:
            return self.chains[chain_name]["policy"]
        return "UNKNOWN"


# ============================================================================
# SECURITY AUDIT CHECKS
# ============================================================================
class FirewallAuditor:
    """Performs security audit checks on parsed firewall rules."""
    
    def __init__(self, parser):
        self.parser = parser
        self.results = []        # list of (status, category, message)
        self.score = 0
        self.max_score = 0
    
    def _add_result(self, status, category, message, details=""):
        """Record an audit result."""
        self.results.append({
            "status": status,
            "category": category,
            "message": message,
            "details": details
        })
        self.max_score += 1
        if status == "PASS":
            self.score += 1
        elif status == "WARN":
            self.score += 0.5
    
    # ------------------------------------------------------------------
    # CHECK 1: Default Policies
    # ------------------------------------------------------------------
    def check_default_policies(self):
        """
        Verify that default policies are set to DROP.
        
        WHY THIS MATTERS:
        A default ACCEPT policy means any traffic not explicitly blocked
        will be allowed through. This is a permissive approach that can
        leave gaps. Default DROP ensures only explicitly allowed traffic
        passes — following the Principle of Least Privilege.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 1: Default Policies{Colors.RESET}")
        print(f"{'─'*60}")
        
        for chain in ["INPUT", "FORWARD", "OUTPUT"]:
            policy = self.parser.get_chain_policy(chain)
            if policy == "DROP":
                self._add_result("PASS", "Default Policy",
                    f"{chain} chain default policy is DROP (deny all)")
                print(f"  {PASS} — {chain} chain: policy is DROP ✓")
            elif policy == "ACCEPT":
                self._add_result("FAIL", "Default Policy",
                    f"{chain} chain default policy is ACCEPT (allow all) — INSECURE",
                    "Change to DROP: iptables -P {chain} DROP")
                print(f"  {FAIL} — {chain} chain: policy is ACCEPT ✗ (INSECURE)")
            else:
                self._add_result("WARN", "Default Policy",
                    f"{chain} chain policy is {policy}")
                print(f"  {WARN} — {chain} chain: policy is {policy}")
    
    # ------------------------------------------------------------------
    # CHECK 2: Stateful Inspection
    # ------------------------------------------------------------------
    def check_stateful_inspection(self):
        """
        Verify that connection tracking (conntrack) is in use.
        
        WHY THIS MATTERS:
        Without stateful inspection, the firewall treats each packet
        independently. This means return traffic from legitimate connections
        might be blocked, or an attacker could craft packets that appear
        to be part of an established connection.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 2: Stateful Inspection (conntrack){Colors.RESET}")
        print(f"{'─'*60}")
        
        has_established = False
        has_invalid_drop = False
        
        for rule in self.parser.all_rules:
            if "ESTABLISHED" in rule.details and "RELATED" in rule.details:
                has_established = True
            if "INVALID" in rule.details and rule.target == "DROP":
                has_invalid_drop = True
        
        if has_established:
            self._add_result("PASS", "Stateful Inspection",
                "ESTABLISHED,RELATED connections are tracked and allowed")
            print(f"  {PASS} — ESTABLISHED,RELATED tracking enabled ✓")
        else:
            self._add_result("FAIL", "Stateful Inspection",
                "No conntrack rules found for ESTABLISHED,RELATED connections",
                "Add: iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
            print(f"  {FAIL} — ESTABLISHED,RELATED tracking NOT found ✗")
        
        if has_invalid_drop:
            self._add_result("PASS", "Stateful Inspection",
                "INVALID packets are dropped")
            print(f"  {PASS} — INVALID packets are dropped ✓")
        else:
            self._add_result("WARN", "Stateful Inspection",
                "INVALID packets are not explicitly dropped",
                "Add: iptables -A INPUT -m conntrack --ctstate INVALID -j DROP")
            print(f"  {WARN} — INVALID packets not explicitly dropped")
    
    # ------------------------------------------------------------------
    # CHECK 3: Anti-Spoofing
    # ------------------------------------------------------------------
    def check_anti_spoofing(self):
        """
        Verify that RFC 1918 and bogon addresses are blocked on the
        external interface.
        
        WHY THIS MATTERS:
        Spoofed source addresses are used in DDoS attacks, bypassing
        ACLs, and making attacks harder to trace. Private IP addresses
        should never appear as source addresses on internet-facing traffic.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 3: Anti-Spoofing Rules{Colors.RESET}")
        print(f"{'─'*60}")
        
        # RFC 1918 private address ranges
        rfc1918_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        bogon_ranges = ["127.0.0.0/8", "0.0.0.0/8", "169.254.0.0/16",
                        "224.0.0.0/4", "240.0.0.0/4"]
        
        blocked_sources = set()
        for rule in self.parser.all_rules:
            if rule.target == "DROP" and rule.source != "0.0.0.0/0":
                blocked_sources.add(rule.source)
        
        # Check RFC 1918
        rfc1918_blocked = all(r in blocked_sources for r in rfc1918_ranges)
        if rfc1918_blocked:
            self._add_result("PASS", "Anti-Spoofing",
                "All RFC 1918 private ranges are blocked on ingress")
            print(f"  {PASS} — RFC 1918 ranges (10/8, 172.16/12, 192.168/16) blocked ✓")
        else:
            missing = [r for r in rfc1918_ranges if r not in blocked_sources]
            self._add_result("FAIL", "Anti-Spoofing",
                f"Missing RFC 1918 blocks: {', '.join(missing)}")
            print(f"  {FAIL} — Missing RFC 1918 blocks: {', '.join(missing)} ✗")
        
        # Check bogon addresses
        bogon_blocked = sum(1 for r in bogon_ranges if r in blocked_sources)
        if bogon_blocked == len(bogon_ranges):
            self._add_result("PASS", "Anti-Spoofing",
                "All bogon address ranges are blocked on ingress")
            print(f"  {PASS} — Bogon addresses blocked ✓")
        elif bogon_blocked > 0:
            self._add_result("WARN", "Anti-Spoofing",
                f"Only {bogon_blocked}/{len(bogon_ranges)} bogon ranges blocked")
            print(f"  {WARN} — Partial bogon blocking: {bogon_blocked}/{len(bogon_ranges)}")
        else:
            self._add_result("FAIL", "Anti-Spoofing",
                "No bogon address ranges are blocked")
            print(f"  {FAIL} — No bogon addresses blocked ✗")
    
    # ------------------------------------------------------------------
    # CHECK 4: SSH Hardening
    # ------------------------------------------------------------------
    def check_ssh_hardening(self):
        """
        Verify that SSH access is properly restricted and rate-limited.
        
        WHY THIS MATTERS:
        SSH brute-force attacks are extremely common. Without restrictions,
        attackers can try thousands of password combinations. Rate limiting
        and IP restrictions dramatically reduce the attack surface.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 4: SSH Hardening{Colors.RESET}")
        print(f"{'─'*60}")
        
        ssh_rules = [r for r in self.parser.all_rules if "dpt:22" in r.details]
        
        if not ssh_rules:
            # Check if SSH is handled by a custom chain
            for rule in self.parser.all_rules:
                if "dpt:22" in rule.details:
                    ssh_rules.append(rule)
            
            # Also check custom chains
            for chain_name, chain_data in self.parser.chains.items():
                if chain_name not in ["INPUT", "OUTPUT", "FORWARD"]:
                    for rule in chain_data["rules"]:
                        if rule.source != "0.0.0.0/0" or "limit" in rule.details:
                            ssh_rules.append(rule)
        
        has_rate_limit = any("limit" in r.details for r in ssh_rules 
                           if r.chain != "OUTPUT")
        has_ip_restriction = any(r.source != "0.0.0.0/0" for r in ssh_rules)
        has_logging = any(r.target == "LOG" and "SSH" in r.details 
                         for r in self.parser.all_rules)
        has_custom_chain = any(r.target not in ["ACCEPT", "DROP", "REJECT", "LOG"] 
                              and "dpt:22" in r.details for r in self.parser.all_rules)
        
        # Check for wide-open SSH
        ssh_open_to_all = any(
            r.source == "0.0.0.0/0" and r.target == "ACCEPT" and "dpt:22" in r.details
            for r in self.parser.get_chain_rules("INPUT")
        )
        
        if has_ip_restriction:
            self._add_result("PASS", "SSH Hardening",
                "SSH access restricted to specific IP ranges")
            print(f"  {PASS} — SSH restricted to specific IPs ✓")
        elif ssh_open_to_all:
            self._add_result("FAIL", "SSH Hardening",
                "SSH is open to ALL source IPs (0.0.0.0/0)",
                "Restrict SSH to admin subnet: -s 192.168.1.0/28")
            print(f"  {FAIL} — SSH open to all IPs ✗")
        else:
            self._add_result("WARN", "SSH Hardening",
                "Could not determine SSH IP restrictions")
            print(f"  {WARN} — SSH IP restriction status unclear")
        
        if has_rate_limit:
            self._add_result("PASS", "SSH Hardening",
                "SSH connections are rate-limited")
            print(f"  {PASS} — SSH rate limiting enabled ✓")
        else:
            self._add_result("FAIL", "SSH Hardening",
                "SSH is not rate-limited (vulnerable to brute-force)",
                "Add: -m limit --limit 3/min")
            print(f"  {FAIL} — SSH NOT rate-limited ✗")
        
        if has_logging:
            self._add_result("PASS", "SSH Hardening",
                "Failed SSH attempts are logged")
            print(f"  {PASS} — SSH attempt logging enabled ✓")
        else:
            self._add_result("WARN", "SSH Hardening",
                "Failed SSH attempts may not be logged")
            print(f"  {WARN} — SSH logging not detected")
        
        if has_custom_chain:
            self._add_result("PASS", "SSH Hardening",
                "SSH uses a dedicated custom chain (good organization)")
            print(f"  {PASS} — SSH uses custom chain (good practice) ✓")
    
    # ------------------------------------------------------------------
    # CHECK 5: Web Server Rules
    # ------------------------------------------------------------------
    def check_web_server(self):
        """
        Verify web server rules (HTTP port 80, HTTPS port 443).
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 5: Web Server Rules{Colors.RESET}")
        print(f"{'─'*60}")
        
        has_http = any("dpt:80" in r.details and r.target == "ACCEPT" 
                       for r in self.parser.all_rules)
        has_https = any("dpt:443" in r.details and r.target == "ACCEPT" 
                        for r in self.parser.all_rules)
        
        if has_http:
            self._add_result("PASS", "Web Server",
                "HTTP (port 80) is accessible")
            print(f"  {PASS} — HTTP (port 80) allowed ✓")
        else:
            self._add_result("WARN", "Web Server",
                "HTTP (port 80) does not appear to be allowed")
            print(f"  {WARN} — HTTP (port 80) not found")
        
        if has_https:
            self._add_result("PASS", "Web Server",
                "HTTPS (port 443) is accessible")
            print(f"  {PASS} — HTTPS (port 443) allowed ✓")
        else:
            self._add_result("WARN", "Web Server",
                "HTTPS (port 443) does not appear to be allowed")
            print(f"  {WARN} — HTTPS (port 443) not found")
    
    # ------------------------------------------------------------------
    # CHECK 6: DNS Configuration
    # ------------------------------------------------------------------
    def check_dns(self):
        """
        Verify DNS resolution rules.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 6: DNS Configuration{Colors.RESET}")
        print(f"{'─'*60}")
        
        dns_rules = [r for r in self.parser.all_rules if "dpt:53" in r.details]
        
        dns_restricted = any(r.destination != "0.0.0.0/0" for r in dns_rules)
        dns_outbound_only = all(r.chain == "OUTPUT" for r in dns_rules 
                                if r.target == "ACCEPT")
        
        if dns_rules:
            self._add_result("PASS", "DNS", "DNS rules are configured")
            print(f"  {PASS} — DNS rules present ✓")
        else:
            self._add_result("FAIL", "DNS", "No DNS rules found")
            print(f"  {FAIL} — No DNS rules found ✗")
        
        if dns_restricted:
            self._add_result("PASS", "DNS",
                "DNS queries restricted to specific servers")
            print(f"  {PASS} — DNS restricted to specific servers ✓")
        elif dns_rules:
            self._add_result("WARN", "DNS",
                "DNS queries allowed to any server",
                "Restrict to trusted DNS: -d 8.8.8.8")
            print(f"  {WARN} — DNS not restricted to specific servers")
    
    # ------------------------------------------------------------------
    # CHECK 7: ICMP Rules
    # ------------------------------------------------------------------
    def check_icmp(self):
        """
        Verify ICMP (ping) rules are properly configured.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 7: ICMP Rules{Colors.RESET}")
        print(f"{'─'*60}")
        
        icmp_rules = [r for r in self.parser.all_rules if r.protocol == "icmp"]
        icmp_rate_limited = any("limit" in r.details for r in icmp_rules)
        
        if icmp_rules:
            self._add_result("PASS", "ICMP",
                f"ICMP rules configured ({len(icmp_rules)} rules)")
            print(f"  {PASS} — {len(icmp_rules)} ICMP rules found ✓")
        else:
            self._add_result("WARN", "ICMP",
                "No ICMP rules found — ping may be blocked entirely")
            print(f"  {WARN} — No ICMP rules found")
        
        if icmp_rate_limited:
            self._add_result("PASS", "ICMP",
                "ICMP is rate-limited (prevents ping floods)")
            print(f"  {PASS} — ICMP rate limiting enabled ✓")
        elif icmp_rules:
            self._add_result("WARN", "ICMP",
                "ICMP is not rate-limited (potential for ping floods)",
                "Add: -m limit --limit 1/sec")
            print(f"  {WARN} — ICMP NOT rate-limited")
    
    # ------------------------------------------------------------------
    # CHECK 8: Logging
    # ------------------------------------------------------------------
    def check_logging(self):
        """
        Verify that dropped packets are logged for audit/forensic purposes.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 8: Logging Configuration{Colors.RESET}")
        print(f"{'─'*60}")
        
        log_rules = [r for r in self.parser.all_rules if r.target == "LOG"]
        log_rate_limited = any("limit" in r.details for r in log_rules)
        
        chains_with_logging = set(r.chain for r in log_rules)
        
        if log_rules:
            self._add_result("PASS", "Logging",
                f"Logging enabled ({len(log_rules)} LOG rules in chains: "
                f"{', '.join(chains_with_logging)})")
            print(f"  {PASS} — {len(log_rules)} LOG rules found in: "
                  f"{', '.join(chains_with_logging)} ✓")
        else:
            self._add_result("FAIL", "Logging",
                "No LOG rules found — dropped packets are not recorded",
                "Add: iptables -A INPUT -j LOG --log-prefix 'Dropped: '")
            print(f"  {FAIL} — No logging rules found ✗")
        
        if log_rate_limited:
            self._add_result("PASS", "Logging",
                "Log entries are rate-limited (prevents log flooding)")
            print(f"  {PASS} — Log rate limiting enabled ✓")
        elif log_rules:
            self._add_result("WARN", "Logging",
                "Logs are NOT rate-limited (could fill disk during attack)",
                "Add: -m limit --limit 5/min")
            print(f"  {WARN} — Logs NOT rate-limited (disk flood risk)")
    
    # ------------------------------------------------------------------
    # CHECK 9: Egress Filtering
    # ------------------------------------------------------------------
    def check_egress_filtering(self):
        """
        Verify that outbound traffic is controlled.
        
        WHY THIS MATTERS:
        Without egress filtering, a compromised host could exfiltrate data,
        connect to C&C servers, or participate in DDoS attacks without
        any restrictions.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 9: Egress Filtering (Outbound Control){Colors.RESET}")
        print(f"{'─'*60}")
        
        output_policy = self.parser.get_chain_policy("OUTPUT")
        output_rules = self.parser.get_chain_rules("OUTPUT")
        
        if output_policy == "DROP":
            self._add_result("PASS", "Egress Filtering",
                "OUTPUT chain default policy is DROP (egress filtering active)")
            print(f"  {PASS} — OUTPUT default policy: DROP (egress filtering active) ✓")
        elif output_policy == "ACCEPT":
            self._add_result("FAIL", "Egress Filtering",
                "OUTPUT chain default policy is ACCEPT — no egress filtering",
                "Set: iptables -P OUTPUT DROP, then allow specific outbound traffic")
            print(f"  {FAIL} — OUTPUT default policy: ACCEPT (no egress filtering) ✗")
        
        # Check which outbound ports are allowed
        allowed_outbound = []
        for rule in output_rules:
            if rule.target == "ACCEPT" and "dpt:" in rule.details:
                port_match = re.search(r'dpt:(\d+)', rule.details)
                if port_match:
                    allowed_outbound.append(port_match.group(1))
        
        if allowed_outbound:
            print(f"  {INFO} — Allowed outbound ports: {', '.join(set(allowed_outbound))}")
    
    # ------------------------------------------------------------------
    # CHECK 10: Dangerous Rules
    # ------------------------------------------------------------------
    def check_dangerous_rules(self):
        """
        Check for rules that are overly permissive or dangerous.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 10: Dangerous / Overly Permissive Rules{Colors.RESET}")
        print(f"{'─'*60}")
        
        dangerous_found = False
        
        for rule in self.parser.all_rules:
            # Check for ACCEPT ALL from anywhere (excluding loopback and conntrack)
            if (rule.target == "ACCEPT" and
                rule.protocol == "all" and
                rule.source == "0.0.0.0/0" and
                rule.destination == "0.0.0.0/0" and
                rule.in_iface not in ["lo", "*"] and
                "ctstate" not in rule.details):
                
                self._add_result("FAIL", "Dangerous Rules",
                    f"Overly permissive rule in {rule.chain}: "
                    f"ACCEPT ALL from ANY to ANY",
                    f"Rule: {rule.raw}")
                print(f"  {FAIL} — Overly permissive rule found in {rule.chain} ✗")
                dangerous_found = True
            
            # Check for Telnet (insecure remote access)
            if "dpt:23" in rule.details and rule.target == "ACCEPT":
                self._add_result("FAIL", "Dangerous Rules",
                    "Telnet (port 23) is ALLOWED — use SSH instead",
                    "Telnet sends credentials in plaintext")
                print(f"  {FAIL} — Telnet (port 23) allowed — INSECURE ✗")
                dangerous_found = True
            
            # Check for FTP (insecure file transfer)
            if ("dpt:21" in rule.details and rule.target == "ACCEPT" and
                rule.chain == "INPUT"):
                self._add_result("WARN", "Dangerous Rules",
                    "FTP (port 21) is allowed — consider SFTP instead",
                    "FTP sends credentials in plaintext")
                print(f"  {WARN} — FTP (port 21) allowed — consider SFTP")
                dangerous_found = True
        
        if not dangerous_found:
            self._add_result("PASS", "Dangerous Rules",
                "No obviously dangerous or overly permissive rules detected")
            print(f"  {PASS} — No dangerous rules detected ✓")
    
    # ------------------------------------------------------------------
    # CHECK 11: SYN Flood Protection
    # ------------------------------------------------------------------
    def check_syn_flood_protection(self):
        """
        Check for SYN flood protection mechanisms.
        """
        print(f"\n{Colors.BOLD}{'─'*60}{Colors.RESET}")
        print(f"{Colors.BOLD}CHECK 11: SYN Flood Protection{Colors.RESET}")
        print(f"{'─'*60}")
        
        has_syn_limit = any(
            "tcp" in r.protocol and "flags" in r.details and "limit" in r.details
            for r in self.parser.all_rules
        )
        has_invalid_flags = any(
            "flags" in r.details and r.target == "DROP"
            for r in self.parser.all_rules
        )
        
        if has_syn_limit:
            self._add_result("PASS", "SYN Flood",
                "SYN packet rate limiting is configured")
            print(f"  {PASS} — SYN rate limiting enabled ✓")
        else:
            self._add_result("WARN", "SYN Flood",
                "No SYN rate limiting detected",
                "Add: iptables -A INPUT -p tcp --syn -m limit --limit 10/sec -j ACCEPT")
            print(f"  {WARN} — SYN rate limiting not detected")
        
        if has_invalid_flags:
            self._add_result("PASS", "SYN Flood",
                "Invalid TCP flag combinations are dropped")
            print(f"  {PASS} — Invalid TCP flags dropped ✓")
        else:
            self._add_result("WARN", "SYN Flood",
                "No rules to drop packets with invalid TCP flags")
            print(f"  {WARN} — Invalid TCP flag rules not found")
    
    # ------------------------------------------------------------------
    # RUN ALL CHECKS
    # ------------------------------------------------------------------
    def run_audit(self):
        """Execute all audit checks and display results."""
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║          FIREWALL RULES SECURITY AUDIT                  ║")
        print("║          Automated Analysis Report                      ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")
        print(f"  Audit Date  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"  Chains Found: {', '.join(self.parser.chains.keys())}")
        print(f"  Total Rules : {len(self.parser.all_rules)}")
        
        # Run all checks
        self.check_default_policies()
        self.check_stateful_inspection()
        self.check_anti_spoofing()
        self.check_ssh_hardening()
        self.check_web_server()
        self.check_dns()
        self.check_icmp()
        self.check_logging()
        self.check_egress_filtering()
        self.check_dangerous_rules()
        self.check_syn_flood_protection()
        
        # Print summary
        self._print_summary()
        
        return self.results
    
    def _print_summary(self):
        """Print the final audit summary."""
        
        pass_count = sum(1 for r in self.results if r["status"] == "PASS")
        warn_count = sum(1 for r in self.results if r["status"] == "WARN")
        fail_count = sum(1 for r in self.results if r["status"] == "FAIL")
        total = len(self.results)
        
        percentage = (self.score / self.max_score * 100) if self.max_score > 0 else 0
        
        # Determine overall grade
        if percentage >= 90:
            grade = f"{Colors.GREEN}A — Excellent{Colors.RESET}"
        elif percentage >= 80:
            grade = f"{Colors.GREEN}B — Good{Colors.RESET}"
        elif percentage >= 70:
            grade = f"{Colors.YELLOW}C — Acceptable{Colors.RESET}"
        elif percentage >= 60:
            grade = f"{Colors.YELLOW}D — Needs Improvement{Colors.RESET}"
        else:
            grade = f"{Colors.RED}F — Critical Issues{Colors.RESET}"
        
        print(f"\n{Colors.BOLD}{Colors.CYAN}")
        print("╔══════════════════════════════════════════════════════════╗")
        print("║                   AUDIT SUMMARY                        ║")
        print("╚══════════════════════════════════════════════════════════╝")
        print(f"{Colors.RESET}")
        print(f"  {Colors.GREEN}PASS : {pass_count:3d}{Colors.RESET}")
        print(f"  {Colors.YELLOW}WARN : {warn_count:3d}{Colors.RESET}")
        print(f"  {Colors.RED}FAIL : {fail_count:3d}{Colors.RESET}")
        print(f"  {'─'*30}")
        print(f"  Total: {total}")
        print(f"  Score: {self.score:.1f} / {self.max_score} ({percentage:.1f}%)")
        print(f"  Grade: {grade}")
        print()
        
        # Print recommendations for failures
        failures = [r for r in self.results if r["status"] == "FAIL"]
        if failures:
            print(f"  {Colors.RED}{Colors.BOLD}CRITICAL ISSUES TO FIX:{Colors.RESET}")
            for i, f in enumerate(failures, 1):
                print(f"    {i}. [{f['category']}] {f['message']}")
                if f['details']:
                    print(f"       → Fix: {f['details']}")
            print()
        
        # Print recommendations for warnings
        warnings = [r for r in self.results if r["status"] == "WARN"]
        if warnings:
            print(f"  {Colors.YELLOW}{Colors.BOLD}RECOMMENDATIONS:{Colors.RESET}")
            for i, w in enumerate(warnings, 1):
                print(f"    {i}. [{w['category']}] {w['message']}")
                if w['details']:
                    print(f"       → Suggestion: {w['details']}")
            print()


# ============================================================================
# MAIN EXECUTION
# ============================================================================
def main():
    """Main entry point for the firewall audit script."""
    
    # Determine input file path
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_file = os.path.join(script_dir, "sample_iptables_output.txt")
    
    input_file = sys.argv[1] if len(sys.argv) > 1 else default_file
    
    # Read the iptables output
    try:
        with open(input_file, 'r') as f:
            iptables_output = f.read()
    except FileNotFoundError:
        print(f"{Colors.RED}[ERROR] File not found: {input_file}{Colors.RESET}")
        print(f"\nUsage:")
        print(f"  python3 {sys.argv[0]} [iptables_output_file]")
        print(f"\nGenerate iptables output with:")
        print(f"  sudo iptables -L -n -v > iptables_output.txt")
        sys.exit(1)
    
    if not iptables_output.strip():
        print(f"{Colors.RED}[ERROR] Input file is empty.{Colors.RESET}")
        sys.exit(1)
    
    # Parse and audit
    parser = FirewallParser(iptables_output)
    auditor = FirewallAuditor(parser)
    results = auditor.run_audit()
    
    # Return exit code based on results
    fail_count = sum(1 for r in results if r["status"] == "FAIL")
    sys.exit(1 if fail_count > 0 else 0)


if __name__ == "__main__":
    main()
