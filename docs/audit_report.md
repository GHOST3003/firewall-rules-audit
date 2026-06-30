# 🔒 Firewall Security Audit Report

## Network Security — Minor Project
**Prepared by:** Sujal & Kowshik Chowdhary  
**Date:** June 2026  
**Scope:** Small Office/Home Office (SOHO) Network Firewall  
**System:** Linux (iptables/Netfilter)

---

## 1. Executive Summary 

This report presents the findings of a comprehensive security audit performed on the Linux `iptables` firewall configured for a Small Office/Home Office (SOHO) network. The firewall protects a web server (HTTP/HTTPS) and provides restricted SSH access for administration.

### Overall Assessment

| Metric           | Value                     |
|------------------|---------------------------|
| **Audit Grade**  | **A — Excellent**         |
| **Total Checks** | 24                        |
| **Passed**       | 22                        |
| **Warnings**     | 2                         |
| **Failed**       | 0                         |
| **Score**        | 95.8%                     |

> The firewall configuration demonstrates strong security practices including default-deny policies, stateful inspection, anti-spoofing protection, rate limiting, and comprehensive logging.

---

## 2. Scope and Methodology

### 2.1 Audit Scope

The audit covered the following aspects of the firewall configuration:

1. **Default Policies** — Chain-level default actions (ACCEPT/DROP)
2. **Stateful Inspection** — Connection tracking using conntrack module
3. **Anti-Spoofing** — RFC 1918 and bogon address blocking
4. **SSH Hardening** — Access restrictions, rate limiting, logging
5. **Web Server Rules** — HTTP (80) and HTTPS (443) accessibility
6. **DNS Configuration** — Outbound DNS resolution rules
7. **ICMP Rules** — Ping and diagnostic traffic controls
8. **Logging** — Dropped packet logging for forensics
9. **Egress Filtering** — Outbound traffic control
10. **Dangerous Rules** — Detection of overly permissive configurations
11. **SYN Flood Protection** — TCP SYN attack mitigation

### 2.2 Methodology

The audit was performed using:
- Manual review of the `firewall_setup.sh` configuration script
- Automated analysis using `audit_firewall.py` (custom Python script)
- Comparison against industry benchmarks:
  - CIS Benchmark for Linux
  - NIST SP 800-41 Rev.1 (Guidelines on Firewalls and Firewall Policy)
  - SANS Firewall Best Practices

### 2.3 Network Topology

```
                        ┌──────────────────┐
                        │    INTERNET      │
                        └────────┬─────────┘
                                 │
                        ┌────────┴─────────┐
                        │    FIREWALL       │
                        │  eth0 (external)  │
                        │  eth1 (internal)  │
                        │    iptables       │
                        └────────┬─────────┘
                                 │
                    ┌────────────┼────────────┐
                    │            │            │
              ┌─────┴────┐ ┌────┴─────┐ ┌────┴─────┐
              │Web Server│ │Admin PC  │ │Workstations│
              │.1.10     │ │.1.1-.1.14│ │.1.15-.1.254│
              │HTTP/HTTPS│ │SSH Access│ │LAN Only    │
              └──────────┘ └──────────┘ └───────────┘
              
              Internal Network: 192.168.1.0/24
              Admin Subnet:     192.168.1.0/28
```

---

## 3. Detailed Findings

### 3.1 Default Policies ✅ PASS

| Chain   | Policy | Assessment |
|---------|--------|------------|
| INPUT   | DROP   | ✅ Secure   |
| FORWARD | DROP   | ✅ Secure   |
| OUTPUT  | DROP   | ✅ Secure   |

**Analysis:**
All three built-in chains use a **default DROP policy**, implementing the security principle of **"deny by default, allow by exception."** This is the most secure approach and aligns with:
- CIS Benchmark: Rule 3.5.2.1 — "Ensure default deny firewall policy"
- NIST SP 800-41: "The default configuration should block all inbound and outbound traffic"

**Rule Logic:**
```
Default Action: DENY ALL
↓
Only packets matching explicit ACCEPT rules pass through
↓
Everything else is dropped and logged
```

---

### 3.2 Stateful Inspection ✅ PASS

**Connection Tracking Rules Found:**
```
ACCEPT  all  ctstate RELATED,ESTABLISHED  (INPUT, OUTPUT, FORWARD)
DROP    all  ctstate INVALID              (INPUT, OUTPUT, FORWARD)
```

**Analysis:**
The firewall uses the `conntrack` module for stateful packet inspection, which tracks the state of network connections:

| State         | Meaning                              | Action |
|---------------|--------------------------------------|--------|
| NEW           | First packet of a new connection     | Checked against specific rules |
| ESTABLISHED   | Part of an already-established conn. | ✅ Allowed |
| RELATED       | Related to an established connection | ✅ Allowed |
| INVALID       | Doesn't belong to any known conn.    | ❌ Dropped |

This ensures that:
- Return traffic from legitimate connections is automatically allowed
- New inbound connections must match specific ACCEPT rules
- Invalid/malformed packets are immediately discarded

---

### 3.3 Anti-Spoofing ✅ PASS

**Blocked Address Ranges:**

| Range           | Type               | Interface | Status     |
|------------------|--------------------|-----------|------------|
| 10.0.0.0/8      | RFC 1918 (Private) | eth0      | ✅ Blocked  |
| 172.16.0.0/12   | RFC 1918 (Private) | eth0      | ✅ Blocked  |
| 192.168.0.0/16  | RFC 1918 (Private) | eth0      | ✅ Blocked  |
| 127.0.0.0/8     | Loopback           | eth0      | ✅ Blocked  |
| 0.0.0.0/8       | Reserved           | eth0      | ✅ Blocked  |
| 169.254.0.0/16  | Link-Local         | eth0      | ✅ Blocked  |
| 224.0.0.0/4     | Multicast          | eth0      | ✅ Blocked  |
| 240.0.0.0/4     | Reserved           | eth0      | ✅ Blocked  |

**Analysis:**
All RFC 1918 private address ranges and common bogon addresses are blocked on the external interface (`eth0`). Packets arriving from the internet should never have private source addresses — if they do, they are spoofed.

**Why This Matters:**
- Prevents IP spoofing attacks used in DDoS amplification
- Blocks attackers from impersonating internal hosts
- Complies with BCP 38 (Network Ingress Filtering)

---

### 3.4 SSH Hardening ✅ PASS

**Configuration Summary:**

| Feature             | Implementation         | Status    |
|---------------------|------------------------|-----------|
| IP Restriction      | Admin subnet only (192.168.1.0/28) | ✅ Restricted |
| Rate Limiting       | 3 new connections/minute | ✅ Enabled |
| Brute-Force Logging | LOG prefix "SSH-Brute-Force:" | ✅ Enabled |
| Custom Chain        | SSH_RULES              | ✅ Good Practice |

**Rule Flow:**
```
Incoming SSH (port 22)
    │
    ▼
SSH_RULES (custom chain)
    │
    ├── Source IP in 192.168.1.0/28?
    │   └── YES → Rate limit check (3/min) → ACCEPT
    │
    ├── Excessive attempts?
    │   └── LOG with "SSH-Brute-Force:" prefix
    │
    └── All other SSH → DROP
```

**Analysis:**
- SSH access is limited to the admin subnet (14 IPs maximum)
- Rate limiting prevents automated brute-force attacks
- Failed attempts are logged for security monitoring
- Using a custom chain improves rule organization and readability

---

### 3.5 Web Server Rules ✅ PASS

| Port | Protocol | Direction | Access    | Status     |
|------|----------|-----------|-----------|------------|
| 80   | TCP      | Inbound   | Public    | ✅ Allowed  |
| 443  | TCP      | Inbound   | Public    | ✅ Allowed  |
| 80   | TCP      | Outbound  | Firewall  | ✅ Allowed  |
| 443  | TCP      | Outbound  | Firewall  | ✅ Allowed  |

**Analysis:**
HTTP and HTTPS are properly configured with:
- New connection tracking (`ctstate NEW`) for inbound requests
- Outbound access for the firewall itself (for updates)
- Stateful return traffic handled by the ESTABLISHED,RELATED rule

---

### 3.6 DNS Configuration ✅ PASS

| Direction | Protocol | Destination | Port | Status     |
|-----------|----------|-------------|------|------------|
| Outbound  | UDP      | 8.8.8.8     | 53   | ✅ Allowed  |
| Outbound  | UDP      | 8.8.4.4     | 53   | ✅ Allowed  |
| Outbound  | TCP      | 8.8.8.8     | 53   | ✅ Allowed  |
| Outbound  | TCP      | 8.8.4.4     | 53   | ✅ Allowed  |

**Analysis:**
DNS queries are:
- ✅ Restricted to trusted servers (Google Public DNS)
- ✅ Outbound only (no inbound DNS service)
- ✅ Both UDP and TCP supported (for standard queries and large responses)
- ✅ Prevents DNS exfiltration to arbitrary servers

---

### 3.7 ICMP Rules ✅ PASS

| Type | Name                    | Direction | Rate Limit | Status     |
|------|-------------------------|-----------|------------|------------|
| 8    | Echo Request (ping)     | Inbound   | 1/sec      | ✅ Limited  |
| 0    | Echo Reply              | Inbound   | No         | ✅ Allowed  |
| 3    | Destination Unreachable | Inbound   | No         | ✅ Allowed  |
| 11   | Time Exceeded           | Inbound   | No         | ✅ Allowed  |
| 8    | Echo Request            | Outbound  | No         | ✅ Allowed  |
| 0    | Echo Reply              | Outbound  | No         | ✅ Allowed  |

**Analysis:**
ICMP is properly configured:
- Incoming pings are rate-limited (1/sec with burst of 4)
- Essential ICMP types (Destination Unreachable, Time Exceeded) are allowed
- Path MTU Discovery (via Type 3) is preserved
- Prevents ping flood DoS attacks

---

### 3.8 Logging ✅ PASS

| Chain   | Log Prefix                    | Rate Limit | Status     |
|---------|-------------------------------|------------|------------|
| INPUT   | "IPTables-Dropped: "          | 5/min      | ✅ Enabled  |
| OUTPUT  | "IPTables-Outbound-Dropped: " | 5/min      | ✅ Enabled  |
| FORWARD | "IPTables-Forward-Dropped: "  | 5/min      | ✅ Enabled  |
| SSH     | "SSH-Brute-Force: "           | 5/min      | ✅ Enabled  |

**Analysis:**
- All chains have logging for dropped packets
- Rate-limited to prevent log flooding during attacks
- Distinct log prefixes allow easy filtering with tools like `grep`, `awk`, or SIEM systems
- Supports security incident investigation and compliance auditing

---

### 3.9 Egress Filtering ✅ PASS

**Allowed Outbound Services:**

| Service | Port | Protocol | Destination     |
|---------|------|----------|-----------------|
| SSH     | 22   | TCP      | Any             |
| HTTP    | 80   | TCP      | Any             |
| HTTPS   | 443  | TCP      | Any             |
| DNS     | 53   | UDP/TCP  | 8.8.8.8, 8.8.4.4 |
| NTP     | 123  | UDP      | Any             |
| ICMP    | —    | ICMP     | Any             |

**Analysis:**
The OUTPUT chain has a default DROP policy with explicit allows for essential services only. This provides strong egress filtering that:
- Prevents compromised software from connecting to C&C servers on unusual ports
- Limits data exfiltration channels
- Reduces the attack surface if the host is compromised

**Recommendation:** Consider restricting SSH outbound to specific destination IPs for even tighter control.

---

### 3.10 SYN Flood Protection ✅ PASS

**Protection Mechanisms:**

| Mechanism              | Implementation                    | Status     |
|------------------------|-----------------------------------|------------|
| SYN Rate Limiting      | 10 SYN packets/sec, burst 20      | ✅ Enabled  |
| Christmas Tree Packets | FLAGS ALL/ALL → DROP              | ✅ Blocked  |
| Null Packets           | FLAGS ALL/NONE → DROP             | ✅ Blocked  |
| SYN-FIN Attack         | FLAGS SYN,FIN/SYN,FIN → DROP     | ✅ Blocked  |
| SYN-RST Attack         | FLAGS SYN,RST/SYN,RST → DROP     | ✅ Blocked  |
| SYN Cookies (kernel)   | net.ipv4.tcp_syncookies = 1       | ✅ Enabled  |

**Analysis:**
Multiple layers of SYN flood protection are in place:
1. **Rate limiting** at the iptables level constrains new connections
2. **Invalid flag detection** drops common attack patterns
3. **SYN cookies** at the kernel level provide a fallback if the SYN queue fills up

---

### 3.11 Kernel Hardening ✅ PASS

| Parameter                    | Value | Purpose                          |
|------------------------------|-------|----------------------------------|
| tcp_syncookies               | 1     | SYN flood protection             |
| accept_source_route          | 0     | Prevent source routing attacks   |
| rp_filter                    | 1     | Reverse path filtering (anti-spoof) |
| accept_redirects             | 0     | Prevent ICMP redirect attacks    |
| send_redirects               | 0     | Don't send ICMP redirects        |
| icmp_echo_ignore_broadcasts  | 1     | Prevent Smurf attacks            |
| log_martians                 | 1     | Log impossible source addresses  |

---

## 4. Summary of Recommendations

### High Priority
| # | Recommendation | Current Status |
|---|---------------|----------------|
| 1 | Restrict outbound SSH to specific IPs | ⚠️ Currently allows SSH to any destination |

### Medium Priority
| # | Recommendation | Details |
|---|---------------|---------|
| 2 | Implement fail2ban | Auto-ban IPs after repeated SSH failures |
| 3 | Add IPv6 rules | Current config only covers IPv4 (ip6tables) |
| 4 | Configure log rotation | Prevent log files from consuming disk space |

### Low Priority
| # | Recommendation | Details |
|---|---------------|---------|
| 5 | Consider using nftables | Modern replacement for iptables |
| 6 | Add IDS/IPS integration | Snort or Suricata for deeper inspection |

---

## 5. Compliance Mapping

| Standard | Requirement | Status |
|----------|-------------|--------|
| CIS 3.5.1.1 | Ensure iptables installed | ✅ |
| CIS 3.5.2.1 | Ensure default deny policy | ✅ |
| CIS 3.5.2.2 | Ensure loopback traffic configured | ✅ |
| CIS 3.5.2.4 | Ensure outbound connections configured | ✅ |
| NIST AC-4 | Information Flow Enforcement | ✅ |
| NIST SC-7 | Boundary Protection | ✅ |
| NIST AU-3 | Content of Audit Records | ✅ |

---

## 6. Conclusion

The firewall configuration demonstrates **excellent security practices** suitable for a SOHO environment. The implementation follows the principle of least privilege with a default-deny approach, implements multiple layers of defense (defense-in-depth), and provides comprehensive logging for audit and incident response.

The few recommendations identified are enhancements that would further strengthen an already robust configuration.

---

**Report Generated:** June 2026  
**Audit Tool:** `audit_firewall.py` v1.0  
**Auditors:** Sujal & Kowshik Chowdhary
