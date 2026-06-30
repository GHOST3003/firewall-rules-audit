# 🔍 Security Gap Analysis

## Network Security — Firewall Rules Audit (Minor Project)
**Prepared by:** Sujal & Kowshik Chowdhary  
**Date:** June 2026  
**Scope:** SOHO Network Firewall (iptables)

--- 

## 1. Introduction

### 1.1 Purpose
A **security gap analysis** identifies the difference between the **current security posture** and the **desired/ideal security state**. This document evaluates the firewall configuration against industry best practices and standards to identify areas where security could be improved.

### 1.2 Framework Used
The analysis maps our configuration against:
- **CIS Benchmarks** (Center for Internet Security) for Linux
- **NIST SP 800-41 Rev.1** — Guidelines on Firewalls and Firewall Policy
- **SANS Top 20 Critical Security Controls** (now CIS Controls)
- **PCI DSS** — Payment Card Industry Data Security Standard (as reference)

---

## 2. Gap Analysis Matrix

### Legend
| Symbol | Meaning |
|--------|---------|
| 🟢 | Fully implemented (no gap) |
| 🟡 | Partially implemented (minor gap) |
| 🔴 | Not implemented (significant gap) |

---

### 2.1 Access Control Gaps

| # | Security Control | Expected State | Current State | Gap | Risk Level |
|---|-----------------|----------------|---------------|-----|------------|
| 1 | Default deny policy | DROP on all chains | DROP on INPUT, FORWARD, OUTPUT | 🟢 None | — |
| 2 | SSH access restriction | IP-based restriction | Admin subnet (192.168.1.0/28) only | 🟢 None | — |
| 3 | SSH rate limiting | Max 3-5 attempts/min | 3/min with burst 3 | 🟢 None | — |
| 4 | SSH key authentication | Enforce key-only auth | Not enforced by firewall* | 🟡 Minor | Low |
| 5 | Multi-factor auth (MFA) | SSH MFA enabled | Not implemented | 🟡 Minor | Medium |
| 6 | Port knocking / SPA | Hidden SSH port | Not implemented | 🟡 Optional | Low |

> *Note: SSH key authentication is configured in `/etc/ssh/sshd_config`, not in iptables. It's included here for completeness of the security posture.

---

### 2.2 Network Filtering Gaps

| # | Security Control | Expected State | Current State | Gap | Risk Level |
|---|-----------------|----------------|---------------|-----|------------|
| 7 | Anti-spoofing (IPv4) | Block RFC 1918 + bogons | Fully implemented | 🟢 None | — |
| 8 | Anti-spoofing (IPv6) | Block spoofed IPv6 | No ip6tables rules | 🔴 Gap | Medium |
| 9 | Egress filtering | Restrict outbound ports | OUTPUT DROP + explicit allows | 🟢 None | — |
| 10 | Egress IP restriction | Restrict outbound destinations | Some services unrestricted | 🟡 Minor | Low |
| 11 | GeoIP filtering | Block traffic from high-risk countries | Not implemented | 🟡 Optional | Low |
| 12 | MAC filtering | Restrict by MAC address on LAN | Not implemented | 🟡 Optional | Low |

---

### 2.3 Attack Protection Gaps

| # | Security Control | Expected State | Current State | Gap | Risk Level |
|---|-----------------|----------------|---------------|-----|------------|
| 13 | SYN flood protection | Rate limiting + SYN cookies | Fully implemented | 🟢 None | — |
| 14 | Invalid TCP flags | Drop malformed packets | Fully implemented | 🟢 None | — |
| 15 | ICMP rate limiting | Limited ping rate | 1/sec with burst 4 | 🟢 None | — |
| 16 | Port scan detection | Detect/block port scans | Not implemented | 🟡 Minor | Medium |
| 17 | IDS/IPS integration | Deep packet inspection | Not implemented | 🔴 Gap | Medium |
| 18 | Application layer firewall | Layer 7 filtering | Not available (iptables is L3/L4) | 🟡 Limitation | Medium |

---

### 2.4 Monitoring & Logging Gaps

| # | Security Control | Expected State | Current State | Gap | Risk Level |
|---|-----------------|----------------|---------------|-----|------------|
| 19 | Dropped packet logging | Log all drops | Implemented with rate limit | 🟢 None | — |
| 20 | SSH attempt logging | Log brute-force attempts | Implemented | 🟢 None | — |
| 21 | Log rotation | Automated log management | Not configured in firewall | 🟡 Minor | Low |
| 22 | SIEM integration | Centralized log analysis | Not implemented | 🔴 Gap | Medium |
| 23 | Real-time alerting | Automated attack alerts | Not implemented | 🔴 Gap | Medium |
| 24 | Log integrity | Tamper-proof logging | Not implemented | 🟡 Minor | Low |

---

### 2.5 Maintenance & Operations Gaps

| # | Security Control | Expected State | Current State | Gap | Risk Level |
|---|-----------------|----------------|---------------|-----|------------|
| 25 | Rule documentation | All rules documented | Comprehensive comments | 🟢 None | — |
| 26 | Rule persistence | Survive reboot | iptables-save configured | 🟢 None | — |
| 27 | Automated backups | Regular rule backups | Not automated | 🟡 Minor | Low |
| 28 | Change management | Track rule changes | Not implemented | 🟡 Minor | Medium |
| 29 | Regular rule review | Periodic audit schedule | Manual (this project) | 🟡 Minor | Low |
| 30 | Fail2ban / auto-banning | Auto-ban attacking IPs | Not implemented | 🟡 Minor | Medium |

---

## 3. Gap Summary

### 3.1 Statistics

| Status | Count | Percentage |
|--------|-------|------------|
| 🟢 Fully Implemented | 16 | 53.3% |
| 🟡 Partially / Optional | 11 | 36.7% |
| 🔴 Not Implemented | 3 | 10.0% |
| **Total Controls** | **30** | **100%** |

### 3.2 Risk Distribution

| Risk Level | Count | Controls |
|------------|-------|----------|
| **High** | 0 | — |
| **Medium** | 7 | #5, #8, #16, #17, #18, #22, #23 |
| **Low** | 8 | #4, #6, #10, #11, #12, #21, #24, #27 |
| **None** | 15 | All 🟢 items |

---

## 4. Detailed Gap Analysis

### 4.1 🔴 GAP: No IPv6 Firewall Rules (Control #8)

**Current State:** Only IPv4 (iptables) rules are configured. No `ip6tables` rules exist.

**Risk:** If the system has IPv6 enabled (most modern Linux distributions do), it has **no firewall protection** for IPv6 traffic. An attacker could bypass all firewall rules by using IPv6.

**Remediation:**
```bash
# Option 1: Disable IPv6 if not needed
sysctl -w net.ipv6.conf.all.disable_ipv6=1
sysctl -w net.ipv6.conf.default.disable_ipv6=1

# Option 2: Configure ip6tables with equivalent rules
ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# ... (mirror all IPv4 rules)
```

**Priority:** Medium — Should be addressed in the next iteration.

---

### 4.2 🔴 GAP: No IDS/IPS Integration (Control #17)

**Current State:** The firewall operates at Layer 3/4 only. No deep packet inspection or intrusion detection is performed.

**Risk:** The firewall cannot detect:
- Malware in HTTP traffic
- SQL injection attempts
- Application-layer attacks
- Zero-day exploits

**Remediation:**
```bash
# Install and configure Snort (IDS)
sudo apt install snort
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

# Or use Suricata (IDS/IPS)
sudo apt install suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

**Priority:** Medium — Recommended for environments handling sensitive data.

---

### 4.3 🔴 GAP: No SIEM/Centralized Logging (Controls #22, #23)

**Current State:** Logs are written to local syslog only. No centralized log analysis, correlation, or automated alerting.

**Risk:** 
- Logs could be tampered with on a compromised host
- No real-time visibility into attack patterns
- Manual log review is time-consuming and error-prone
- Difficult to correlate events across multiple systems

**Remediation:**
```bash
# Option 1: Forward logs to a central syslog server
# In /etc/rsyslog.conf:
*.* @@syslog-server.example.com:514

# Option 2: Use open-source SIEM (ELK Stack)
# Filebeat → Logstash → Elasticsearch → Kibana

# Option 3: Use Wazuh (free, open-source SIEM)
# https://wazuh.com/
```

**Priority:** Medium — Essential for environments with compliance requirements.

---

## 5. Remediation Roadmap

### Phase 1: Quick Wins (1-2 days)
| Action | Gap Addressed | Effort |
|--------|---------------|--------|
| Disable IPv6 or add ip6tables rules | #8 | Low |
| Install and configure fail2ban | #30 | Low |
| Set up logrotate for firewall logs | #21 | Low |
| Add port scan detection rules | #16 | Low |

### Phase 2: Short-term Improvements (1-2 weeks)
| Action | Gap Addressed | Effort |
|--------|---------------|--------|
| Deploy Snort/Suricata IDS | #17 | Medium |
| Set up centralized syslog | #22 | Medium |
| Configure automated alerts | #23 | Medium |
| Implement change management process | #28 | Low |

### Phase 3: Long-term Enhancements (1-3 months)
| Action | Gap Addressed | Effort |
|--------|---------------|--------|
| Deploy SIEM (ELK/Wazuh) | #22, #23, #24 | High |
| Migrate to nftables | Modernization | Medium |
| Implement WAF for web server | #18 | High |
| Set up SSH MFA (Google Authenticator) | #5 | Medium |

---

## 6. Conclusion

The current firewall configuration addresses **53.3%** of security controls fully and **36.7%** partially. There are **no high-risk gaps**, and the three significant gaps (IPv6, IDS/IPS, SIEM) are common in SOHO environments and represent areas for future improvement rather than critical vulnerabilities.

The firewall demonstrates a strong understanding of:
- ✅ Network perimeter defense principles
- ✅ Principle of least privilege (default deny)
- ✅ Defense in depth (multiple protection layers)
- ✅ Security monitoring fundamentals (logging)
- ✅ Industry standard compliance (CIS, NIST)

### Overall Maturity Assessment

```
┌─────────────────────────────────────────────────┐
│ Security Maturity Level                         │
├─────────────────────────────────────────────────┤
│                                                 │
│  Level 1: Initial        ░░░░░░░░░░             │
│  Level 2: Managed        ██████████             │
│  Level 3: Defined        ████████░░  ← Current  │
│  Level 4: Measured       ████░░░░░░             │
│  Level 5: Optimized      ██░░░░░░░░             │
│                                                 │
│  Current Level: 3 (Defined)                     │
│  Target Level:  4 (Measured)                    │
│                                                 │
└─────────────────────────────────────────────────┘
```

---

**Document Prepared:** June 2026  
**Authors:** Sujal & Kowshik Chowdhary  
**Review Status:** Final
