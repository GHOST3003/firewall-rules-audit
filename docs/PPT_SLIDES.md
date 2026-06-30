# Firewall Rules Audit — PowerPoint Presentation Content

> **Instructions:** Each slide below is ready to be transferred directly into PowerPoint.
> Copy the **Title** into the slide title placeholder and the **bullet points** into the content area.
> Tables can be inserted as PowerPoint tables. The ASCII diagram on Slide 3 can be recreated
> using SmartArt or simple shapes.

---
 
## Slide 1 — Title Slide

**Title:** Firewall Rules Audit

| | |
|---|---|
| **Subject** | Network Security (Minor Project) |
| **Presented By** | LALIT BAIRWA |
| **Instructor** | Ganesh K |
| **Platform** | labmentix.in |
| **Date** | June 2026 |

> *Suggested design:* Dark blue or charcoal background with a shield/firewall icon.
> Place the project title prominently at center. Student names and details below.

---

## Slide 2 — Introduction & Problem Statement

**Title:** Why Firewall Auditing Matters

- A **firewall** is the first line of defense — it controls all traffic entering and leaving a network
- **70% of the world's servers run Linux**, making iptables the most widely deployed firewall
- **Misconfigured firewalls are the #1 cause of network breaches** (Gartner, Verizon DBIR)
- Even a single overlooked rule can expose critical services to the internet
- **Project Objective:**
  - Configure a Linux iptables firewall from scratch
  - Test it against real-world attack scenarios
  - Audit the ruleset using automated tools
  - Identify gaps and build a remediation roadmap

> *Suggested visual:* Split layout — left side: bullet points; right side: a simple icon
> showing "Misconfigured Firewall → Data Breach" flow.

---

## Slide 3 — Network Lab Setup (Phases 1–2)

**Title:** Lab Environment & Network Topology

- **Virtualization:** Oracle VirtualBox 7.x with Host-Only + NAT networking
- **Firewall VM:** Ubuntu Server 22.04 LTS (192.168.1.10) — runs iptables + Apache
- **Attacker VM:** Kali Linux 2024.x — used for penetration testing & scanning
- **Network:** 192.168.1.0/24 (internal LAN) · Admin subnet: 192.168.1.0/28
- **Verification:** Bi-directional ping test confirmed connectivity before hardening

**Network Diagram** *(recreate using SmartArt or shapes in PowerPoint):*

```
                        ┌─────────────┐
                        │  INTERNET   │
                        └──────┬──────┘
                               │
                     ┌─────────▼─────────┐
                     │   FIREWALL VM      │
                     │  Ubuntu 22.04 LTS  │
                     │  iptables + Apache │
                     │   192.168.1.10     │
                     └─────────┬─────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
     ┌────────▼──────┐ ┌──────▼───────┐ ┌──────▼───────┐
     │  Admin PCs    │ │  Web Server  │ │ Workstations │
     │ .1.1 – .1.14  │ │  (Apache)    │ │ .1.15 – .1.254│
     │ SSH allowed   │ │  Port 80/443 │ │  Standard     │
     └───────────────┘ └──────────────┘ └──────────────┘

              ┌───────────────────┐
              │  ATTACKER (Kali)  │
              │  192.168.1.100    │
              │  nmap, hping3     │
              └───────────────────┘
```

> *Suggested visual:* Replace the ASCII art above with a SmartArt "Hierarchy" or
> use rounded-rectangle shapes with arrows. Color-code: green for trusted, red for attacker.

---

## Slide 4 — Firewall Policy Design (Phase 3)

**Title:** Security Policy — Default DENY (Least Privilege)

- **Policy Approach:** Block everything by default; explicitly allow only required traffic
- Based on the **Principle of Least Privilege** — no service runs unless justified
- Policies documented before any rule was written (policy-first methodology)

**Firewall Policy Matrix:**

| Service | Port | Protocol | Action | Reason |
|---------|------|----------|--------|--------|
| SSH | 22 | TCP | ✅ ALLOW (admin subnet only) | Remote administration |
| HTTP | 80 | TCP | ✅ ALLOW (public) | Web server access |
| HTTPS | 443 | TCP | ✅ ALLOW (public) | Secure web access |
| DNS | 53 | UDP/TCP | ✅ ALLOW (outbound only) | Name resolution |
| FTP | 21 | TCP | ❌ BLOCK | Insecure protocol |
| Telnet | 23 | TCP | ❌ BLOCK | Sends credentials in plaintext |
| ICMP | — | ICMP | ⚠️ ALLOW (rate-limited) | Diagnostics (5/sec) |
| All Others | * | * | ❌ BLOCK | Default deny policy |

> *Suggested visual:* Use a PowerPoint table with green rows for ALLOW, red rows for BLOCK,
> and yellow for rate-limited. Add a small lock icon next to "Default DENY" in the title.

---

## Slide 5 — Firewall Implementation (Phase 4)

**Title:** iptables Rules — Defense in Depth

- **Default Policy:** DROP on all chains (INPUT, FORWARD, OUTPUT)
- **Stateful Inspection:** `conntrack` module tracks ESTABLISHED & RELATED connections
- **Anti-Spoofing:** RFC 1918 private ranges blocked on external interface
- **SYN Flood Protection:** Rate limiting (25/sec burst 50) + TCP flag validation
- **SSH Hardening:** Restricted to admin subnet (192.168.1.0/28) + rate limit (3 attempts/min)
- **Logging:** All dropped packets logged with prefix `[FW-DROP]` for forensic analysis
- **Kernel Hardening:** sysctl parameters — disabled IP forwarding, ICMP redirects, source routing

**Implementation Highlights:**

| Category | Details |
|----------|---------|
| Custom Chain | `SSH_RULES` — dedicated chain for SSH traffic management |
| Total Rules | **35+ iptables rules** configured and tested |
| Persistence | Rules saved via `iptables-save` and loaded at boot via `iptables-restore` |
| Backup | Rule snapshots exported before and after each change |

> *Suggested visual:* Use a layered/stacked diagram showing the defense-in-depth layers:
> Kernel Hardening → Default DENY → Anti-Spoofing → Stateful Inspection → Service Rules → Logging.

---

## Slide 6 — Testing Results (Phase 5)

**Title:** Penetration Testing & Validation

- **Methodology:** Black-box testing from Kali Linux attacker machine
- **Tools Used:** nmap (port scanning), ping (connectivity), hping3 (flood testing)
- **All 6 critical tests passed** — firewall behaved exactly as designed

**Test Results Matrix:**

| # | Test Case | Command Used | Expected Result | Actual Result | Status |
|---|-----------|-------------|-----------------|---------------|--------|
| 1 | Port Scan | `nmap -sV 192.168.1.10` | Only 22, 80, 443 open | 22, 80, 443 open | ✅ PASS |
| 2 | SSH (admin) | `ssh student@192.168.1.10` | Connection success | Connected | ✅ PASS |
| 3 | SSH (outside) | `ssh student@192.168.1.10` | Connection refused | Timed out | ✅ PASS |
| 4 | Ping Flood | `ping -f 192.168.1.10` | Rate limited | Packets dropped | ✅ PASS |
| 5 | Telnet | `telnet 192.168.1.10 23` | Blocked | Connection refused | ✅ PASS |
| 6 | FTP | `ftp 192.168.1.10` | Blocked | Connection refused | ✅ PASS |

**Result: 6/6 tests passed — 100% pass rate**

> *Suggested visual:* Use a green checkmark icon next to each PASS row.
> Consider a bar chart or circular "6/6 = 100%" graphic on the right side.

---

## Slide 7 — Security Audit (Phase 6)

**Title:** Automated Security Audit — Grade A (95.8%)

- **Tool:** Custom Python script (`audit_firewall.py`) — 11 automated security checks
- **CVE Assessment:** iptables version verified against NIST National Vulnerability Database

**Audit Checklist:**

| # | Security Check | Result |
|---|---------------|--------|
| 1 | Default policies set to DROP | ✅ Pass |
| 2 | Stateful inspection enabled | ✅ Pass |
| 3 | Anti-spoofing rules configured | ✅ Pass |
| 4 | SSH access hardened | ✅ Pass |
| 5 | Web server rules (80/443) | ✅ Pass |
| 6 | DNS configuration (outbound only) | ✅ Pass |
| 7 | ICMP rate limiting | ✅ Pass |
| 8 | Logging enabled for dropped packets | ✅ Pass |
| 9 | Egress filtering configured | ✅ Pass |
| 10 | No dangerous permissive rules | ✅ Pass |
| 11 | SYN flood protection | ✅ Pass |

**Final Score: 23/24 points — Grade A (Excellent)**

> *Suggested visual:* Large circular gauge/meter showing 95.8% in green.
> Place the checklist on the left, gauge on the right.

---

## Slide 8 — Gap Analysis & Remediation (Phase 7)

**Title:** Gap Analysis & Remediation Roadmap

**Gap Analysis Summary:**

| Status | Count | Percentage | Examples |
|--------|-------|------------|----------|
| 🟢 Fully Implemented | 16 / 30 | 53% | Default DENY, SSH hardening, logging |
| 🟡 Partially Implemented | 11 / 30 | 37% | Egress filtering, ICMP controls |
| 🔴 Not Implemented | 3 / 30 | 10% | IPv6 rules, IDS/IPS, SIEM |

**Top 3 Gaps Identified:**

| # | Gap | Risk Level | Impact |
|---|-----|-----------|--------|
| 1 | No IPv6 firewall rules (ip6tables) | 🔴 High | IPv6 traffic bypasses all controls |
| 2 | No IDS/IPS integration | 🟡 Medium | Cannot detect advanced attack patterns |
| 3 | No centralized logging (SIEM) | 🟡 Medium | Limited forensic & correlation capability |

**Remediation Roadmap:**

| Phase | Action | Timeline | Effort |
|-------|--------|----------|--------|
| Phase 1 | Disable IPv6 or configure ip6tables | 1–2 days | Low |
| Phase 2 | Deploy Snort/Suricata IDS | 1–2 weeks | Medium |
| Phase 3 | Set up ELK Stack / SIEM solution | 1–3 months | High |

**Compliance:** Mapped to **CIS Benchmarks** & **NIST SP 800-41** (Firewall Policy Guidelines)

> *Suggested visual:* Horizontal timeline/roadmap graphic for the 3 remediation phases.
> Use a stacked bar chart (green/yellow/red) for the gap analysis summary.

---

## Slide 9 — Conclusion & Key Takeaways

**Title:** Conclusion

- ✅ Successfully configured an **iptables firewall** for a SOHO network environment
- ✅ Implemented **defense-in-depth** with multiple overlapping security layers
- ✅ Built an **automated Python audit tool** — 11 checks, Grade A (95.8%)
- ✅ Identified **3 security gaps** with a prioritized remediation roadmap
- ✅ Mapped controls to industry standards: **CIS Benchmarks** & **NIST SP 800-41**

**Skills Demonstrated:**

| Skill Area | Application in Project |
|-----------|----------------------|
| Linux Administration | Ubuntu Server, iptables, sysctl hardening |
| Networking | TCP/IP, subnetting, packet filtering |
| Python Scripting | Automated audit tool (audit_firewall.py) |
| Security Auditing | Vulnerability assessment, gap analysis |
| Technical Writing | Professional documentation & reporting |

**Key Formula for a Strong Firewall:**

> **Default DENY + Stateful Inspection + Rate Limiting + Logging = Robust Security**

> *Suggested visual:* Use a summary icon layout (5 icons for 5 skills).
> End with the key formula in a highlighted callout box. Add a "Thank You / Questions?" footer.

---

## Appendix — Presentation Tips

| Aspect | Recommendation |
|--------|---------------|
| **Theme** | Use a dark professional theme (dark blue, charcoal) with white text |
| **Font** | Title: Calibri Bold 36pt · Body: Calibri 20pt · Code: Consolas 16pt |
| **Icons** | Use shield 🛡️, lock 🔒, and checkmark ✅ icons throughout |
| **Animations** | Minimal — use "Appear" for bullet points, avoid excessive transitions |
| **Duration** | Plan for ~2 minutes per slide = ~18 minutes total presentation |
| **Speaker Notes** | Add 3–4 talking points per slide for reference during presentation |

---

*Document prepared for: Network Security Minor Project — June 2026*
*Students: Sujal & Kowshik Chowdhary · Instructor: Ganesh K · Platform: labmentix.in*
