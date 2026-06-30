# 🔒 Firewall Rules Audit — Minor Project

## Network Security | Firewall Rules Configuration & Audit

**Project By:** Sujal & Kowshik Chowdhary

---

## 📋 Project Overview
 
This project demonstrates the configuration and auditing of Linux `iptables` firewall rules for a **Small Office/Home Office (SOHO)** network. It showcases foundational network security skills including:

- Linux iptables configuration from scratch
- Allow/deny rule logic and policy thinking
- Security documentation and gap analysis
- Understanding of network perimeter defense

## 🏗️ Network Scenario

**Small Office / Home Network** with the following services:

| Service       | Port(s)       | Protocol | Access Policy          |
|---------------|---------------|----------|------------------------|
| SSH           | 22            | TCP      | Restricted (admin IPs) |
| HTTP          | 80            | TCP      | Public                 |
| HTTPS         | 443           | TCP      | Public                 |
| DNS           | 53            | TCP/UDP  | Outbound only          |
| ICMP (Ping)   | —             | ICMP     | Rate-limited           |

**Network Topology:**
```
                    ┌──────────────┐
   Internet ────────│   Firewall   │──────── Internal LAN
                    │  (iptables)  │         192.168.1.0/24
                    └──────────────┘
                          │
                    ┌─────┴──────┐
                    │ Web Server │
                    │ 192.168.1.10│
                    └────────────┘
```

## 📁 Project Structure

```
firewall-rules-audit/
│
├── README.md                        # This file
├── scripts/
│   ├── firewall_setup.sh            # Main iptables configuration script
│   ├── firewall_reset.sh            # Script to flush/reset all rules
│   └── firewall_status.sh           # Script to display current rules
│
├── audit/
│   ├── audit_firewall.py            # Python audit script (parses & analyzes rules)
│   └── sample_iptables_output.txt   # Sample iptables output for testing
│
├── docs/
│   ├── audit_report.md              # Complete security audit report
│   └── gap_analysis.md              # Security gap analysis document
│
└── diagrams/
    └── network_topology.txt         # ASCII network diagram
```

## 🚀 How to Use

### 1. Apply Firewall Rules
```bash
sudo chmod +x scripts/firewall_setup.sh
sudo ./scripts/firewall_setup.sh
```

### 2. Check Firewall Status
```bash
sudo ./scripts/firewall_status.sh
```

### 3. Run the Audit Script
```bash
# Generate current rules and audit them
sudo iptables -L -n -v --line-numbers > audit/sample_iptables_output.txt
python3 audit/audit_firewall.py
```

### 4. Reset Firewall (if needed)
```bash
sudo ./scripts/firewall_reset.sh
```

## 🔑 Key Concepts Demonstrated

1. **Default Deny Policy** — Drop all traffic by default, allow only what's needed
2. **Stateful Inspection** — Using connection tracking (`conntrack`) for established sessions
3. **Rate Limiting** — Preventing brute-force and DoS attacks
4. **Logging** — Logging dropped packets for forensic analysis
5. **Egress Filtering** — Controlling outbound traffic to prevent data exfiltration
6. **Anti-Spoofing** — Blocking packets with spoofed source addresses

## 📊 Audit Findings Summary

| Category            | Status    | Details                         |
|---------------------|-----------|---------------------------------|
| Default Policy      | ✅ PASS   | Default DROP on INPUT/FORWARD   |
| SSH Hardening       | ✅ PASS   | Rate-limited, restricted IPs    |
| Logging             | ✅ PASS   | Dropped packets logged          |
| Anti-Spoofing       | ✅ PASS   | RFC 1918 ingress blocked        |
| Egress Filtering    | ⚠️ PARTIAL| Only essential ports allowed    |
| ICMP                | ✅ PASS   | Rate-limited, type-restricted   |

## 📚 References

- [Netfilter/iptables Official Documentation](https://netfilter.org/documentation/)
- [CIS Benchmark for Linux](https://www.cisecurity.org/benchmark/distribution_independent_linux)
- [NIST SP 800-41 Rev.1 — Guidelines on Firewalls and Firewall Policy](https://csrc.nist.gov/publications/detail/sp/800-41/rev-1/final)
- [SANS Institute — Firewall Best Practices](https://www.sans.org/white-papers/)

---

> **Note:** This project is for educational purposes. Always test firewall rules in a safe lab environment before deploying to production systems.
