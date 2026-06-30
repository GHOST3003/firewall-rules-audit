# 🔒 Firewall Rules Audit

> **Minor Project | Network Security | Linux iptables Firewall Configuration & Security Audit**

**Author:** **Lalit Bairwa**

---

## 📖 Project Overview

**Firewall Rules Audit** is a Linux-based network security project that demonstrates the implementation, configuration, and auditing of firewall rules using **iptables**.

The project follows a **Default Deny** security model, allowing only authorized network traffic while blocking unnecessary or potentially malicious connections. A Python-based audit tool analyzes the firewall configuration and helps identify security issues based on common firewall security practices.

This project was developed as part of a **Network Security Minor Project** to demonstrate practical knowledge of Linux firewall administration, network hardening, and security auditing.

---

# 🎯 Objectives

* Configure a secure Linux firewall using iptables.
* Implement a Default Deny firewall policy.
* Protect network services from unauthorized access.
* Audit firewall rules using Python automation.
* Perform security testing before and after firewall implementation.
* Document security findings and recommendations.

---

# 🛠 Technologies Used

* Linux
* iptables (Netfilter)
* Bash Shell
* Python 3
* Nmap
* Git & GitHub

---

# 🌐 Network Scenario

The project simulates a Small Office/Home Office (SOHO) environment protected by a Linux firewall.

```
                 Internet
                     │
             ┌────────────────┐
             │    Firewall    │
             │    iptables    │
             └───────┬────────┘
                     │
          ┌──────────┴──────────┐
          │                     │
   Internal Network        Web Server
    192.168.1.0/24       192.168.1.10
```

---

# 🔐 Firewall Policy

| Service | Port | Protocol | Policy            |
| ------- | ---- | -------- | ----------------- |
| SSH     | 22   | TCP      | Restricted Access |
| HTTP    | 80   | TCP      | Allowed           |
| HTTPS   | 443  | TCP      | Allowed           |
| DNS     | 53   | TCP/UDP  | Outbound Only     |
| ICMP    | —    | ICMP     | Rate Limited      |

---

# 📂 Project Structure

```
firewall-rules-audit/
│
├── README.md
├── LICENSE
├── .gitignore
│
├── scripts/
│   ├── firewall_setup.sh
│   ├── firewall_status.sh
│   └── firewall_reset.sh
│
├── audit/
│   ├── audit_firewall.py
│   └── sample_iptables_output.txt
│
├── docs/
│   ├── audit_report.md
│   ├── gap_analysis.md
│   ├── before_firewall.nmap
│   ├── after_firewall.nmap
│   └── presentation_notes.md
│
├── diagrams/
│   ├── network_topology.txt
│   └── network_topology.png
│
└── screenshots/
    ├── firewall_rules.png
    ├── audit_output.png
    ├── nmap_before.png
    ├── nmap_after.png
    ├── ssh_connection.png
    ├── server_terminal.png
    └── firewall_server.png
```

---

# 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/firewall-rules-audit.git
cd firewall-rules-audit
```

---

# ⚙ Configure Firewall

Make the scripts executable:

```bash
chmod +x scripts/*.sh
```

Apply firewall rules:

```bash
sudo ./scripts/firewall_setup.sh
```

---

# 📋 Check Firewall Status

```bash
sudo ./scripts/firewall_status.sh
```

---

# 🔍 Perform Firewall Audit

Export the current firewall configuration:

```bash
sudo iptables -L -n -v --line-numbers > audit/sample_iptables_output.txt
```

Run the audit tool:

```bash
python3 audit/audit_firewall.py
```

---

# 🔄 Reset Firewall

```bash
sudo ./scripts/firewall_reset.sh
```

---

# 🧪 Security Testing

The firewall configuration was verified using **Nmap** before and after applying firewall rules.

The project includes:

* Nmap scan before firewall configuration
* Nmap scan after firewall configuration
* Firewall rule verification
* SSH connectivity testing
* Automated firewall audit

---

# 🛡 Security Features

* Default Deny Policy
* Stateful Packet Inspection
* SSH Hardening
* ICMP Rate Limiting
* Firewall Rule Logging
* Egress Filtering
* Automated Firewall Rule Analysis
* Basic Network Hardening

---

# 📊 Audit Summary

| Security Control  | Status |
| ----------------- | ------ |
| Default Policy    | ✅ PASS |
| SSH Protection    | ✅ PASS |
| Firewall Logging  | ✅ PASS |
| ICMP Protection   | ✅ PASS |
| Rule Verification | ✅ PASS |
| Automated Audit   | ✅ PASS |

---

# 📸 Screenshots

The repository includes screenshots demonstrating:

* Firewall configuration
* iptables rule table
* SSH connection
* Python audit output
* Nmap scan before firewall
* Nmap scan after firewall
* Firewall server terminal

---

# 📚 Documentation

Additional documentation is available in the **docs/** directory:

* Audit Report
* Gap Analysis
* Nmap Scan Results
* Presentation Notes

---

# 🎓 Learning Outcomes

This project demonstrates practical skills in:

* Linux Administration
* Firewall Configuration
* Network Security
* Bash Scripting
* Python Automation
* Security Auditing
* Network Hardening
* Nmap Security Assessment

---

# 🚀 Future Improvements

* IPv6 Firewall Support
* nftables Migration
* PDF Audit Report Generation
* Web-based Firewall Dashboard
* Email Alerting
* Automatic Rule Backup & Restore
* Firewall Rule Visualization

---

# 📚 References

* Netfilter / iptables Documentation
* NIST SP 800-41 Rev.1 – Guidelines on Firewalls and Firewall Policy
* CIS Linux Benchmarks
* SANS Institute – Firewall Best Practices
* Nmap Documentation

---

# ⚠ Disclaimer

This project is intended for educational and laboratory purposes only. Test firewall rules in a controlled environment before deploying them to production systems.

---

# 👨‍💻 Author

**Lalit Bairwa**

**B.Tech CSE (Cyber Security)**

**Minor Project – Network Security**
