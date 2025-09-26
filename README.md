# 🛡️ OSCP Tools Installation Script

A comprehensive **one-script solution** for installing all essential OSCP (Offensive Security Certified Professional) preparation tools on Kali Linux.

---

## 🎯 Purpose

Automate the installation of **50+ top penetration testing tools** specifically for OSCP exam prep on Kali Linux (tested on 6.12.25-amd64).

---

## 🚀 Quick Start

**Install in 4 easy steps:**

```bash
git clone https://github.com/ibrahimptsec/kali-oscp-setup/
cd kali-oscp-setup
chmod +x kali-oscp-setup.sh
sudo ./kali-oscp-setup.sh
```

---

## 📦 Tools Installed

### 🏢 Active Directory

- **Impacket** – Suite: secretsdump, GetNPUsers, GetUserSPNs, etc.
- **BloodHound + Neo4j** – AD relationship mapping
- **CrackMapExec** – Network exploitation
- **Evil-WinRM** – WinRM shell
- **Kerbrute** – Kerberos enumeration
- **Rubeus** – Kerberos toolkit *(Windows binary)*
- **ldapdomaindump** – LDAP enum

### 🌐 Web Application

- **Feroxbuster** – Fast directory enum
- **Aquatone** – Domain flyover
- **Nuclei** – Vulnerability scanner
- **HTTPx** – HTTP toolkit
- **Subfinder** – Subdomain discovery
- **XSStrike** – XSS testing
- **ParamSpider** – Parameter discovery
- **Arjun** – HTTP param finder
- **NoSQLMap** – NoSQL injection
- **CMSeeK** – CMS exploitation
- **LinkFinder** – JS endpoint extractor
- **SecretFinder** – Find secrets in JS
- **GitTools** – Git repo exploitation
- **JWT Tools** – Token testing

### ⚡ Privilege Escalation

- **PEASS-ng** – LinPEAS/WinPEAS
- **PowerSploit** – PowerShell exploitation
- **JuicyPotato, RoguePotato** – Token impersonation
- **PrintSpoofer** – Spooler exploitation
- **GodPotato, SweetPotato** – Token abuse
- **pspy** – Process monitoring
- **LinEnum** – Linux enum
- **Linux Smart Enumeration**
- **traitor** – Automated privesc
- **wesng** – Windows Exploit Suggester

### 🔍 Network Enumeration

- **AutoRecon** – Automated recon
- **nmapAutomator** – Automated nmap
- **RustScan** – Fast port scanner

### 🔄 Pivoting & Tunneling

- **Chisel** – TCP/UDP tunnel *(Linux/Windows)*
- **Ligolo-ng** – Advanced tunneling
- **sshuttle** – Transparent proxy

### 🎧 Additional

- **pwncat-cs** – Netcat replacement
- **SecLists** – Wordlists
- **PayloadsAllTheThings** – Payload repo

---

## 🛠️ Post-Installation

1. **Restart Terminal**
   ```bash
   source ~/.bashrc
   # Or just restart your terminal
   ```

2. **Test Key Tools**
   - BloodHound:
     ```bash
     sudo neo4j start
     bloodhound
     ```
   - Impacket:
     ```bash
     impacket-secretsdump -h
     ```
   - Aliases:
     ```bash
     cheat      # OSCP cheat sheet
     tools      # Browse installed tools
     ```

3. **Verify Installation**
   ```bash
   ls /opt/
   nmapquick --help
   revshell
   webenum
   ```

---

## 🤝 Contributing

Found a bug or want to add a tool? **Contributions are welcome!**

- Fork the repo
- Create a feature branch
- Make changes & test on fresh Kali
- Submit a Pull Request

---

*Happy hacking & good luck on your OSCP journey!*
