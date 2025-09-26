OSCP Tools Installation Script
A comprehensive one-script solution for installing all essential OSCP (Offensive Security Certified Professional) preparation tools on Kali Linux.

🎯 Purpose
This script automates the installation of 50+ penetration testing tools specifically needed for OSCP exam preparation on Kali Linux 6.12.25-amd64.

🚀 Quick Start
Command Installation
git clone https://github.com/ibrahimptsec/kali-oscp-setup/
cd kali-oscp-setup
chmod +x kali-oscp-setup.sh
sudo ./kali-oscp-setup.sh


📦 What Gets Installed
🎯 Active Directory Tools

Impacket - Complete suite (secretsdump, GetNPUsers, GetUserSPNs, etc.)
BloodHound + Neo4j - AD relationship mapping
CrackMapExec - Network service exploitation
Evil-WinRM - Windows Remote Management shell
Kerbrute - Kerberos username enumeration
Rubeus - Kerberos interaction toolkit (Windows binary)
ldapdomaindump - LDAP enumeration tool

🌐 Web Application Tools

Feroxbuster - Fast directory enumeration
Aquatone - Domain flyover tool
Nuclei - Vulnerability scanner with templates
HTTPx - HTTP toolkit
Subfinder - Subdomain discovery
XSStrike - XSS detection and exploitation
ParamSpider - Parameter discovery
Arjun - HTTP parameter finder
NoSQLMap - NoSQL injection tool
CMSeeK - CMS detection and exploitation
LinkFinder - JavaScript endpoint extractor
SecretFinder - Find secrets in JS files
GitTools - Git repository exploitation
JWT tools - JSON Web Token testing

⚡ Privilege Escalation Tools

PEASS-ng - LinPEAS/WinPEAS suite
PowerSploit - PowerShell exploitation framework
JuicyPotato, RoguePotato - Windows token impersonation
PrintSpoofer - Print spooler exploitation
GodPotato, SweetPotato - Advanced token abuse
pspy - Process monitoring without root
LinEnum - Linux enumeration script
Linux Smart Enumeration - Advanced Linux enum
traitor - Automated Linux privesc
wesng - Windows Exploit Suggester

🔍 Network Enumeration Tools

AutoRecon - Automated reconnaissance
nmapAutomator - Automated nmap scanning
RustScan - High-speed port scanner

🔄 Pivoting & Tunneling Tools

Chisel - Fast TCP/UDP tunnel (Linux + Windows)
Ligolo-ng - Advanced tunneling tool
sshuttle - Transparent proxy server

🎧 Additional Tools

pwncat-cs - Enhanced netcat replacement
SecLists - Comprehensive wordlist collection
PayloadsAllTheThings - Payload repository


🛠️ Post-Installation Steps
1. Restart Terminal
bash# Apply new bash configuration
source ~/.bashrc
# Or restart your terminal

2. Test Key Tools
bash# Test BloodHound
sudo neo4j start
bloodhound

# Test Impacket
impacket-secretsdump -h

# Test custom aliases
cheat  # Shows OSCP cheat sheet
tools  # Browse installed tools

3. Verify Installation
bash# Check installed tools
ls /opt/

# Test custom functions
nmapquick --help
revshell
webenum


🤝 Contributing
Found a bug or want to add a tool? Contributions are welcome!

Fork the repository
Create a feature branch
Make your changes
Test on a fresh Kali installation
Submit a pull request
