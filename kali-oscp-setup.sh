#!/bin/bash

# OSCP Tools Installation Script for Kali Linux 6.12.25-amd64
# Run this script step by step or in sections as needed

echo "==============================================="
echo "OSCP Tools Installation Guide for Kali Linux"
echo "==============================================="

# Update system first
echo "[+] Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install essential packages that might be missing
echo "[+] Installing essential packages..."
sudo apt install -y curl wget git vim tmux screen htop tree unzip p7zip-full

echo ""
echo "=== ACTIVE DIRECTORY TOOLS ==="

# Install Python3 and pip if not already present
echo "[+] Installing Python3 and pip..."
sudo apt install -y python3 python3-pip python3-venv python3-dev

# Install Impacket (Essential for AD attacks)
echo "[+] Installing Impacket..."
pip3 install impacket

# Alternative method if above fails:
# git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
# cd /opt/impacket && pip3 install .

# Install BloodHound and Neo4j
echo "[+] Installing Neo4j and BloodHound..."
sudo apt install -y neo4j bloodhound

# Install PowerView equivalent for Linux
echo "[+] Installing ldapdomaindump..."
pip3 install ldapdomaindump

# Install CrackMapExec
echo "[+] Installing CrackMapExec..."
pip3 install crackmapexec

# Install Evil-WinRM
echo "[+] Installing Evil-WinRM..."
sudo gem install evil-winrm

# Install Kerbrute
echo "[+] Installing Kerbrute..."
cd /opt
sudo git clone https://github.com/ropnop/kerbrute.git
cd kerbrute
sudo make all
sudo ln -sf /opt/kerbrute/dist/kerbrute_linux_amd64 /usr/local/bin/kerbrute

# Install Rubeus (compile on Windows target or use pre-compiled)
echo "[+] Downloading Rubeus..."
cd /opt
sudo mkdir rubeus
cd rubeus
sudo wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe

echo ""
echo "=== WEB APPLICATION TOOLS ==="

# Most web tools should already be in Kali, but let's ensure they're updated
echo "[+] Installing/Updating Web Application Tools..."

# Burp Suite (should be pre-installed, but let's check)
sudo apt install -y burpsuite

# Install additional web tools
sudo apt install -y gobuster ffuf wfuzz nikto whatweb

# Install Feroxbuster (Rust-based directory buster)
echo "[+] Installing Feroxbuster..."
cd /tmp
curl -sLO https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb
sudo dpkg -i feroxbuster_amd64.deb

# Install aquatone for web reconnaissance
echo "[+] Installing Aquatone..."
cd /opt
sudo wget https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip
sudo unzip aquatone_linux_amd64_1.7.0.zip
sudo chmod +x aquatone
sudo ln -sf /opt/aquatone /usr/local/bin/aquatone

echo ""
echo "=== WINDOWS PRIVILEGE ESCALATION TOOLS ==="

# Install Windows enumeration scripts
echo "[+] Setting up Windows PrivEsc tools..."
cd /opt
sudo git clone https://github.com/carlospolop/PEASS-ng.git
sudo git clone https://github.com/PowerShellMafia/PowerSploit.git
sudo git clone https://github.com/rasta-mouse/Sherlock.git
sudo git clone https://github.com/bitsadmin/wesng.git

# Install PowerUp and PowerView
sudo git clone https://github.com/PowerShellEmpire/PowerTools.git

# Download Windows binaries
echo "[+] Downloading Windows exploitation binaries..."
cd /opt
sudo mkdir windows-binaries
cd windows-binaries

# Download common Windows exploit binaries
sudo wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe
sudo wget https://github.com/antonioCoco/RoguePotato/releases/download/1.0/RoguePotato.zip
sudo unzip RoguePotato.zip

# Download PrintSpoofer
sudo wget https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe

echo ""
echo "=== LINUX PRIVILEGE ESCALATION TOOLS ==="

echo "[+] Installing Linux PrivEsc tools..."

# Install LinEnum
cd /opt
sudo git clone https://github.com/rebootuser/LinEnum.git

# Install linux-smart-enumeration
sudo git clone https://github.com/diego-treitos/linux-smart-enumeration.git

# Install LinPEAS (already part of PEASS-ng cloned above)

# Install pspy for process monitoring
cd /opt
sudo wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64
sudo wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32
sudo chmod +x pspy64 pspy32

echo ""
echo "=== NETWORK ENUMERATION TOOLS ==="

echo "[+] Installing Network Enumeration Tools..."

# Most should be pre-installed, but let's ensure
sudo apt install -y nmap masscan rustscan

# Install AutoRecon
pip3 install autorecon

# Install nmapAutomator
cd /opt
sudo git clone https://github.com/21y4d/nmapAutomator.git
sudo chmod +x nmapAutomator/nmapAutomator.sh
sudo ln -sf /opt/nmapAutomator/nmapAutomator.sh /usr/local/bin/nmapAutomator

echo ""
echo "=== PIVOTING AND TUNNELING TOOLS ==="

echo "[+] Installing Pivoting/Tunneling tools..."

# Install Chisel
cd /opt
sudo wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_linux_amd64.gz
sudo gunzip chisel_1.7.7_linux_amd64.gz
sudo chmod +x chisel_1.7.7_linux_amd64
sudo mv chisel_1.7.7_linux_amd64 chisel
sudo ln -sf /opt/chisel /usr/local/bin/chisel

# Download Windows version of Chisel
sudo wget https://github.com/jpillora/chisel/releases/download/v1.7.7/chisel_1.7.7_windows_amd64.gz
sudo gunzip chisel_1.7.7_windows_amd64.gz
sudo chmod +x chisel_1.7.7_windows_amd64
sudo mv chisel_1.7.7_windows_amd64 chisel.exe

# Install ligolo-ng
cd /opt
sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
sudo wget https://github.com/nicocha30/ligolo-ng/releases/download/v0.4.3/ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz
sudo tar -xzf ligolo-ng_agent_0.4.3_Linux_64bit.tar.gz
sudo tar -xzf ligolo-ng_proxy_0.4.3_Linux_64bit.tar.gz

# Install sshuttle
pip3 install sshuttle

echo ""
echo "=== REVERSE SHELL TOOLS ==="

echo "[+] Installing Reverse Shell tools..."

# Install pwncat-cs (modern replacement for netcat listeners)
pip3 install pwncat-cs

# Install rlwrap for better shell interaction
sudo apt install -y rlwrap

echo ""
echo "=== CREDENTIAL ATTACKS ==="

echo "[+] Installing Credential Attack tools..."

# Hashcat should be pre-installed
sudo apt install -y hashcat hashcat-utils

# John the Ripper should be pre-installed
sudo apt install -y john

# Install Responder (should be pre-installed)
sudo apt install -y responder

# Install Patator for password spraying
pip3 install patator

echo ""
echo "=== CODE ANALYSIS AND REVERSE ENGINEERING ==="

echo "[+] Installing Code Analysis tools..."

# Install Ghidra (if not already present)
sudo apt install -y ghidra

# Install radare2
sudo apt install -y radare2

# Install strings, file, binwalk (should be pre-installed)
sudo apt install -y binutils binwalk file

echo ""
echo "=== PAYLOAD GENERATION AND ENCODING ==="

echo "[+] Setting up Payload Generation tools..."

# msfvenom should be pre-installed with Metasploit
sudo apt install -y metasploit-framework

# Install donut for .NET payload generation
pip3 install donut-shellcode

# Install msfpc for easier payload generation
cd /opt
sudo git clone https://github.com/g0tmi1k/mpc.git

echo ""
echo "=== USEFUL SCRIPTS AND WORDLISTS ==="

echo "[+] Installing wordlists and useful scripts..."

# SecLists should be pre-installed, but let's ensure
sudo apt install -y seclists

# If not available, install manually:
# cd /opt
# sudo git clone https://github.com/danielmiessler/SecLists.git

# Install PayloadsAllTheThings
cd /opt
sudo git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# Install HackerOne H1-212 CTF scripts (good for learning)
sudo git clone https://github.com/0xRick/CVE-2017-1000353.git

echo ""
echo "=== DATABASE AND WEB SERVER TOOLS ==="

echo "[+] Installing Database tools..."

# Install database clients
sudo apt install -y mysql-client postgresql-client sqlite3

# Install SQLMAP (should be pre-installed)
sudo apt install -y sqlmap

echo ""
echo "=== USEFUL ALIASES AND CONFIGURATIONS ==="

echo "[+] Setting up useful aliases..."

# Add useful aliases to .bashrc
cat >> ~/.bashrc << 'EOF'

# OSCP Aliases
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias fgrep='fgrep --color=auto'
alias egrep='egrep --color=auto'

# OSCP-specific aliases
alias nse='ls /usr/share/nmap/scripts/ | grep'
alias ports='netstat -tulanp'
alias listen='lsof -i -P -n | grep LISTEN'
alias www='python3 -m http.server 80'
alias wwws='python3 -m http.server 443'
alias myip='curl -s ipinfo.io/ip'
alias urlencode='python3 -c "import sys, urllib.parse as ul; print(ul.quote_plus(sys.argv[1]))"'
alias urldecode='python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus(sys.argv[1]))"'
alias b64d='base64 -d'
alias b64e='base64 -w 0'

# Directory shortcuts
alias pentest='cd /opt && ls'
alias tools='cd /opt && ls'
alias wordlists='cd /usr/share/wordlists && ls'
alias seclists='cd /usr/share/seclists && ls'

EOF

echo ""
echo "=== PYTHON TOOLS AND MODULES ==="

echo "[+] Installing Python modules for exploit development..."

pip3 install pwntools
pip3 install requests
pip3 install beautifulsoup4
pip3 install lxml
pip3 install paramiko
pip3 install scapy
pip3 install colorama
pip3 install termcolor
pip3 install python-ldap
pip3 install dnspython

echo ""
echo "=== TMUX CONFIGURATION ==="

echo "[+] Setting up tmux configuration..."

cat > ~/.tmux.conf << 'EOF'
# Change prefix key to Ctrl-a
unbind C-b
set -g prefix C-a
bind C-a send-prefix

# Enable mouse support
set -g mouse on

# Set window and pane index to 1
set -g base-index 1
setw -g pane-base-index 1

# Split panes using | and -
bind | split-window -h
bind - split-window -v
unbind '"'
unbind %

# Switch panes using Alt-arrow without prefix
bind -n M-Left select-pane -L
bind -n M-Right select-pane -R
bind -n M-Up select-pane -U
bind -n M-Down select-pane -D

# Enable vi mode
setw -g mode-keys vi

# Status bar
set -g status-bg black
set -g status-fg white
set -g status-interval 60
set -g status-left-length 30
set -g status-left '#[fg=green](#S) #(whoami)@#H'
set -g status-right '#[fg=yellow]#(cut -d " " -f 1-3 /proc/loadavg)#[default] #[fg=white]%H:%M#[default]'
EOF

echo ""
echo "=== CREATE OSCP DIRECTORY STRUCTURE ==="

echo "[+] Creating OSCP directory structure..."

mkdir -p ~/oscp/{machines,tools,wordlists,notes,scripts,payloads}
mkdir -p ~/oscp/machines/{active,retired}
mkdir -p ~/oscp/notes/{enumeration,exploitation,privesc,ad}

echo ""
echo "=== FINAL CONFIGURATIONS ==="

echo "[+] Setting execute permissions and final setup..."

# Make sure all tools in /opt are executable
sudo find /opt -type f -name "*.sh" -exec chmod +x {} \;
sudo find /opt -type f -name "*.py" -exec chmod +x {} \;

# Update locate database
sudo updatedb

# Source the new bashrc
source ~/.bashrc

echo ""
echo "==============================================="
echo "           INSTALLATION COMPLETE!"
echo "==============================================="
echo ""
echo "Summary of installed tools:"
echo ""
echo "Active Directory Tools:"
echo "  - Impacket (secretsdump, GetNPUsers, etc.)"
echo "  - BloodHound + Neo4j"
echo "  - CrackMapExec"
echo "  - Evil-WinRM"
echo "  - Kerbrute"
echo "  - Rubeus (binary downloaded)"
echo ""
echo "Web Application Tools:"
echo "  - Burp Suite"
echo "  - Gobuster, FFuF, Feroxbuster"
echo "  - Aquatone"
echo ""
echo "Privilege Escalation:"
echo "  - LinPEAS/WinPEAS"
echo "  - PowerSploit"
echo "  - JuicyPotato, PrintSpoofer"
echo "  - pspy"
echo ""
echo "Network Tools:"
echo "  - AutoRecon"
echo "  - nmapAutomator"
echo "  - RustScan"
echo ""
echo "Pivoting/Tunneling:"
echo "  - Chisel"
echo "  - Ligolo-ng"
echo "  - sshuttle"
echo ""
echo "Additional Tools:"
echo "  - pwncat-cs"
echo "  - PayloadsAllTheThings"
echo "  - SecLists wordlists"
echo ""
echo "Useful Commands to Remember:"
echo "  - Start Neo4j: sudo neo4j start"
echo "  - Start BloodHound: bloodhound"
echo "  - Python web server: python3 -m http.server 80"
echo "  - Check installed tools: ls /opt"
echo ""
echo "Directory Structure Created:"
echo "  ~/oscp/machines/{active,retired}"
echo "  ~/oscp/{tools,wordlists,notes,scripts,payloads}"
echo ""
echo "Next Steps:"
echo "1. Restart your terminal or run 'source ~/.bashrc'"
echo "2. Test BloodHound: sudo neo4j start && bloodhound"
echo "3. Verify Impacket: impacket-secretsdump -h"
echo "4. Start with HTB machine 'Active' for practice!"
echo ""
echo "Happy Hacking! 🚀"