Intrusion Detection System using Snort
Complete Network Intrusion Detection Tool Repository
A comprehensive guide and toolkit for using Snort, the industry-standard network intrusion detection and prevention system. This repository contains installation instructions, configurations, usage examples, practical demonstrations, and real-world scenarios for network security.

License: MITGitHubSnort

📋 Table of Contents
About Snort

Features

Why Use Snort

Installation

Linux Installation

Windows Installation

Operational Modes

Commands and Configuration

Rule Writing

Practical Use Cases

Troubleshooting

Best Practices

Contributing

License

🔍 About Snort
Snort is a powerful, open-source network-based intrusion detection system (NIDS) and intrusion prevention system (IPS) created in 1998 by Martin Roesch, founder and former CTO of Sourcefire. Snort is currently developed and maintained by Cisco, which acquired Sourcefire in 2013.

In 2009, Snort entered InfoWorld's Open Source Hall of Fame as one of the "greatest pieces of open source software of all time."

Snort performs real-time traffic analysis and packet logging on IP networks, enabling it to detect various attacks as they occur. With millions of downloads and approximately 400,000 registered users, Snort has become the industry standard for intrusion detection and prevention systems.

Key History
Created: September 1997 by Martin Roesch

Current Maintainer: Cisco Systems (acquired Sourcefire in 2013)

Recognition: InfoWorld Open Source Hall of Fame (2009)

Users: 400,000+ registered users globally

Downloads: Millions worldwide

Status: Active development and community support

✨ Features
Feature	Description
Real-Time Analysis	Monitor network traffic and detect threats as they occur
Protocol Analysis	Understand and analyze various network protocols (TCP, UDP, ICMP, etc.)
Content Matching	Identify malicious patterns in network traffic
Attack Detection	Detect buffer overflows, port scans, DoS attacks, SQL injection, and more
Flexible Rules	Customize detection through user-defined rule-based configurations
Multiple Modes	Function as sniffer, packet logger, or full NIDS/IPS
Cross-Platform	Works on Linux, Windows, Unix, and BSD systems
Open Source	Free, community-driven, with active development
Modular Architecture	Extensible through plugins and preprocessors
Real-Time Alerting	Immediate notification of security events
💡 Why Use Snort?
Snort is widely used in cybersecurity for several compelling reasons:

Real-Time Traffic Analysis: Monitors network traffic and detects threats as they happen

Protocol Analysis: Understands and analyzes various network protocols (TCP, UDP, ICMP, etc.)

Content Searching and Matching: Identifies malicious patterns in network traffic

Attack Detection: Detects buffer overflows, port scans, DoS attacks, SQL injection, and more

Flexible Rule-Based Engine: Customizable detection through user-defined rules

Multiple Operating Modes: Can function as sniffer, packet logger, or full NIDS/IPS

Open Source and Free: No licensing costs, with active community support

Cross-Platform: Works on Linux, Windows, Unix, and BSD systems

Industry Standard: Trusted by security professionals worldwide

📦 Installation
Linux Installation (Ubuntu/Debian)
Step 1: Update System Packages
bash
sudo apt update
sudo apt upgrade -y
Explanation: Updates package lists and upgrades existing packages to latest versions.

Step 2: Install Snort
bash
sudo apt install snort -y
Explanation: Snort installation from Ubuntu repositories. During installation, you'll be prompted to configure:

Network interface to monitor (e.g., eth0, ens33)

HOME_NET address range (e.g., 192.168.1.0/24)

Step 3: Configure Network Interface
During installation, when prompted:

Interface: Enter your network interface name (check with ip a command)

HOME_NET: Enter your local network CIDR (e.g., 192.168.1.0/24)

Step 4: Verify Installation
bash
snort -V
Expected Output:

text
,,_
-*> Snort! <*-
o" )~ Version 2.9.15.1 GRE (Build 82)
''''
By Martin Roesch & The Snort Team
Copyright (C) 1998-2019 Sourcefire, Inc., et al.
Step 5: Test Configuration
bash
sudo snort -T -c /etc/snort/snort.conf
Explanation: Tests (-T) the configuration file (-c) without actually running Snort. Should show "Snort successfully validated the configuration!"

Windows Installation
Step 1: Download Snort
Visit: https://www.snort.org/downloads

Download the latest Windows installer (e.g., Snort_2_9_15_1_Installer.exe)

Register for a free community account if prompted

Step 2: Install Npcap (Recommended over WinPcap)
Download from: https://npcap.com/#download

Run the installer with administrator privileges

Select "Install Npcap in WinPcap API-compatible Mode"

Complete installation

Step 3: Install Visual C++ Redistributable
Download from Microsoft's website

Install Visual C++ Redistributable 2015-2019 (x64)

Required for Snort to run properly

Step 4: Install Snort
Run Snort installer as Administrator

Choose installation directory (default: C:\Snort)

Complete installation wizard

Installation creates directories:

C:\Snort\bin - Snort executable

C:\Snort\etc - Configuration files

C:\Snort\rules - Rule files

C:\Snort\log - Log directory

Step 5: Configure Snort
Navigate to C:\Snort\etc

Edit snort.conf in text editor

Set HOME_NET variable to your network (e.g., 192.168.1.0/24)

Set paths to rule files and output plugins

Step 6: Verify Installation
Open Command Prompt as Administrator:

bash
cd C:\Snort\bin
snort -V
Expected Output: Version information similar to Linux

Step 7: Test Configuration
bash
snort -T -c C:\Snort\etc\snort.conf
🎯 Operational Modes
Snort can operate in three primary modes, each serving different purposes:

3.1 Sniffer Mode
Purpose: Capture and display network packets in real-time on console (like tcpdump or Wireshark).

Basic Sniffer Command:

bash
snort -v
Explanation:

-v: Verbose mode, displays packet headers and data

Display IP Headers Only:

bash
snort -vd
Explanation:

-v: Verbose mode

-d: Display application layer data

Display Full Packet Details:

bash
snort -vde
Explanation:

-v: Verbose

-d: Display data

-e: Display data link layer headers

Sniff on Specific Interface:

bash
# Linux
sudo snort -v -i eth0

# Windows
snort -v -i 1
Explanation:

-i eth0: Monitor specific interface (replace eth0 with your interface)

3.2 Packet Logger Mode
Purpose: Record packets to disk for later analysis and forensics.

Log Packets to Directory:

bash
# Linux
sudo snort -dev -l /var/log/snort

# Windows
snort -dev -l C:\Snort\log
Explanation:

-dev: Display full packet information

-l: Log directory path

Log in Binary Format (pcap):

bash
# Linux
sudo snort -b -l /var/log/snort

# Windows
snort -b -l C:\Snort\log
3.3 NIDS Mode
Purpose: Perform intrusion detection with rule-based analysis.

Console Alert Mode:

bash
# Linux
sudo snort -A console -q -c /etc/snort/snort.conf -i eth0

# Windows
snort -A console -q -c C:\Snort\etc\snort.conf -i 1
Fast Alert Mode:

bash
# Linux
sudo snort -A fast -c /etc/snort/snort.conf -i eth0

# Windows
snort -A fast -c C:\Snort\etc\snort.conf -i 1
Full Alert Mode:

bash
# Linux
sudo snort -A full -c /etc/snort/snort.conf -i eth0

# Windows
snort -A full -c C:\Snort\etc\snort.conf -i 1
🔧 Commands and Configuration
Basic Commands
Command	Purpose	Linux	Windows
Check Version	Display Snort version	sudo snort -V	snort -V
List Interfaces	Show network interfaces	snort -W	snort -W
Test Config	Validate configuration file	sudo snort -T -c /etc/snort/snort.conf	snort -T -c C:\Snort\etc\snort.conf
Read and Analyze Traffic
Linux:

bash
sudo snort -r capture.pcap -c /etc/snort/snort.conf
sudo snort --pcap-dir=/var/log/pcaps -c /etc/snort/snort.conf
Windows:

bash
snort -r C:\Snort\log\capture.pcap -c C:\Snort\etc\snort.conf
snort --pcap-dir=C:\Snort\log\pcaps -c C:\Snort\etc\snort.conf
Create and Edit Rules
Linux:

bash
sudo nano /etc/snort/rules/local.rules
Windows:

bash
notepad C:\Snort\rules\local.rules
Fix Permissions
Linux:

bash
sudo chmod 644 /etc/snort/rules/*.rules
sudo chown -R snort:snort /etc/snort/rules/
Windows (Run as Administrator):

powershell
icacls C:\Snort\rules /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T
icacls C:\Snort\log /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T
📝 Rule Writing
Rule Syntax
text
action protocol src_ip src_port -> dest_ip dest_port (option1:"value1"; option2:"value2";)
Essential Rule Options
Option	Purpose	Example
msg	Alert message	msg:"ICMP Ping Detected"
content	Match specific string	content:"admin"
nocase	Case-insensitive match	content:"admin"; nocase;
sid	Unique rule ID	sid:1000001
rev	Revision number	rev:1
classtype	Attack classification	classtype:web-application-attack
priority	Alert priority (1-4)	priority:1
flow	Traffic flow direction	flow:to_server,established
pcre	Perl Compatible Regex	pcre:"/admin\.php/i"
Example Rules
ICMP Ping Detection:

text
alert icmp any any -> $HOME_NET any (msg:"ICMP Ping Detected"; itype:8; sid:1000001; rev:1;)
SQL Injection Detection:

text
alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - UNION SELECT"; content:"union"; nocase; content:"select"; nocase; sid:1000002; rev:1; classtype:web-application-attack; priority:1;)
SSH Brute Force Detection:

text
alert tcp any any -> $HOME_NET 22 (msg:"SSH Brute Force Attempt"; flags:S; threshold:type threshold, track by_src, count 5, seconds 60; sid:1000003; rev:1; classtype:attempted-recon;)
Port Scanning Detection:

text
alert tcp any any -> $HOME_NET 1:1024 (msg:"Port Scan Detected"; flags:S; detection_filter:track by_src, count 20, seconds 60; sid:1000004; rev:1; classtype:attempted-recon; priority:2;)
🎓 Practical Use Cases
Use Case 1: Network Traffic Monitoring and Analysis
Objective: Real-time visibility into network traffic

Commands:

bash
# Linux
sudo snort -v -i eth0                           # View traffic
sudo snort -dev -l /var/log/snort -i eth0     # Log traffic
sudo snort -r /var/log/snort/snort.log.*      # Analyze logs

# Windows
snort -v -i 1                                   # View traffic
snort -dev -l C:\Snort\log -i 1               # Log traffic
snort -r C:\Snort\log\capture.pcap            # Analyze logs
Business Value:

Real-time visibility into network activity

Forensic evidence for security incidents

Network troubleshooting and performance analysis

Use Case 2: Detecting SQL Injection Attacks
Objective: Protect web applications from SQL injection

Rules:

text
alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - UNION SELECT"; content:"union"; nocase; content:"select"; nocase; distance:0; sid:1000010; rev:1; classtype:web-application-attack; priority:1;)

alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - OR 1=1"; content:"or"; nocase; content:"1=1"; nocase; distance:0; sid:1000011; rev:1; classtype:web-application-attack; priority:1;)

alert tcp any any -> $HTTP_SERVERS $HTTP_PORTS (msg:"SQL Injection - DROP TABLE"; content:"drop"; nocase; content:"table"; nocase; distance:0; sid:1000012; rev:1; classtype:web-application-attack; priority:1;)
Business Value:

Protects web applications from database compromise

Detects automated SQL injection scanning tools

Prevents data breaches and exfiltration

Use Case 3: Detecting Port Scanning Activities
Objective: Identify reconnaissance activities like port scans

Rule:

text
alert tcp any any -> $HOME_NET any (msg:"Potential Port Scan Detected"; flags:S; detection_filter:track by_src, count 20, seconds 60; sid:1000020; rev:1; classtype:attempted-recon; priority:2;)
Testing:

bash
# From attacker machine
nmap -sS 192.168.1.100

# Snort will generate alerts
Business Value:

Early warning of potential attacks

Identifies reconnaissance phase of cyber attacks

Enables proactive response before actual exploit

🔧 Troubleshooting
Common Issues and Solutions
Issue	Solution
Configuration Test Fails	Check if rules file exists: ls /etc/snort/rules/ or dir C:\Snort\rules\
No Interface Specified Error	List interfaces: snort -W and use correct interface number
Permission Denied (Linux)	sudo chmod 644 /etc/snort/rules/*.rules
Permission Denied (Windows)	Run as Administrator or use: icacls C:\Snort\rules /grant:r "NT AUTHORITY\SYSTEM:(OI)(CI)F" /T
Cannot Write to Log Directory	Create and fix permissions: mkdir /var/log/snort then sudo chown snort:snort /var/log/snort
No Alerts Appearing	Check interface number with snort -W and ensure correct -i flag
Snort Cannot Read Rules File	Verify file path and permissions: ls -la /etc/snort/rules/
📋 Best Practices
Before Scanning
Get Authorization: Obtain written permission before monitoring any network

Specify Scope: Define targets and timeframe clearly

Document Procedures: Keep records of scanning methodology

During Monitoring
Use Appropriate Rules: Load only necessary rule files

Minimize False Positives: Tune rules for your environment

Keep Records: Save all alerts and logs: -l flag

After Monitoring
Verify Findings: Manually verify critical alerts

Maintain Confidentiality: Securely store monitoring results

Follow Up: Address identified threats and vulnerabilities

🤝 Contributing
Contributions are welcome! To contribute:

Fork the repository

Create your feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

📚 Additional Resources
Official Documentation
Snort Official Website

Snort Documentation

Snort Community Rules

Security References
OWASP Top 10

CIS Controls

NIST Cybersecurity Framework

Learning Resources
Snort Manual

Rule Writing Guide

Security Training Platforms (HackTheBox, TryHackMe, etc.)

⚖️ Legal and Ethical Guidelines
IMPORTANT:

⚠️ Unauthorized network monitoring is illegal in most jurisdictions.

Before using Snort:

✅ Always get written authorization from network owners

✅ Specify scope and timeframe in authorization

✅ Monitor only authorized networks

✅ Maintain confidentiality of monitoring results

✅ Follow local laws regarding network monitoring

📝 License
This project is provided for educational and commercial use. Snort itself is licensed under its own license (free for use and redistribution).

👨‍💻 Authors
Vaishnavi - 251091010011
MTech Cybersecurity Student
MIT

🎓 Acknowledgments
Martin Roesch for creating Snort

Cisco for maintaining and developing Snort

The Snort community for rules and contributions

All contributors and testers

📊 Statistics
Metric	Value
Created	November 2025
Version	1.0.0
Snort Compatibility	2.9.x and 3.x
Platforms	Linux, Windows, Unix, BSD
Use Cases	3+ documented
Example Rules	5+ included
Status	Production Ready

📞 Support
For issues, questions, or suggestions:

Check the Troubleshooting section

Review the official Snort Documentation

Open an issue in this repository

Contact the Snort community on mailing lists
