# ZTS_assignment
Intrusion Detection System Using Snort (NIDS)
Introduction
This project implements a Network Intrusion Detection System using Snort, a leading open-source tool developed by Cisco for real-time traffic analysis and intrusion detection. Snort captures network packets, analyzes protocol behavior, and generates alerts based on user-defined rules.

Features
Real-time packet capture and analysis

Signature-based detection of attacks (port scan, SQL injection, DoS, etc.)

Operates in sniffer, packet logger, and NIDS modes

Cross-platform supported (Linux and Windows)

Flexible, customizable configuration and rule sets

Installation & Setup
Linux Installation (Ubuntu/Debian)
bash
sudo apt update && sudo apt upgrade -y
sudo apt install snort -y
# Configure network interface and HOME_NET during installation prompts
Windows Installation
Download Snort installer from Snort Downloads

Install Npcap from npcap.com (WinPcap compatible mode)

Install Visual C++ Redistributable 2015-2019

Run Snort installer as Administrator

Configure snort.conf file in C:\Snort\etc

Verify installation with:

bash
snort -V
Test configuration with:

bash
snort -T -c C:\Snort\etc\snort.conf
Usage Modes
Sniffer Mode (Live packet capture)
bash
snort -v -i <interface_number>
Packet Logger Mode (Log captured traffic)
bash
snort -dev -l <log_directory> -i <interface_number>
Network Intrusion Detection System (NIDS) Mode
bash
snort -A console -q -c <path_to_snort.conf> -i <interface_number>
Configuration Overview
Main config file: snort.conf (Linux: /etc/snort/snort.conf; Windows: C:\Snort\etc\snort.conf)

Key variables: HOME_NET, EXTERNAL_NET, ports

Preprocessors for protocol normalization and anomaly detection

Output methods: alert_fast (console), alert_full (files), unified2 (binary), syslog

Rules: community rules and custom local rules (local.rules)

Use Case 1: Live Network Monitoring and Packet Capture
Objective
Monitor live network traffic on a specific interface to analyze packet details in real time.

Commands & Output
Step 1: Start verbose packet capture

bash
snort -v -i 5
Output: Displays all packet headers and details such as source/destination IPs, ports, protocols in real-time on console.

Step 2: Capture and log packets with full headers and payload

bash
snort -dev -l C:\Snort\log -i 5
Output: Logs all packets into binary log files in the specified log directory for offline analysis.

Step 3: Read and Analyze Captured Logs Offline

bash
snort -r C:\Snort\log\snort.log.TIMESTAMP
Output: Displays detailed packet information from saved logs in human-readable format.

Screenshots
Live Packet Capture (Step 1)
![Step 1: Live Packet Capture Output](./images/snort_live_capture Traffic to Disk (Step 2)
![Step 2: Packet Logging Output](./images/snort_packet_logging Log Analysis (Step 3)
![Step 3: Offline Log Analysis Output](./images/snort_offline_analysishooting

Always run Snort with administrator/root privileges.

Verify correct interface with ip a (Linux) or netsh interface show interface (Windows).

Test configuration with snort -T -c <config_file>.

Check paths for rule files and log directories.

Update rule sets regularly for latest threat detection.

Best Practices
Deploy Snort at network perimeter or SPAN ports.

Regularly update Snort and rules to maintain protection.

Use alert prioritization to manage noise.

Integrate alerts with SIEMs for centralized analysis.

Monitor performance metrics and tune preprocessors.
