# Cybersecurity Firewall Project

A comprehensive firewall implementation in Python that includes multiple types of protection against various network attacks.

## Components

### 1. DoS Firewall
Located in `/DoS Firewall/`
- `main.py`: Main DoS protection implementation that monitors traffic rates and blocks IPs exceeding thresholds
- `02_dos_blocker_tester.py`: Testing script to simulate DoS attacks by sending packets to a target IP

**How it works:**
- Monitors incoming network traffic in real-time
- Tracks packet rates from each source IP
- If an IP exceeds the threshold (20 packets/second), it's automatically blocked
- Uses `iptables` to implement blocking rules
- Includes a tester script to simulate DoS attacks for testing purposes

### 2. Mini Firewall 
Located in `/Mini Firewall/`
- Basic packet filtering with whitelist/blacklist functionality
- Configurable thresholds for traffic monitoring (default: 40 packets/sec)
- Nimda worm detection
- Comprehensive logging system

**How it works:**
- Maintains whitelist and blacklist of IP addresses
- Monitors packet rates and blocks IPs exceeding thresholds
- Includes specific detection for Nimda worm signatures
- Logs all security events with timestamps
- Requires administrative privileges for packet capture
- Uses Scapy for packet analysis and manipulation

### 3. Application Layer Firewall
Located in `/firewalls/app_firewall.py`
- Protection against common web attacks:
  - XSS (Cross-Site Scripting)
  - SQL Injection
  - Header injection
- Request sanitization
- Security violation logging

**How it works:**
- Uses regex patterns to detect common attack signatures
- Sanitizes input parameters and headers
- Inspects HTTP requests for malicious content
- Maintains detailed logs of security violations
- Provides content sanitization for output

### 3.5 Packet Firewall
Located in `/firewalls/packet_firewall.py`
- Low-level packet analysis
- TCP/IP header inspection
- Malicious signature detection
- Configurable filtering rules

**How it works:**
- Analyzes packet headers at TCP/IP level
- Checks packets against predefined malicious signatures
- Implements configurable filtering rules from JSON
- Maintains statistics per IP address
- Logs all violations with detailed information

## Features

- DoS/DDoS attack prevention through rate limiting
- IP blacklisting/whitelisting
- Real-time traffic monitoring
- Application layer security
- Packet-level filtering
- Detailed logging of security events
- Administrative privileges verification

## Requirements

- Python 3.12
- Scapy library for packet manipulation
- Administrative/root privileges for packet capture

## Installation

Install required dependencies:
```bash
pip install scapy
```

### Configuration Files
- `whitelist.txt`: List of allowed IP addresses
- `blacklist.txt`: List of blocked IP addresses
- Configurable thresholds in respective modules

## Security Notes

- Must be run with root/admin privileges
- Customize IP addresses and interfaces for your network
- Regularly update blacklists and security rules
- Monitor log files for suspicious activity
- Test in a controlled environment before production use

## Project Structure

```
Cybersecurity-Firewall/
├── DoS Firewall/
│   ├── main.py
│   └── 02_dos_blocker_tester.py
├── Mini Firewall/
│   ├── Mini Firewall.py
│   ├── whitelist.txt
│   └── blacklist.txt
├── firewalls/
│   ├── app_firewall.py
│   └── packet_firewall.py
└── README.md
```

## Disclaimer

This firewall is for educational purposes.
```
Feel free to modify any sections to better match your specific implementation or add additional details as needed.
