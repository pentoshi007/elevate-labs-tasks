# 🦈 Day 5: Network Traffic Analysis with Wireshark

> **Cybersecurity Virtual Internship - Elevate Labs**  
> **Date:** August 11, 2025  
> **Intern:** Aniket Pandey  
> **Task:** Capture and Analyze Network Traffic Using Wireshark

---

## 📋 Task Overview

**Objective:** Learn to capture, analyze, and interpret network traffic using Wireshark to understand network protocols, identify security patterns, and develop network forensics skills essential for cybersecurity analysis.

**Tools Used:**
- 🦈 **Wireshark** (Network Protocol Analyzer)
- 💻 **macOS Terminal** (Traffic generation)
- 🌐 **Network Utilities** (ping, nslookup, curl)
- 📊 **Protocol Analysis** (TCP/UDP/DNS/TLS inspection)

---

## 🖥️ Test Environment

### **System Specifications**
```
Device: MacBook Air (Apple Silicon M1)
OS: macOS Sequoia
Network Interface: Wi-Fi (en0)
Local IP: 10.102.139.x/21
Subnet Mask: 255.255.248.0
Gateway: 10.102.136.1
DNS Server: 10.94.2.111
```

### **Capture Configuration**
- **Interface:** Wi-Fi (active wireless adapter)
- **Capture Duration:** 1-2 minutes per session
- **Filter:** None (promiscuous mode for comprehensive analysis)
- **Output Format:** PCAPNG (Wireshark native format)

---

## 🚀 Implementation Process

### **1. Environment Setup**
```bash
# Install Wireshark via Homebrew
brew install --cask wireshark

# Launch Wireshark
open -a Wireshark

# Verify network interface
ifconfig en0
```

### **2. Traffic Generation**
I systematically generated various types of network traffic to capture diverse protocols:

```bash
# DNS Resolution Testing
nslookup google.com
nslookup facebook.com
nslookup github.com

# ICMP Testing
ping -c 5 google.com
ping -c 5 8.8.8.8
ping -c 3 cloudflare.com

# HTTP/HTTPS Testing
curl -I http://example.com
curl -I https://httpbin.org/get
curl -I https://www.google.com

# Additional web browsing for realistic traffic patterns
```

### **3. Capture Methodology**
- **Live Capture:** Real-time packet interception on Wi-Fi interface
- **Multiple Sessions:** Separate captures for different protocol analysis
- **Filtered Analysis:** Applied display filters for targeted investigation
- **Export Options:** Saved both raw PCAP and analyzed text formats

---

## 📊 Traffic Analysis Results

### **Capture Statistics**
| Metric | Value |
|--------|-------|
| **Total Packets** | 60-90 per session |
| **Capture Duration** | 1-2 minutes |
| **Unique Protocols** | 6 major protocols |
| **Active Connections** | 15+ concurrent flows |
| **Data Volume** | ~50KB per capture |

### **Protocol Distribution**
| Protocol | Packets | Percentage | Purpose |
|----------|---------|------------|---------|
| **TCP** | 45-60 | 65-70% | Web traffic, SSH |
| **UDP** | 15-25 | 20-25% | DNS, broadcasts |
| **TLS** | 30-40 | 40-45% | Encrypted web traffic |
| **DNS** | 8-12 | 10-15% | Name resolution |
| **NBNS** | 5-8 | 5-10% | NetBIOS broadcasts |
| **SSH** | 3-5 | 3-5% | Encrypted remote access |

---

## 🔍 Detailed Protocol Analysis

### **🌐 TCP Traffic Analysis**

#### **HTTPS Connections (Port 443)**
```
Primary Destinations:
├── 104.90.6.178 (Akamai CDN)
├── 104.104.66.98 (Content Delivery)
├── 125.21.240.240 (Web Services)
├── 172.64.41.4 (Cloudflare)
└── Various CDN endpoints
```

**Connection Patterns:**
- **Three-way Handshake:** SYN → SYN/ACK → ACK
- **TLS Negotiation:** Client Hello → Server Hello → Key Exchange
- **Data Transfer:** Encrypted Application Data
- **Connection Termination:** FIN/ACK sequences

#### **SSH Traffic (Port 22)**
```
Connection: 13.232.131.249 ↔ 10.102.139.8
Protocol: SSHv2
Encryption: Strong (encrypted payloads observed)
Status: Active session with bidirectional data flow
```

### **🔍 UDP Traffic Analysis**

#### **DNS Queries (Port 53)**
```
DNS Server: 10.94.2.111 (Internal)
Query Types: A records, AAAA records
Domains Resolved:
├── google.com
├── facebook.com
├── a1068.dscr.akamai.net
└── Various CDN hostnames
```

#### **Network Broadcasts**
```
Broadcast Address: 10.102.143.255
Services:
├── NBNS (NetBIOS Name Service)
├── Host Announcements
└── Service Discovery
```

### **🔒 TLS/SSL Analysis**

#### **Handshake Sequence**
1. **Client Hello:** Cipher suites, TLS version negotiation
2. **Server Hello:** Selected cipher, certificate exchange
3. **Key Exchange:** Encrypted key material
4. **Change Cipher Spec:** Encryption activation
5. **Application Data:** Encrypted payload transmission

#### **Security Observations**
- **TLS Versions:** TLSv1.2 and TLSv1.3 observed
- **Cipher Suites:** Modern encryption algorithms
- **Certificate Validation:** Proper certificate chains
- **Perfect Forward Secrecy:** Ephemeral key exchange

---

## 🎯 Key Network Conversations

### **Top Traffic Flows**
| Source | Destination | Protocol | Port | Volume | Purpose |
|--------|-------------|----------|------|--------|---------|
| 10.102.139.x | 104.90.6.178 | TCP | 443 | High | HTTPS (Akamai CDN) |
| 10.102.139.x | 104.104.66.98 | TCP | 443 | Medium | HTTPS (Web Services) |
| 10.102.139.8 | 13.232.131.249 | TCP | 22 | Low | SSH (Remote Access) |
| 10.102.139.x | 10.94.2.111 | UDP | 53 | Low | DNS Queries |
| 10.102.139.x | 10.102.143.255 | UDP | Various | Low | Network Broadcasts |

### **Notable Network Events**

#### **🔗 Connection Establishments**
- **Successful TCP Handshakes:** Clean three-way handshake completion
- **TLS Negotiations:** Proper certificate exchange and encryption setup
- **DNS Resolutions:** Successful name-to-IP address mappings

#### **⚠️ Anomalies Detected**
- **"TCP Previous segment not captured":** Indicates packet loss or late capture start
- **Incomplete Flows:** Some connections captured mid-stream
- **External SSH Session:** Active connection to 13.232.131.249 (requires verification)

---

## 🔧 Wireshark Analysis Techniques

### **Display Filters Used**
```bash
# Protocol-specific filtering
tcp                          # TCP traffic only
udp                          # UDP traffic only
dns                          # DNS queries and responses
tls                          # TLS/SSL encrypted traffic
ssh                          # SSH protocol traffic

# IP-based filtering
ip.addr == 10.102.139.x      # Local machine traffic
ip.src == 10.102.139.x       # Outbound traffic
ip.dst == 10.102.139.x       # Inbound traffic

# Port-based filtering
tcp.port == 443              # HTTPS traffic
tcp.port == 22               # SSH traffic
udp.port == 53               # DNS traffic

# Advanced filtering
tcp.flags.syn == 1           # TCP SYN packets
tls.handshake.type == 1      # TLS Client Hello
dns.qry.name contains "google" # DNS queries for Google
```

### **Analysis Workflow**
1. **Overview Analysis:** Statistics → Protocol Hierarchy
2. **Conversation Analysis:** Statistics → Conversations
3. **Protocol Inspection:** Detailed packet examination
4. **Flow Reconstruction:** Follow TCP/UDP streams
5. **Security Assessment:** Identify anomalies and threats

---

## 🛡️ Security Analysis

### **🟢 Positive Security Indicators**
- **Encryption Prevalence:** 90%+ of traffic encrypted (TLS/SSH)
- **Modern Protocols:** TLSv1.2/1.3 usage
- **Proper Handshakes:** Clean connection establishment
- **Certificate Validation:** No certificate errors observed
- **DNS Security:** Internal DNS server usage

### **🟡 Areas for Investigation**
- **External SSH Connection:** 13.232.131.249 requires verification
- **Packet Loss:** "Previous segment not captured" warnings
- **Broadcast Traffic:** Excessive NetBIOS announcements
- **Ephemeral Ports:** High port usage patterns

### **🔴 Potential Security Concerns**
- **Unverified SSH Session:** External connection needs authorization check
- **Network Reconnaissance:** Broadcast traffic could reveal network topology
- **Incomplete Captures:** Missing packets may hide malicious activity

---

## 📚 Learning Outcomes

This network traffic analysis provided comprehensive insights into:

- **Protocol Stack Understanding:** Deep dive into TCP/IP, UDP, DNS, TLS protocols
- **Network Forensics:** Packet-level analysis and flow reconstruction
- **Security Monitoring:** Identifying normal vs. suspicious traffic patterns
- **Encryption Analysis:** Understanding TLS handshakes and encrypted communications
- **Network Troubleshooting:** Diagnosing connection issues and packet loss
- **Traffic Characterization:** Distinguishing between different application protocols

The exercise demonstrated how network traffic analysis is fundamental to cybersecurity monitoring, incident response, and network security assessment.

---

## 🎓 Interview Questions & Answers

### Q1: What is Wireshark and how is it used in cybersecurity?
**Answer:** Wireshark is a free, open-source network protocol analyzer that captures and displays network traffic in real-time. In cybersecurity, it's used for: **Network Forensics** - analyzing packet captures to investigate security incidents and understand attack patterns; **Malware Analysis** - examining network communications of malicious software; **Intrusion Detection** - identifying suspicious network activity and attack signatures; **Protocol Analysis** - understanding how applications communicate and identifying protocol vulnerabilities; **Performance Troubleshooting** - diagnosing network issues that could impact security; **Compliance Monitoring** - ensuring network communications meet security policies. Wireshark provides deep packet inspection capabilities, allowing security analysts to examine every detail of network communications from Layer 2 to Layer 7.

### Q2: How do you analyze TCP three-way handshakes and what security information do they provide?
**Answer:** TCP three-way handshake analysis involves examining the SYN, SYN/ACK, ACK sequence: **Step 1 (SYN)** - client sends SYN packet with initial sequence number and TCP options; **Step 2 (SYN/ACK)** - server responds with SYN/ACK, acknowledging client's sequence number and providing its own; **Step 3 (ACK)** - client acknowledges server's sequence number, completing the handshake. **Security insights:** **Connection Legitimacy** - proper handshakes indicate legitimate connections vs. spoofed traffic; **Port Scanning Detection** - SYN packets without corresponding ACKs may indicate reconnaissance; **DDoS Identification** - excessive SYN packets without completion suggest SYN flood attacks; **Firewall Effectiveness** - blocked connections show as unreachable or reset responses; **Timing Analysis** - unusual delays may indicate network issues or man-in-the-middle attacks. Failed handshakes or abnormal patterns often indicate security issues or misconfigurations.

### Q3: What can TLS handshake analysis reveal about network security?
**Answer:** TLS handshake analysis provides critical security insights: **Encryption Strength** - cipher suites reveal encryption algorithms and key lengths used; **Protocol Versions** - identifies use of secure (TLS 1.2/1.3) vs. deprecated (SSL 3.0, TLS 1.0) protocols; **Certificate Validation** - shows certificate chains, validity periods, and potential trust issues; **Perfect Forward Secrecy** - ephemeral key exchange methods protect past communications; **Cipher Suite Negotiation** - reveals if weak or vulnerable ciphers are being used; **Certificate Transparency** - shows if certificates are properly logged and monitored. **Security red flags:** use of weak ciphers (RC4, DES), expired certificates, self-signed certificates in production, downgrade attacks forcing weaker protocols, or missing certificate validation. Modern TLS implementations should use AEAD ciphers, ECDHE key exchange, and strong hash functions (SHA-256 or better).

### Q4: How do you identify and analyze DNS traffic for security purposes?
**Answer:** DNS traffic analysis focuses on queries, responses, and patterns: **Query Analysis** - examine requested domains for malicious indicators like DGA (Domain Generation Algorithm) patterns, suspicious TLDs, or known bad domains; **Response Analysis** - check for DNS poisoning, unusual TTL values, or responses from unexpected servers; **Traffic Volume** - excessive DNS queries may indicate malware beaconing or data exfiltration; **Query Types** - unusual record types (TXT, NULL) might indicate DNS tunneling; **Timing Patterns** - regular intervals could suggest automated malware communication. **Security indicators:** **Malicious Domains** - queries to known C&C servers, phishing sites, or malware distribution points; **DNS Tunneling** - large TXT records or unusual query patterns used for data exfiltration; **Fast Flux** - rapidly changing IP addresses for the same domain; **DGA Detection** - algorithmically generated domain names with high entropy; **Cache Poisoning** - responses that don't match queries or come from unexpected sources.

### Q5: What are the key differences between analyzing encrypted vs. unencrypted traffic?
**Answer:** **Encrypted Traffic Analysis:** **Metadata Focus** - analyze connection patterns, timing, packet sizes, and flow characteristics rather than content; **Protocol Identification** - identify encryption protocols (TLS, SSH, VPN) and their versions; **Behavioral Analysis** - examine traffic patterns, connection frequency, and data volume patterns; **Certificate Analysis** - inspect TLS certificates for validity and trust chains; **Side-Channel Analysis** - timing attacks, traffic analysis, and pattern recognition. **Unencrypted Traffic Analysis:** **Content Inspection** - full payload analysis including credentials, commands, and data; **Protocol Parsing** - detailed application-layer protocol analysis; **Data Extraction** - ability to extract files, credentials, and sensitive information; **Attack Detection** - direct identification of malicious payloads and attack signatures. **Security Implications:** Encrypted traffic requires different analysis techniques focusing on behavioral patterns and metadata, while unencrypted traffic allows direct content inspection but is increasingly rare in modern networks due to widespread TLS adoption.

### Q6: How do you use Wireshark display filters effectively for security analysis?
**Answer:** Effective display filtering requires understanding both basic and advanced syntax: **Protocol Filters** - `tcp`, `udp`, `dns`, `tls`, `http` for protocol-specific analysis; **IP Filters** - `ip.addr == x.x.x.x`, `ip.src == x.x.x.x`, `ip.dst == x.x.x.x` for host-based filtering; **Port Filters** - `tcp.port == 80`, `udp.port == 53` for service-specific analysis; **Flag Filters** - `tcp.flags.syn == 1`, `tcp.flags.rst == 1` for connection state analysis; **Content Filters** - `frame contains "password"`, `dns.qry.name contains "malware"` for payload inspection. **Advanced Techniques:** **Logical Operators** - `and`, `or`, `not` for complex conditions; **Comparison Operators** - `==`, `!=`, `>`, `<` for value comparisons; **Regular Expressions** - `matches` operator for pattern matching; **Time Filters** - `frame.time >= "2025-08-11 10:00:00"` for temporal analysis. **Security-Specific Filters:** `tls.alert_message`, `tcp.analysis.flags`, `dns.flags.rcode != 0` for identifying anomalies and security events.

### Q7: What network anomalies should security analysts look for in packet captures?
**Answer:** Security analysts should monitor for various network anomalies: **Connection Anomalies** - failed handshakes, excessive connection attempts, unusual port usage, connections to suspicious IPs; **Protocol Anomalies** - malformed packets, protocol violations, unexpected protocol usage, version downgrade attempts; **Traffic Patterns** - unusual data volumes, regular beaconing intervals, data exfiltration patterns, DDoS traffic characteristics; **DNS Anomalies** - queries to suspicious domains, DNS tunneling indicators, cache poisoning attempts, excessive NXDOMAIN responses; **Encryption Anomalies** - weak cipher usage, certificate errors, TLS downgrade attacks, suspicious certificate authorities. **Behavioral Indicators:** **Data Exfiltration** - large outbound transfers, unusual upload patterns, data to unexpected destinations; **Lateral Movement** - internal network scanning, privilege escalation attempts, unusual internal connections; **Command and Control** - regular communication patterns, encrypted channels to external hosts, domain generation algorithms; **Reconnaissance** - port scanning, service enumeration, network mapping activities.

### Q8: How can packet capture analysis support incident response activities?
**Answer:** Packet capture analysis is crucial for incident response: **Timeline Reconstruction** - establish sequence of events, attack progression, and impact scope using timestamps and flow analysis; **Attack Vector Identification** - determine how attackers gained initial access, what vulnerabilities were exploited, and what tools were used; **Lateral Movement Tracking** - follow attacker movement through the network, identify compromised systems, and understand privilege escalation; **Data Exfiltration Assessment** - quantify what data was accessed or stolen, identify exfiltration methods and destinations; **Malware Analysis** - examine malware communications, command and control channels, and payload delivery mechanisms. **Evidence Collection:** **Forensic Integrity** - maintain chain of custody, create forensic images, and document analysis procedures; **Attribution** - identify attack signatures, tools, and techniques that may indicate specific threat actors; **Impact Assessment** - determine scope of compromise, affected systems, and business impact; **Remediation Support** - identify indicators of compromise (IOCs), create detection rules, and support containment efforts. Packet analysis provides the detailed technical evidence needed for legal proceedings and comprehensive incident understanding.

---

## 📁 Repository Structure
```
day-5-11-aug/
├── 📋 readme.md              # This comprehensive traffic analysis report
├── 📄 task 5.pdf             # Original task requirements
├── 📊 results.txt            # Detailed analysis results
├── 🦈 packet-capture.pcapng  # Raw network capture file
├── 🔍 tcp-filter.pcapng      # TCP-filtered capture
├── 🌐 udp-filter.pcapng      # UDP-filtered capture
└── 🔐 ssh-filter.pcapng      # SSH-filtered capture
```

---

## 🔧 **Command Reference**

### **Wireshark Installation & Setup**
```bash
# Install Wireshark via Homebrew
brew install --cask wireshark

# Launch Wireshark
open -a Wireshark

# Command-line capture (alternative)
sudo tcpdump -i en0 -w capture.pcap
```

### **Traffic Generation Commands**
```bash
# DNS Resolution Testing
nslookup google.com
dig @8.8.8.8 example.com

# Network Connectivity Testing
ping -c 5 google.com
traceroute google.com

# HTTP/HTTPS Testing
curl -I https://www.google.com
wget --spider https://github.com

# Network Interface Information
ifconfig en0
netstat -rn
```

### **Wireshark Display Filters**
```bash
# Protocol Filtering
tcp and port 443              # HTTPS traffic
udp and port 53               # DNS traffic
ssh                           # SSH protocol

# IP Address Filtering
ip.addr == 10.102.139.0/24    # Local subnet
not broadcast and not multicast # Unicast only

# Advanced Filtering
tcp.analysis.flags            # TCP anomalies
tls.handshake.type == 1       # TLS Client Hello
dns.flags.rcode != 0          # DNS errors
```

---

## 🔗 **Analysis Tools and Resources**
- **Wireshark Official:** https://www.wireshark.org/
- **Display Filter Reference:** https://www.wireshark.org/docs/dfref/
- **Protocol Documentation:** https://www.wireshark.org/docs/
- **Network Forensics Guide:** SANS Network Forensics resources

---

**Key Achievement:** Successfully captured and analyzed diverse network traffic, demonstrating proficiency in protocol analysis, security monitoring, and network forensics essential for cybersecurity operations.

---
*This analysis showcases practical network forensics skills critical for incident response, security monitoring, and threat hunting in modern cybersecurity environments.*