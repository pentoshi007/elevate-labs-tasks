# 🔍 Day 1: Network Port Scanning

> **Cybersecurity Virtual Internship - Elevate Labs**  
> **Date:** August 4, 2025  
> **Intern:** Aniket Pandey  
> **Task:** Scan Local Network for Open Ports

---

## 📋 Task Overview

**Objective:** Learn to discover open ports on devices in the local network to understand network exposure and security posture.

**Tools Used:**
- 🛠️ **Nmap** (Network Mapper)
- 💻 **macOS Terminal** (MacBook M1 Air)
- 📱 **Android Hotspot** (for controlled network environment)

---

## 🚀 Implementation Process

### 1. Environment Setup
I started by setting up the necessary tools and environment on my MacBook M1 Air:

```bash
# Installed Nmap via Homebrew (official macOS package manager)
brew install nmap

# Verified installation
nmap --version
```

### 2. Network Discovery Challenge
Initially, I attempted to scan my original network range (10.102.136.0/21) but encountered several technical challenges:

**Issues Faced:**
- `dnet: Failed to open device en0` errors
- `No route to host` connectivity problems
- Network routing restrictions

**Troubleshooting Steps:**
- Added `--disable-arp-ping` flag
- Used `-Pn` for host discovery bypass
- Narrowed scan ranges for testing
- Applied various timing and detection flags

### 3. Solution Implementation
To overcome the network limitations, I created a controlled testing environment:

1. **Connected Android phone to Wi-Fi**
2. **Enabled mobile hotspot**
3. **Connected MacBook to the hotspot**
4. **Created isolated network:** `10.129.166.0/24`

### 4. Network Reconnaissance
```bash
# Discovered local IP configuration
ifconfig

# Executed comprehensive TCP SYN scan
sudo nmap -sS -sV --disable-arp-ping --reason -oN advanced_scan.txt -T4 -oX scan_results.xml 10.129.166.0/24 -v
```

---

## 📊 Scan Results

### Network Summary
- **Scanned Range:** 10.129.166.0/24 (256 addresses)
- **Hosts Discovered:** 2 active devices
- **Scan Type:** TCP SYN Stealth Scan
- **Service Detection:** Enabled

### 🎯 Discovered Hosts

#### Host 1: 10.129.166.172 (Network Infrastructure)
```
Port: 53/tcp (OPEN)
Service: DNS (Domain Name System)
Version: dnsmasq 2.51
MAC Address: 00:00:40:01:8D:17
```

#### Host 2: 10.129.166.7 (Local Machine)
```
Port: 5000/tcp (OPEN)
Service: RTSP (Real Time Streaming Protocol)
Details: AirTunes-like service (403 Forbidden response)

Port: 7000/tcp (OPEN)  
Service: RTSP (Real Time Streaming Protocol)
Details: AirTunes-like service (403 Forbidden response)
```

---

## 🔬 Technical Analysis

### Service Research

#### 🌐 Port 53 - DNS Service (dnsmasq 2.51)
- **Function:** Provides DNS resolution for the local network
- **Common Usage:** Router/hotspot DNS caching and local name resolution
- **Implementation:** Lightweight DNS forwarder typical in embedded systems

#### 📺 Ports 5000/7000 - RTSP/AirTunes Services
- **Function:** Media streaming protocol services
- **Platform:** macOS native media sharing capabilities
- **Access Control:** HTTP 403 Forbidden responses indicate proper access restrictions
- **Legacy Protocol:** AirTunes (predecessor to AirPlay)

---

## ⚠️ Security Risk Assessment

### 🔴 High Priority Risks

#### DNS Service (Port 53)
- **DNS Amplification Attacks:** Potential for DDoS amplification if exposed to internet
- **Cache Poisoning:** Risk of malicious DNS response injection
- **Information Disclosure:** DNS queries can reveal network topology
- **Unauthorized Queries:** Possible reconnaissance vector

#### RTSP Services (Ports 5000/7000)
- **Buffer Overflow Vulnerabilities:** Historical RTSP exploits (e.g., CVE-2018-4013)
- **Unauthorized Media Access:** Potential streaming hijacking
- **Legacy Protocol Risks:** AirTunes vulnerabilities (e.g., CVE-2020-9839)
- **Local Network Exposure:** Services accessible to network devices

### 🛡️ Mitigation Recommendations

1. **Firewall Configuration:** Restrict unnecessary port access
2. **Service Updates:** Ensure latest security patches
3. **Network Segmentation:** Isolate critical services
4. **Access Control:** Implement strong authentication
5. **Monitoring:** Deploy intrusion detection systems

---

## 📚 Learning Outcomes

This exercise provided valuable insights into:

- **Network reconnaissance techniques** using industry-standard tools
- **TCP SYN scanning methodology** for stealth port discovery  
- **Service fingerprinting** and version detection capabilities
- **Security assessment** of discovered network services
- **Problem-solving skills** when facing technical challenges
- **Network architecture** impact on scanning effectiveness

The experience demonstrated how network configuration significantly affects scanning results and the importance of controlled testing environments.

---

## 🎓 Interview Questions & Answers

### Q1: What is an open port and why is it significant in cybersecurity?
**Answer:** An open port is a network endpoint on a device that actively listens for incoming connections, allowing specific services to communicate with external systems. In cybersecurity, open ports represent potential attack vectors - they're like doors into a system. Each open port runs a service that could have vulnerabilities, making them critical points for security assessment. For example, port 80 typically runs web services, while port 22 runs SSH for remote access.

### Q2: How does Nmap perform a TCP SYN scan and why is it considered "stealth"?
**Answer:** A TCP SYN scan works by sending SYN packets (the first step of a TCP handshake) to target ports. If the port is open, the target responds with a SYN-ACK packet. Instead of completing the handshake with an ACK, Nmap immediately sends a RST packet to terminate the connection. This is considered "stealth" because it never establishes a full connection, making it less likely to be logged by basic intrusion detection systems and reducing the scan's footprint on target systems.

### Q3: What security risks are associated with open ports?
**Answer:** Open ports present several security risks: **Unauthorized Access** - attackers can exploit weak authentication or default credentials; **Service Vulnerabilities** - unpatched software may have known exploits; **Information Disclosure** - services might leak sensitive system information; **Denial of Service** - ports can be targeted for resource exhaustion attacks; **Lateral Movement** - compromised services can provide footholds for network traversal; **Data Exfiltration** - open ports might allow unauthorized data transmission.

### Q4: Explain the difference between TCP and UDP scanning techniques.
**Answer:** **TCP Scanning** uses connection-oriented protocols with established handshakes (SYN, SYN-ACK, ACK). Methods include SYN scans, Connect scans, and FIN scans. TCP scans are generally faster and more reliable because they receive clear responses. **UDP Scanning** deals with connectionless protocols - it sends UDP probes and waits for responses or ICMP error messages. UDP scanning is inherently slower and less reliable because UDP doesn't guarantee responses, making it harder to distinguish between open, closed, and filtered ports.

### Q5: How can open ports be secured effectively?
**Answer:** Port security involves multiple layers: **Firewall Rules** - block unnecessary ports and restrict access by IP/network; **Service Hardening** - disable unused services, change default configurations, and use strong authentication; **Regular Updates** - apply security patches promptly; **Port Obfuscation** - run services on non-standard ports when appropriate; **Access Control** - implement role-based permissions and multi-factor authentication; **Monitoring** - deploy intrusion detection systems and log analysis; **Network Segmentation** - isolate critical services in separate network zones.

### Q6: What role does a firewall play in port security?
**Answer:** A firewall acts as a network security gatekeeper that filters traffic based on predetermined rules. For port security, firewalls: **Control Access** - allow or deny connections to specific ports based on source IP, destination, and protocols; **Hide Services** - make ports appear closed or filtered to external scanners; **Log Activity** - record connection attempts for security analysis; **Rate Limiting** - prevent abuse by limiting connection rates; **Deep Packet Inspection** - analyze packet contents for malicious patterns; **Network Segmentation** - create security zones with different access policies.

### Q7: What is port scanning and why do attackers use it?
**Answer:** Port scanning is a reconnaissance technique that probes network hosts to discover open ports and running services. Attackers use port scanning for: **Network Mapping** - understanding network topology and active hosts; **Service Discovery** - identifying potential attack targets and their software versions; **Vulnerability Assessment** - finding services with known security flaws; **Attack Planning** - determining the best entry points and attack vectors; **Stealth Reconnaissance** - gathering intelligence without triggering obvious alarms. It's essentially the digital equivalent of checking which doors and windows are unlocked in a building.

### Q8: How does Wireshark complement port scanning activities?
**Answer:** Wireshark provides deep packet-level analysis that complements Nmap's high-level summaries: **Traffic Analysis** - captures and displays actual network packets during scans; **Protocol Inspection** - reveals detailed communication patterns and service behaviors; **Anomaly Detection** - identifies unusual responses or hidden services; **Forensic Evidence** - provides detailed logs for security incident analysis; **Performance Monitoring** - shows network latency and response times; **Security Validation** - verifies that security controls are working as expected. While Nmap tells you "what" is open, Wireshark shows you "how" the communication actually works.

---

## 📁 Repository Structure
```
day-1-04-aug/
├── 📄 task 1.pdf          # Original task requirements
├── 📝 result.txt          # Raw scan results and analysis
├── 📋 readme.md           # This comprehensive report
├── 🔍 advanced_scan.txt   # Detailed Nmap output

```



---
*This report demonstrates practical application of network reconnaissance skills while maintaining ethical cybersecurity practices in a controlled environment.*