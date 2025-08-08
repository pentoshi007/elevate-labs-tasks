# 🔥 Day 4: Firewall Configuration & Traffic Filtering

> **Cybersecurity Virtual Internship - Elevate Labs**  
> **Date:** August 8, 2025  
> **Intern:** Aniket Pandey  
> **Task:** Configure Host-Based Firewalls on Linux and Windows

---

## 📋 Task Overview

**Objective:** Learn to configure and manage host-based firewalls on both Linux and Windows systems, implement traffic filtering rules, and understand the principles of network access control and defense in depth.

**Tools Used:**
- 🐧 **UFW (Uncomplicated Firewall)** - Linux firewall management
- 🪟 **Windows Defender Firewall** - Windows Advanced Security
- 🖥️ **Parallels Desktop** - Virtual machine environment
- 🔧 **Network Testing Tools** - netcat, telnet, SSH

---

## 🖥️ Test Environment

### **Virtual Machine Setup**
```
Host System: MacBook Air M1
Hypervisor: Parallels Desktop
VM 1: Parrot OS (Linux) - UFW Configuration
VM 2: Windows 11 - Windows Defender Firewall
Network: Bridged networking (10.x.x.x subnet)
```

### **Target Services**
- **Port 22/TCP:** SSH (Secure Shell) - Allow
- **Port 23/TCP:** Telnet - Block (Security Risk)

---

## 🚀 Implementation Process

### **Phase 1: Environment Preparation**
I set up isolated virtual machines to safely practice firewall configuration without affecting production systems or network infrastructure.

### **Phase 2: Linux Firewall Configuration (UFW)**
Implemented comprehensive firewall rules using Ubuntu's Uncomplicated Firewall on Parrot OS.

### **Phase 3: Windows Firewall Configuration**
Configured Windows Defender Firewall with Advanced Security for granular traffic control.

### **Phase 4: Testing and Validation**
Documented expected behavior and validated firewall rule effectiveness.

---

## 🐧 Linux Firewall Configuration (UFW)

### **1. System Preparation**
```bash
# Update package repositories
sudo apt update

# Install required packages
sudo apt install -y ufw netcat-openbsd iproute2 inetutils-telnet openssh-server

# Enable SSH service for testing
sudo systemctl enable --now ssh
```

### **2. Initial Firewall Setup**
```bash
# Configure default policies
sudo ufw default deny incoming    # Block all inbound traffic by default
sudo ufw default allow outgoing   # Allow all outbound traffic
sudo ufw default disabled routed  # Disable routing (host firewall only)

# Enable UFW
sudo ufw enable

# Capture initial status
sudo ufw status verbose > ufw_status_initial.txt
```

### **3. Rule Implementation**
```bash
# Block Telnet (insecure protocol)
sudo ufw deny in 23/tcp

# Allow SSH (secure remote access)
sudo ufw allow 22/tcp

# Document configured rules
sudo ufw status numbered verbose > ufw_rules_after.txt
```

### **4. Rule Management and Cleanup**
```bash
# List numbered rules for management
sudo ufw status numbered

# Remove specific rule (Telnet block for demonstration)
sudo ufw delete [RULE_NUMBER]

# Final status documentation
sudo ufw status numbered verbose > ufw_final_status.txt
```

---

## 📊 Linux Firewall Analysis

### **Initial Configuration**
```
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip
```

### **Rules After Configuration**
| Rule | Port/Protocol | Action | Direction | Source |
|------|---------------|--------|-----------|---------|
| 1 | 23/tcp | DENY | IN | Anywhere |
| 2 | 22/tcp | ALLOW | IN | Anywhere |
| 3 | 23/tcp (v6) | DENY | IN | Anywhere (v6) |
| 4 | 22/tcp (v6) | ALLOW | IN | Anywhere (v6) |

### **Final Configuration (After Cleanup)**
| Rule | Port/Protocol | Action | Direction | Source |
|------|---------------|--------|-----------|---------|
| 1 | 22/tcp | ALLOW | IN | Anywhere |
| 2 | 23/tcp (v6) | DENY | IN | Anywhere (v6) |
| 3 | 22/tcp (v6) | ALLOW | IN | Anywhere (v6) |

---

## 🪟 Windows Firewall Configuration

### **1. Access Windows Defender Firewall**
- **Path:** Control Panel → System and Security → Windows Defender Firewall → Advanced Settings
- **Alternative:** Run `wf.msc` from Windows Run dialog

### **2. Inbound Rule Creation**

#### **Block Telnet (Port 23)**
```
Rule Type: Port
Protocol: TCP
Specific Local Ports: 23
Action: Block the connection
Profile: Domain, Private, Public
Name: Block Telnet 23
Description: Block insecure Telnet protocol
```

#### **Allow SSH (Port 22)**
```
Rule Type: Port
Protocol: TCP
Specific Local Ports: 22
Action: Allow the connection
Profile: Domain, Private, Public
Name: Allow SSH 22
Description: Allow secure SSH connections
```

### **3. Rule Validation**
- Verified rules appear in Inbound Rules list
- Confirmed proper action assignment (Block/Allow)
- Validated profile application (Domain/Private/Public)

---

## 🔍 Security Analysis

### **Protocol Security Comparison**

| Protocol | Port | Encryption | Authentication | Security Risk |
|----------|------|------------|----------------|---------------|
| **Telnet** | 23/TCP | ❌ None | ❌ Cleartext | 🔴 **Critical** |
| **SSH** | 22/TCP | ✅ Strong | ✅ Key-based | 🟢 **Low** |

### **Risk Assessment**

#### **🔴 Telnet Security Risks**
- **Cleartext Transmission:** All data including passwords sent unencrypted
- **Credential Interception:** Network sniffing can capture login credentials
- **Session Hijacking:** Unencrypted sessions vulnerable to man-in-the-middle attacks
- **No Integrity Protection:** Data can be modified in transit without detection

#### **🟢 SSH Security Benefits**
- **Strong Encryption:** AES, ChaCha20 encryption for all communications
- **Public Key Authentication:** Cryptographic key pairs eliminate password risks
- **Session Integrity:** HMAC ensures data hasn't been tampered with
- **Forward Secrecy:** Session keys protect past communications if compromised

---

## 🧪 Testing Methodology

### **Expected Test Results**

#### **Telnet Connection Test**
```bash
# Test command
telnet <TARGET_IP> 23

# Expected result: Connection refused/timeout
# Reason: UFW deny rule blocks TCP/23 inbound
```

#### **SSH Connection Test**
```bash
# Test command
ssh user@<TARGET_IP>

# Expected result: Connection successful
# Reason: UFW allow rule permits TCP/22 inbound
```

### **Validation Approach**
1. **Rule Verification:** Confirm rules appear in firewall configuration
2. **Service Testing:** Attempt connections to blocked and allowed ports
3. **Log Analysis:** Review firewall logs for blocked connection attempts
4. **Network Scanning:** Use nmap to verify port accessibility

---

## 📚 Learning Outcomes

This firewall configuration exercise provided comprehensive insights into:

- **Defense in Depth:** Implementing multiple security layers
- **Principle of Least Privilege:** Denying by default, allowing only necessary services
- **Protocol Security:** Understanding encryption and authentication differences
- **Rule Management:** Creating, modifying, and removing firewall rules
- **Cross-Platform Security:** Comparing Linux and Windows firewall approaches
- **Network Security Fundamentals:** Understanding inbound/outbound traffic control

The exercise demonstrated how proper firewall configuration significantly reduces attack surface and prevents unauthorized network access.

---

## 🎓 Interview Questions & Answers

### Q1: What is a firewall and how does it enhance network security?
**Answer:** A firewall is a network security control system that monitors and filters incoming and outgoing network traffic based on predetermined security rules. It acts as a barrier between trusted internal networks and untrusted external networks (like the Internet). **Security enhancements:** **Access Control** - enforces allow/deny policies for specific ports, protocols, and IP addresses; **Attack Surface Reduction** - blocks unnecessary services and ports from external access; **Traffic Monitoring** - logs connection attempts for security analysis; **Malware Prevention** - blocks known malicious IP addresses and suspicious traffic patterns; **Compliance** - helps meet regulatory requirements for network security controls. Firewalls implement the principle of least privilege by denying all traffic by default and only allowing explicitly permitted communications.

### Q2: What's the difference between stateful and stateless firewalls?
**Answer:** **Stateless Firewalls** examine each packet independently without considering connection context. They make decisions based solely on packet headers (source/destination IP, ports, protocol) against static rules. They're fast but limited because they can't track connection states or related traffic. **Stateful Firewalls** maintain connection state tables tracking active sessions. They understand TCP connection states (SYN, ACK, FIN), allow return traffic for established connections, and can make context-aware decisions. **Key differences:** **Performance** - stateless is faster per packet, stateful provides better security; **Memory Usage** - stateless uses minimal memory, stateful maintains state tables; **Security** - stateless vulnerable to connection-based attacks, stateful provides better protection; **Complexity** - stateless has simple rule sets, stateful requires more sophisticated configuration. Modern firewalls are predominantly stateful for enhanced security.

### Q3: Explain the difference between inbound and outbound firewall rules.
**Answer:** **Inbound Rules** govern traffic entering a system or network from external sources. They control what external connections can reach internal services and are critical for preventing unauthorized access. Examples include allowing HTTP/HTTPS (ports 80/443) for web servers, blocking Telnet (port 23) for security, permitting SSH (port 22) for administration. **Outbound Rules** control traffic leaving the system toward external destinations. They can prevent data exfiltration, block malware communication, and restrict user access to specific services. Examples include allowing DNS queries (port 53), blocking P2P protocols, restricting access to social media sites. **Security implications:** Inbound rules are primary defense against external attacks, while outbound rules prevent internal threats from communicating externally and can contain malware infections. Both are essential for comprehensive network security.

### Q4: How does UFW simplify Linux firewall management compared to iptables?
**Answer:** UFW (Uncomplicated Firewall) provides a user-friendly interface to the complex iptables/nftables framework. **Simplifications:** **Syntax** - uses plain English commands like `ufw allow 22/tcp` instead of complex iptables syntax; **Rule Management** - provides numbered rules for easy deletion and modification; **Default Policies** - simple commands to set default allow/deny behaviors; **Logging** - built-in logging configuration without complex iptables LOG targets; **IPv6 Support** - automatically handles both IPv4 and IPv6 rules; **Application Profiles** - predefined profiles for common services; **Status Display** - clear, readable rule listings with `ufw status verbose`. **Under the hood:** UFW translates simple commands into proper iptables rules, maintains rule persistence across reboots, and provides consistent behavior. This makes firewall management accessible to users without deep iptables knowledge while maintaining the power and flexibility of the underlying netfilter framework.

### Q5: Why should Telnet be blocked and SSH used instead?
**Answer:** **Telnet Security Vulnerabilities:** **No Encryption** - all data including passwords transmitted in cleartext; **Credential Exposure** - network sniffing can capture login credentials; **Session Hijacking** - unencrypted sessions vulnerable to man-in-the-middle attacks; **No Integrity Protection** - data can be modified in transit; **No Authentication Verification** - susceptible to spoofing attacks. **SSH Security Advantages:** **Strong Encryption** - uses AES, ChaCha20, and other modern ciphers; **Public Key Authentication** - eliminates password-based vulnerabilities; **Session Integrity** - HMAC ensures data hasn't been tampered with; **Forward Secrecy** - compromised keys don't affect past sessions; **Tunneling Capabilities** - can securely forward other protocols. **Industry Standards:** SSH is required by security frameworks (PCI DSS, NIST), while Telnet is explicitly prohibited in secure environments. Modern systems should disable Telnet entirely and use SSH for all remote administration needs.

### Q6: What are common firewall configuration mistakes?
**Answer:** **Common Mistakes:** **Overly Permissive Rules** - using "any-any" rules that allow all traffic; **Wrong Default Policy** - allowing inbound by default instead of denying; **Self-Lockout** - blocking SSH access without console access available; **Rule Ordering Issues** - placing specific rules after general ones that override them; **Missing IPv6 Rules** - configuring only IPv4 while leaving IPv6 open; **Inadequate Logging** - not enabling logging for security monitoring; **Unused Rule Accumulation** - keeping old rules that create security gaps; **Testing in Production** - making changes without testing in safe environments; **No Documentation** - failing to document rule purposes and business justification; **Ignoring Application Dependencies** - blocking ports needed for legitimate applications. **Prevention:** Use configuration management tools, implement change control processes, maintain rule documentation, regularly audit and clean up rules, test changes in lab environments, and implement monitoring for blocked connections.

### Q7: How does a firewall improve overall network security posture?
**Answer:** Firewalls enhance security through multiple mechanisms: **Perimeter Defense** - creates security boundary between trusted and untrusted networks; **Access Control** - enforces least privilege by allowing only necessary communications; **Attack Surface Reduction** - hides internal services from external reconnaissance; **Traffic Monitoring** - provides visibility into network communications and attack attempts; **Malware Containment** - prevents infected systems from communicating with command and control servers; **Compliance Support** - helps meet regulatory requirements for network security; **Incident Response** - logs provide forensic evidence for security investigations; **Network Segmentation** - enables micro-segmentation for zero-trust architectures. **Defense in Depth:** Firewalls work with other security controls (IDS/IPS, antivirus, endpoint protection) to create layered security. They're particularly effective against network-based attacks, unauthorized access attempts, and lateral movement within networks.

### Q8: What is NAT and how does it relate to firewall functionality?
**Answer:** NAT (Network Address Translation) maps private internal IP addresses to public external addresses, enabling multiple devices to share a single public IP. **NAT Types:** **Static NAT** - one-to-one mapping between private and public IPs; **Dynamic NAT** - pool of public IPs assigned dynamically; **PAT (Port Address Translation)** - many-to-one mapping using different ports. **Firewall Integration:** Many firewalls include NAT functionality, creating **stateful NAT** that tracks connections and automatically allows return traffic. **Security Benefits:** **IP Hiding** - obscures internal network topology from external attackers; **Implicit Filtering** - unsolicited inbound connections are dropped by default; **Connection Tracking** - maintains state tables for legitimate outbound connections. **Limitations:** NAT can complicate some protocols (FTP, SIP), may break end-to-end connectivity principles, and doesn't provide true security (should be combined with proper firewall rules). Modern IPv6 networks reduce NAT dependency but firewalls remain essential for security policy enforcement.

---

## 📁 Repository Structure
```
day-4-08-aug/
├── 📋 readme.md              # This comprehensive firewall analysis
├── 📄 task 4-3.pdf           # Original task requirements
├── 🐧 linux/                 # Linux UFW configuration
│   ├── ufw_status_initial.txt    # Initial firewall state
│   ├── ufw_rules_after.txt       # Rules after configuration
│   ├── ufw_final_status.txt      # Final state after cleanup
│   ├── test_telnet.txt           # Telnet test documentation
│   ├── test_ssh.txt              # SSH test documentation
│   └── packages.list             # Installed packages
└── 🪟 windows/               # Windows firewall configuration
    ├── Screenshot 2025-08-08 at 7.10.49 PM.png  # Rule creation
    └── Screenshot 2025-08-08 at 7.12.02 PM.png  # Final configuration
```

---

## 🔧 **Command Reference**

### **Linux UFW Commands**
```bash
# Basic UFW operations
sudo ufw enable                    # Enable firewall
sudo ufw disable                   # Disable firewall
sudo ufw status verbose            # Show detailed status
sudo ufw status numbered           # Show numbered rules

# Rule management
sudo ufw allow 22/tcp              # Allow SSH
sudo ufw deny 23/tcp               # Block Telnet
sudo ufw delete [number]           # Delete rule by number

# Default policies
sudo ufw default deny incoming     # Block inbound by default
sudo ufw default allow outgoing    # Allow outbound by default
```

### **Windows Firewall Commands**
```cmd
# Command line alternatives
netsh advfirewall firewall add rule name="Block Telnet" dir=in action=block protocol=TCP localport=23
netsh advfirewall firewall add rule name="Allow SSH" dir=in action=allow protocol=TCP localport=22
netsh advfirewall firewall show rule name=all
```

---

**Key Achievement:** Successfully configured host-based firewalls on both Linux and Windows platforms, implementing security best practices including default-deny policies, service-specific rules, and proper protocol security measures.

---
*This exercise demonstrates practical firewall management skills essential for implementing defense-in-depth security strategies and maintaining secure network communications.*