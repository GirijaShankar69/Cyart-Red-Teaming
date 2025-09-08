# Complete Red Team Cybersecurity Learning Guide
*A Step-by-Step Framework for Students*

## Overview
This comprehensive guide provides a structured approach to learning red team cybersecurity methodologies, from theoretical foundations to practical implementation. Follow each section sequentially to build expertise in offensive security techniques.

---

## Phase 1: Theoretical Knowledge Foundation

### Step 1: Advanced Reconnaissance and OSINT

**Core Concepts to Master:**

**1.1 Passive Reconnaissance**
- **What it is:** Gathering intelligence without direct interaction with target systems
- **Key techniques:** DNS enumeration, WHOIS lookups, metadata extraction
- **Example:** Use Shodan to identify exposed IoT devices
- **MITRE ATT&CK:** T1595.002 (Active Scanning)

**1.2 Active Reconnaissance** 
- **What it is:** Scanning ports and enumerating services stealthily
- **Key techniques:** Port scanning, service fingerprinting, OS detection
- **Example:** Use Nmap scripts to fingerprint operating systems
- **MITRE ATT&CK:** T1046 (Network Service Scanning)

**1.3 OSINT Frameworks**
- **Primary tools:** Maltego, Recon-ng for automated workflows
- **Use case:** Map LinkedIn profiles to email patterns for phishing campaigns
- **MITRE ATT&CK:** T1593 (Search Open Websites/Domains)

**Learning Tasks:**
1. Query Shodan with `port:80 country:US` to find vulnerable servers
2. Run Recon-ng module `recon/domains-hosts/bing_domain_web` on example.com
3. Study OSINT case studies at osintframework.com
4. Analyze Equifax 2017 breach via KrebsOnSecurity for recon insights
5. Review 2024 APT29 campaign via Mandiant reports

### Step 2: Initial Access Techniques

**Core Concepts to Master:**

**2.1 Phishing and Spear-Phishing**
- **What it is:** Craft targeted emails with obfuscated payloads
- **Example:** Clone a login page using Social Engineering Toolkit (SET)
- **MITRE ATT&CK:** T1566.001 (Spearphishing Attachment)

**2.2 Credential Access**
- **Techniques:** Password spraying, pass-the-hash attacks
- **MITRE ATT&CK:** T1110 (Brute Force)

**2.3 Exposed Service Exploitation**
- **Targets:** Misconfigured RDP, SMB services
- **Example:** Exploit weak SMB shares for initial foothold
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)

**Learning Tasks:**
1. Review MITRE ATT&CK Initial Access tactics at attack.mitre.org
2. Practice phishing with Evilginx2 in controlled lab environment
3. Study credential access via HackTheBox Academy
4. Test password spraying with Hydra
5. Analyze Twitter 2020 hack for social engineering tactics

### Step 3: Exploitation and Vulnerability Research

**Core Concepts to Master:**

**3.1 Exploit Development**
- **Focus areas:** Buffer overflows, ASLR mitigations
- **Example:** Debug vulnerable binary with GDB
- **MITRE ATT&CK:** T1068 (Exploitation for Privilege Escalation)

**3.2 Web Application Exploitation**
- **Techniques:** SQL injection, XSS, CSRF
- **Example:** Target DVWA for XSS attacks
- **MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)

**3.3 Privilege Escalation**
- **Methods:** Local exploits, kernel vulnerabilities, misconfigurations
- **MITRE ATT&CK:** T1068

**Learning Tasks:**
1. Study exploit-db.com PoCs; replicate buffer overflow in VM
2. Use OWASP ZAP to exploit web vulnerabilities in Mutillidae
3. Explore Linux privilege escalation via GTFOBins (gtfobins.github.io)
4. Review CVE-2021-3156 (sudo heap overflow) on cve.mitre.org
5. Analyze 2024 APT29 campaigns for exploitation tactics

### Step 4: Lateral Movement and Persistence

**Core Concepts to Master:**

**4.1 Pivoting Techniques**
- **Methods:** Pass-the-ticket, LOLBins (Living off the Land Binaries)
- **Example:** Use PsExec for lateral movement
- **MITRE ATT&CK:** T1021 (Remote Services)

**4.2 Persistence Mechanisms**
- **Techniques:** Scheduled tasks, registry modifications, backdoors
- **MITRE ATT&CK:** T1547 (Boot or Logon Autostart Execution)

**Learning Tasks:**
1. Simulate C2-based lateral movement with Covenant or Empire
2. Study LOLBins at lolbas-project.github.io; test in Windows lab
3. Analyze persistence techniques in APT breaches via FireEye reports
4. Review 2024 APT29 campaigns for persistence tactics

### Step 5: Evasion Techniques

**Core Concepts to Master:**

**5.1 AV/EDR Bypassing**
- **Methods:** Obfuscation, encoding to evade detection
- **Example:** Encode payloads with msfvenom to bypass Windows Defender
- **MITRE ATT&CK:** T1027 (Obfuscated Files or Information)

**5.2 Network Evasion**
- **Techniques:** Proxies, VPNs to mask traffic
- **Example:** Route C2 traffic through Tor
- **MITRE ATT&CK:** T1090 (Proxy)

**5.3 Behavioral Evasion**
- **Methods:** Mimic legitimate processes with LOLBins
- **MITRE ATT&CK:** T1036 (Masquerading)

**Learning Tasks:**
1. Study msfvenom payload encoding techniques
2. Practice Tor routing for C2 using proxychains in lab
3. Analyze EDR evasion techniques via Red Team Village resources

---

## Phase 2: Practical Application Labs

### Lab 1: OSINT and Reconnaissance

**Tools Required:** Maltego, Recon-ng, Shodan

**Objectives:**
- Enumerate subdomains and exposed services
- Build comprehensive target intelligence

**Step-by-Step Process:**

**1.1 Subdomain Enumeration**
```bash
# Using Recon-ng
recon-ng
use recon/domains-hosts/bing_domain_web
set SOURCE example.com
run
```

**Documentation Template:**
```
| Subdomain         | IP Address    | Notes           |
|-------------------|---------------|-----------------|
| www.example.com   | 93.184.216.34 | Hosts web server|
| mail.example.com  | 93.184.216.35 | Mail server     |
```

**1.2 Shodan Intelligence Gathering**
- Search query: `apache country:US`
- Document 3 exposed hosts in 50 words
- Identify potential vulnerabilities

**Deliverables:**
- Comprehensive target profile
- Risk assessment of exposed services
- Recommendations for security improvements

### Lab 2: Phishing Simulation

**Tools Required:** Gophish, Evilginx2

**Objectives:**
- Set up realistic phishing campaign
- Capture credentials safely in controlled environment

**Step-by-Step Process:**

**2.1 Campaign Setup**
1. Configure Evilginx2 proxy server
2. Clone target login page
3. Set up Gophish for email delivery
4. Test on isolated VM network only

**2.2 Credential Harvesting Documentation**
```
| Timestamp           | IP Address   | Username/Password | Risk | Notes              |
|---------------------|--------------|-------------------|------|--------------------|
| 2025-09-06 12:00:00 | 192.168.1.50 | testuser/pass123  | High | Successful capture |
```

**Safety Requirements:**
- Use only isolated lab environment
- Never target real organizations
- Obtain explicit written permission for any testing

### Lab 3: Vulnerability Exploitation

**Tools Required:** Metasploit, Nmap, OWASP ZAP

**Objectives:**
- Scan and exploit vulnerable web applications
- Document findings and remediation steps

**Step-by-Step Process:**

**3.1 Target Scanning**
```bash
# Comprehensive Nmap scan
nmap -sS -sV -O -A target_ip

# Web application scanning with ZAP
zaproxy -cmd -quickurl http://target_ip
```

**3.2 Exploitation with Metasploit**
```bash
msfconsole
use exploit/multi/http/struts_code_exec
set RHOSTS target_ip
exploit
```

**Documentation Template:**
```
| Vulnerability | CVSS Score | Description           | Remediation     |
|---------------|------------|-----------------------|-----------------|
| Struts RCE    | 9.8        | Remote code execution | Update library  |
```

### Lab 4: Lateral Movement Exercise

**Tools Required:** Covenant, Impacket

**Objectives:**
- Demonstrate network pivoting techniques
- Establish persistence mechanisms

**Step-by-Step Process:**

**4.1 Initial Compromise**
1. Establish initial foothold on target system
2. Gather local intelligence and credentials
3. Identify lateral movement opportunities

**4.2 Pivoting with Impacket**
```bash
# Lateral movement using PsExec
python3 psexec.py domain/username:password@target_ip
```

**4.3 Persistence Setup**
```bash
# Create scheduled task for persistence
schtasks /create /tn "SystemUpdate" /tr "payload.exe" /sc daily
```

**Documentation:**
```
| Technique       | Tactic      | Description       | Notes            |
|-----------------|-------------|-------------------|------------------|
| Scheduled Task  | Persistence | T1053             | Runs payload daily |
```

### Lab 5: Social Engineering Simulation

**Tools Required:** SET, PhoneInfoga, Maltego

**Objectives:**
- Simulate vishing scenario
- Gather target intelligence ethically

**Step-by-Step Process:**

**5.1 Intelligence Gathering**
1. Use PhoneInfoga for phone number analysis
2. Map relationships in Maltego
3. Build comprehensive target profile

**5.2 Vishing Scenario Development**
```
| Target ID | Data Source | Information      | Notes           |
|-----------|-------------|------------------|-----------------|
| TID001    | PhoneInfoga | Phone: 555-1234  | Linked to target|
```

**5.3 Scenario Execution (Controlled Environment Only)**
- Develop realistic but ethical scenario
- Test with willing volunteers only
- Document success/failure rates

### Lab 6: Exploit Development Basics

**Tools Required:** GDB, radare2

**Objectives:**
- Analyze binary vulnerabilities
- Develop proof-of-concept exploits

**Step-by-Step Process:**

**6.1 Binary Analysis**
```bash
# Static analysis
strings vulnerable_binary
file vulnerable_binary

# Dynamic analysis with GDB
gdb vulnerable_binary
run AAAAAAAAAAAAAAAA
```

**6.2 Exploit Development**
1. Identify buffer overflow location
2. Calculate offset to return address
3. Develop payload with shellcode
4. Test exploit in controlled environment

### Lab 7: Post-Exploitation and Exfiltration

**Tools Required:** Mimikatz, Custom exfiltration tools

**Objectives:**
- Extract credentials from compromised systems
- Demonstrate data exfiltration techniques

**Step-by-Step Process:**

**7.1 Credential Extraction**
```bash
# Using Mimikatz (Windows lab only)
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

**Documentation:**
```
| Hash Type | Username      | Hash Value       |
|-----------|---------------|------------------|
| NTLM      | Administrator | aad3b435b514...  |
```

**7.2 Data Exfiltration**
- DNS tunneling demonstration
- HTTPS upload simulation
- Steganography techniques

### Lab 8: Red Team Report Creation

**Tools Required:** Google Docs, Draw.io

**Objectives:**
- Document complete engagement
- Provide actionable recommendations

**Report Structure:**
1. **Executive Summary**
   - High-level findings
   - Business risk assessment
   - Key recommendations

2. **Technical Findings**
   - Detailed vulnerability analysis
   - Exploitation steps
   - Evidence screenshots

3. **Attack Flow Diagram**
   - Visual representation using Draw.io
   - Recon → Initial Access → Exploitation → Lateral Movement

4. **Recommendations**
   - Prioritized remediation steps
   - Strategic security improvements
   - Training recommendations

---

## Phase 3: Capstone Project

### Full Red Team Engagement Simulation

**Tools Required:** Kali Linux, Metasploit, Covenant, Google Docs

**Project Scope:**
Complete simulated breach from reconnaissance to exfiltration

**Step-by-Step Execution:**

**Phase 1: Reconnaissance (Week 1)**
- OSINT gathering using multiple tools
- Target profiling and attack surface analysis
- Social engineering intelligence collection

**Phase 2: Initial Access (Week 1)**
- Phishing campaign execution
- Vulnerability scanning and exploitation
- Foothold establishment

**Phase 3: Post-Exploitation (Week 2)**
- Privilege escalation
- Lateral movement simulation
- Persistence mechanism deployment

**Phase 4: Data Collection and Exfiltration (Week 2)**
- Sensitive data identification
- Exfiltration technique demonstration
- Impact assessment

**Documentation Requirements:**

**Engagement Log:**
```
| Phase      | Tool Used | Action Description | MITRE Technique |
|------------|-----------|--------------------|-----------------|
| Recon      | Recon-ng  | Subdomain enum     | T1595           |
| Init Access| Gophish   | Phishing campaign  | T1566.001       |
| Exploit    | Metasploit| RCE exploitation   | T1190           |
| Lateral    | PsExec    | Remote execution   | T1021.002       |
```

**Blue Team Analysis:**
- Review detection logs (Wazuh, Splunk)
- Identify detection gaps
- Document evasion success/failure

**Sample Detection Log:**
```
| Timestamp           | Alert Description | Source IP     | Notes            |
|---------------------|-------------------|---------------|------------------|
| 2025-09-06 13:00:00 | Suspicious Login  | 192.168.1.50  | Phishing attempt |
| 2025-09-06 13:05:00 | Process Injection | 192.168.1.51  | Mimikatz detected|
```

**Final Report (200+ words):**
1. **Executive Summary**
   - Business impact assessment
   - Key vulnerabilities discovered
   - Overall security posture

2. **Technical Findings**
   - Detailed attack path
   - Exploitation techniques used
   - Blue team detection analysis

3. **Recommendations**
   - Immediate remediation steps
   - Long-term security improvements
   - Training and awareness programs

4. **Lessons Learned**
   - Evasion technique effectiveness
   - Detection capability assessment
   - Recommended security investments

**Non-Technical Brief (100 words):**
- Executive-level summary
- Business risk focus
- Investment recommendations
- No technical jargon

---

## Assessment Criteria and Deliverables

### Required Submissions:
1. **Lab Reports:** Individual lab documentation (Labs 1-8)
2. **Tool Inventory:** Comprehensive tool usage log
3. **Capstone Project:** Complete red team engagement simulation
4. **Final Report:** Professional security assessment document
5. **Executive Brief:** Non-technical summary for leadership

### Evaluation Standards:
- **Technical Proficiency:** 40%
- **Documentation Quality:** 30%
- **Ethical Compliance:** 20%
- **Innovation and Creativity:** 10%

### Timeline:
- **Theoretical Study:** Days 1-3
- **Practical Labs:** Days 4-8
- **Capstone Project:** Days 9-14
- **Report Writing:** Days 15-16
- **Final Submission:** September 8th, 5:30 PM

---

## Safety and Legal Guidelines

### Mandatory Requirements:
1. **Written Authorization:** All testing requires explicit written permission
2. **Scope Limitation:** Never exceed defined testing boundaries
3. **Data Protection:** Secure handling of any discovered sensitive information
4. **Incident Response:** Immediate reporting of unintended impacts
5. **Professional Conduct:** Maintain highest ethical standards

### Prohibited Activities:
- Testing against unauthorized systems
- Accessing or modifying production data
- Sharing discovered vulnerabilities publicly
- Using techniques for personal gain
- Causing service disruptions

### Emergency Procedures:
- Immediate cessation of testing if issues arise
- Contact instructor/supervisor immediately
- Document all incidents thoroughly
- Cooperate fully with any investigations

---

## Resource Repository

### Essential Tools Installation:
```bash
# Kali Linux tool installation
sudo apt update && sudo apt upgrade
sudo apt install maltego recon-ng shodan nmap metasploit-framework
git clone https://github.com/UndeadSec/EvilURL.git
git clone https://github.com/gophish/gophish.git
```

### Study Resources:
1. **MITRE ATT&CK Framework:** attack.mitre.org
2. **OWASP Testing Guide:** owasp.org
3. **Red Team Field Manual:** GitHub repository
4. **HackTheBox Academy:** academy.hackthebox.com
5. **TryHackMe Red Team Path:** tryhackme.com

### Community Resources:
- **Red Team Village:** YouTube channel and Discord
- **SANS SEC564:** Red Team Exercises and Adversary Emulation
- **Red Team Journal:** Blog and resource collection
- **Pentester Land:** Newsletter and resource compilation

---

## Success Metrics

### Knowledge Checkpoints:
- [ ] MITRE ATT&CK framework understanding
- [ ] Tool proficiency demonstration  
- [ ] Evasion technique implementation
- [ ] Professional reporting capability
- [ ] Ethical compliance maintenance

### Practical Milestones:
- [ ] Successful OSINT intelligence gathering
- [ ] Phishing campaign execution (lab environment)
- [ ] Vulnerability exploitation demonstration
- [ ] Lateral movement simulation
- [ ] Complete engagement documentation

### Professional Development:
- [ ] Industry best practices adoption
- [ ] Legal and ethical compliance
- [ ] Communication skills demonstration
- [ ] Continuous learning mindset
- [ ] Team collaboration capability

---

*This guide provides a comprehensive framework for red team cybersecurity learning. Remember that with great power comes great responsibility - use these skills ethically and legally to improve organizational security posture.*

**Deadline Reminder:** Complete all phases and submit final deliverables by September 8th, 2025, 5:30 PM IST.