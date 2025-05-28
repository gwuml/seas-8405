
## Question: Equifax Multi-Stage Breach (Initial Access → Exfiltration)

### Scenario

In 2017, an enterprise deployed an Apache Struts–based web application on Amazon EC2 in a public subnet behind an  Elastic Load Balancer (ELB) terminating TLS. DNS was provided by Route 53. A private subnet hosted an RDS PostgreSQL database containing PII. AWS Inspector ran vulnerability scans (misconfigured and producing false negatives), and GuardDuty acted as an IDS but had its certificates expired, disabling alerts. CloudWatch Logs fed into an Elastic-based SIEM, but no micro-segmentation existed between web and DB tiers. Attackers exploited the unpatched CVE-2017-5638, executed code on EC2, pivoted via SSH to the database host, extracted PII, and exfiltrated it over an encrypted C2 channel.

### Tactics Used (MITRE ATT\&CK)

* **Initial Access (T1190)**: Exploit Public-Facing Application
* **Defense Evasion (T1562.001)**: Disable IDS
* **Discovery (T1087)**: Account Discovery
* **Lateral Movement (T1021.002)**: Remote Services (SSH)
* **Collection (T1005)**: Data from Local System
* **Exfiltration (T1041)**: Exfiltration Over C2

### Security Controls (and example tools)

* **Patch Management System** (update orchestration)
* **Automated Patching** (AWS Systems Manager)
* **Web Application Firewall (WAF)** (ELB-level protection)
* **Network Segmentation / Micro-segmentation** (VPC subnets & security groups)
* **Intrusion Detection System (IDS) with valid certificates** (GuardDuty)
* **Vulnerability Scanning** (AWS Inspector correctly configured)
* **Encrypted Data in Transit** (TLS 1.3 east-west)
* **SIEM with CloudWatch Logs** (real-time correlation)
* **Behavioral Analytics (UEBA)** (detects unusual DB access)
* **SOAR Playbooks** (automated containment and remediation)

### Question

Which combination of controls, leveraging Defense in Depth (DiD), Adaptive Security Architecture (ASA), and Zero Trust Architecture (ZTA), best prevents the initial Struts exploit, detects lateral movement, restricts unauthorized DB access, and responds to exfiltration?

### Options

**1.**

* **Prevent (DiD)**: Patch Management System + WAF
* **Detect (ASA)**: Vulnerability Scanning + SIEM with CloudWatch Logs
* **Prevent Access (ZTA)**: Network Segmentation + IDS with valid certificates
* **Respond (ASA)**: SOAR Playbooks + Behavioral Analytics

**2.**

* **Prevent (DiD)**: Automated Patching + WAF
* **Detect (ASA)**: IDS with valid certificates + Behavioral Analytics
* **Prevent Access (ZTA)**: Micro-segmentation + Encrypted Data in Transit
* **Respond (ASA)**: SOAR Playbooks + Certificate Management

**3.**

* **Prevent (DiD)**: Patch Management System + Automated Patching
* **Detect (ASA)**: Behavioral Analytics + SIEM with CloudWatch Logs
* **Prevent Access (ZTA)**: Micro-segmentation + WAF
* **Respond (ASA)**: SOAR Playbooks + IRT Coordination

**4.**

* **Prevent (DiD)**: WAF + Vulnerability Scanning
* **Detect (ASA)**: IDS with valid certificates + Automated Patching
* **Prevent Access (ZTA)**: Network Segmentation + Certificate Management
* **Respond (ASA)**: Behavioral Analytics + Encrypted Data Channels

**5.**

* **Prevent (DiD)**: WAF + Patch Management System
* **Detect (ASA)**: SIEM with CloudWatch Logs + Vulnerability Scanning
* **Prevent Access (ZTA)**: Encrypted Data in Transit + Network Segmentation
* **Respond (ASA)**: Behavioral Analytics + SOAR Playbooks

**6.**

* **Prevent (DiD)**: Automated Patching + Certificate Management
* **Detect (ASA)**: CloudWatch Logs + Behavioral Analytics
* **Prevent Access (ZTA)**: Micro-segmentation + WAF
* **Respond (ASA)**: IRT Coordination + SOAR Playbooks

### Correct Answer: 3

---

## Question: Equifax Lateral Movement & Exfiltration

### Scenario

Same 2017 Equifax AWS layout: public Struts EC2 → ELB → Route 53; private RDS PostgreSQL; no micro-segmentation;  disabled GuardDuty; misconfigured Inspector; CloudWatch Logs→SIEM. After initial compromise, attackers used SSH to pivot across subnets, harvested PII files, and exfiltrated them via an encrypted tunnel to an external C2 server.

### Tactics Used

* **Lateral Movement (T1021.002)**: Remote Services
* **Collection (T1005)**: Data from Local System
* **Exfiltration (T1041)**: Exfiltration Over C2

### Security Controls

* Network Segmentation / Micro-segmentation
* Encrypted Data in Transit (TLS east-west)
* Behavioral Analytics (UEBA)
* SOAR Playbooks
* SIEM with CloudWatch Logs
* IDS with valid certificates

### Question

Which combination of controls best blocks lateral pivot, prevents data harvesting, and responds to exfiltration in this scenario?

### Options

**1.**

* **Prevent (ZTA)**: Micro-segmentation + Encrypted Data in Transit
* **Detect (ASA)**: IDS with valid certificates + Behavioral Analytics
* **Prevent Access (DiD)**: Network Segmentation + WAF
* **Respond (ASA)**: SOAR Playbooks + SIEM Alerts

**2.**

* **Prevent (ZTA)**: Micro-segmentation + Encrypted Data in Transit
* **Detect (ASA)**: Behavioral Analytics + SIEM with CloudWatch Logs
* **Prevent Access (DiD)**: Network Segmentation + IDS with valid certificates
* **Respond (ASA)**: SOAR Playbooks + IRT Coordination

**3.**

* **Prevent (ZTA)**: Micro-segmentation + WAF
* **Detect (ASA)**: Behavioral Analytics + SIEM with CloudWatch Logs
* **Prevent Access (DiD)**: Encrypted Data in Transit + Network Segmentation
* **Respond (ASA)**: SOAR Playbooks + IRT Coordination

**4.**

* **Prevent (DiD)**: Network Segmentation + IDS with valid certificates
* **Detect (ASA)**: Behavioral Analytics + SIEM Alerts
* **Prevent Access (ZTA)**: Micro-segmentation + Encrypted Data in Transit
* **Respond (ASA)**: SOAR Playbooks + Certificate Management

**5.**

* **Prevent (DiD)**: WAF + Certificate Management
* **Detect (ASA)**: IDS with valid certificates + Automated Patching
* **Prevent Access (ZTA)**: Encrypted Data in Transit + WAF
* **Respond (ASA)**: IRT Coordination + Behavioral Analytics

**6.**

* **Prevent (DiD)**: WAF + Automated Patching
* **Detect (ASA)**: CloudWatch Logs + Behavioral Analytics
* **Prevent Access (ZTA)**: Micro-segmentation + Certificate Management
* **Respond (ASA)**: IRT Coordination + SOAR Playbooks

### Correct Answer: 6

---

## Question: SolarWinds Supply-Chain Compromise

### Scenario

In 2020, a vendor’s build pipeline ran in an AWS VPC with three subnets: **Build** (EC2 build servers), **Update** (EC2  distribution servers), and **Client** (EC2 customer appliances). Build artifacts were compiled, cryptographically signed, then pushed to the Update servers. Route 53 DNS directed clients to updates. Amazon CloudTrail recorded API and file events. No tamper detection or continuous validation was in place, and micro-segmentation between build and update subnets was minimal. Attackers injected a backdoor into the signed binaries, which were then automatically distributed to 18,000+ client systems.

### Tactics Used

* **Initial Access (T1195.002)**: Supply Chain Compromise
* **Defense Evasion (T1553.002)**: Forge Code Signing
* **Persistence (T1543.003)**: Create or Modify System Process
* **Lateral Movement (T1021.002)**: Remote Services across subnets
* **Exfiltration (T1041)**: Exfiltration Over C2

### Security Controls

* Code Signing Verification
* Network Segmentation / Micro-segmentation
* Tamper Detection
* Audit Logging (CloudTrail)
* Continuous Validation of Artifacts
* Behavioral Monitoring (UEBA)
* Least Privilege Access
* Dynamic Network Policies
* Encrypted Communication (mTLS)
* SOAR Playbooks (automated response)

### Question

Which combination of controls best prevents backdoor injection, detects pipeline tampering, restricts unauthorized update distribution, and responds to malicious artifacts in this SolarWinds scenario?

### Options

**1.**

* **Prevent (DiD)**: Code Signing Verification + Network Segmentation
* **Detect (ASA)**: Tamper Detection + Audit Logging
* **Prevent Access (ZTA)**: Continuous Validation + Micro-segmentation
* **Respond (ASA)**: Dynamic Network Policies + SOAR Playbooks

**2.**

* **Prevent (DiD)**: Tamper Detection + Continuous Validation
* **Detect (DiD)**: Audit Logging + Behavioral Monitoring
* **Prevent Access (ZTA)**: Least Privilege Access + Encrypted Communication
* **Respond (ASA)**: SOAR Playbooks + CloudTrail Alerts

**3.**

* **Prevent (DiD)**: Code Signing Verification + Continuous Validation
* **Detect (ASA)**: Audit Logging + Anomaly Detection in Builds
* **Prevent Access (ZTA)**: Network Segmentation + Micro-segmentation
* **Respond (ASA)**: Dynamic Network Policies + Encrypted Data Channels

**4.**

* **Prevent (ASA)**: Behavioral Monitoring + Micro-segmentation
* **Detect (DiD)**: Tamper Detection + Audit Logging
* **Prevent Access (ZTA)**: Least Privilege Access + Continuous Validation
* **Respond (ASA)**: SOAR Playbooks + Certificate Management

**5.**

* **Prevent (DiD)**: Code Signing Verification + Network Segmentation
* **Detect (ASA)**: Audit Logging + Anomaly Detection in Builds
* **Prevent Access (ZTA)**: Continuous Validation + Least Privilege Access
* **Respond (ASA)**: Dynamic Network Policies + Encrypted Data Channels

**6.**


* **Prevent (DiD)**: Code Signing Verification + Tamper Detection
* **Detect (ASA)**: Behavioral Monitoring + Audit Logging
* **Prevent Access (ZTA)**: Encrypted Communication + Micro-segmentation
* **Respond (ASA)**: Dynamic Network Policies + IRT Coordination

### Correct Answer: 5

---

## Question: SolarWinds Lateral Movement & Persistence

### Scenario

The SolarWinds environment (build/update/client subnets, signed artifacts, no tamper checks) allowed attackers to pivot from build to update servers, install persistent backdoors in system services, and maintain access across multiple pipeline stages.

### Tactics Used

* **Lateral Movement (T1021.002)**: Remote Services
* **Persistence (T1543.003)**: Create or Modify System Process

### Security Controls

* Micro-segmentation
* Continuous Validation
* Tamper Detection
* Least Privilege Access
* Behavioral Monitoring
* Automated Integrity Checks
* Encrypted Communication

### Question

Which combination of controls best halts lateral movement in the pipeline and prevents installation of persistent
backdoors?

### Options

**1.**

* **Prevent (DiD)**: Network Segmentation + Automated Integrity Checks
* **Detect (ASA)**: Behavioral Monitoring + Tamper Detection
* **Prevent Access (ZTA)**: Micro-segmentation + Continuous Validation
* **Respond (ASA)**: SOAR Playbooks + Audit Logging

**2.**

* **Prevent (DiD)**: Tamper Detection + Code Signing Verification
* **Detect (ASA)**: Audit Logging + Behavioral Monitoring
* **Prevent Access (ZTA)**: Micro-segmentation + Least Privilege Access
* **Respond (ASA)**: Dynamic Network Policies + Encrypted Data Channels

**3.**

* **Prevent (ZTA)**: Continuous Validation + Micro-segmentation
* **Detect (ASA)**: Behavioral Monitoring + Anomaly Detection in Builds
* **Prevent Access (DiD)**: Automated Integrity Checks + Network Segmentation
* **Respond (ASA)**: SOAR Playbooks + IRT Coordination

**4.**

* **Prevent (DiD)**: Network Segmentation + Code Signing Verification
* **Detect (ASA)**: Tamper Detection + Audit Logging
* **Prevent Access (ZTA)**: Continuous Validation + Least Privilege Access
* **Respond (ASA)**: Dynamic Network Policies + Behavioral Monitoring

**5.**

* **Prevent (ASA)**: Behavioral Monitoring + Continuous Validation
* **Detect (DiD)**: Tamper Detection + Automated Integrity Checks
* **Prevent Access (ZTA)**: Micro-segmentation + Encrypted Communication
* **Respond (ASA)**: SOAR Playbooks + Audit Logging

**6.**

* **Prevent (DiD)**: Code Signing Verification + Network Segmentation
* **Detect (ASA)**: Tamper Detection + Behavioral Monitoring
* **Prevent Access (ZTA)**: Micro-segmentation + Continuous Validation
* **Respond (ASA)**: SOAR Playbooks + Dynamic Network Policies

### Correct Answer: 6


---

## Question: Capital One SSRF & Exfiltration

### Scenario

In 2019, a financial firm’s AWS VPC hosted an EC2 web application in a public subnet behind AWS WAF, accessible via Route 53. The EC2 had an IAM role granting wide S3 bucket access. WAF rules were too permissive, allowing an SSRF payload to call the EC2 metadata service, returning temporary credentials. Attackers used these credentials to enumerate and download data from 100+ S3 buckets, then exfiltrated it to an external C2. CloudWatch Logs and GuardDuty were active, but IAM policies were overly broad and micro-segmentation was absent.

### Tactics Used

* **Initial Access (T1190)**: Exploit Public-Facing Application (SSRF)
* **Defense Evasion (T1098)**: Account Manipulation (metadata token reuse)
* **Discovery (T1083)**: File and Directory Discovery (S3 enumeration)
* **Collection (T1005)**: Data from Local System (S3 objects)
* **Exfiltration (T1041)**: Exfiltration Over C2

### Security Controls

* WAF Rule Validation
* IAM Role Hardening (Least Privilege)
* Network Segmentation / Micro-segmentation
* Monitoring & Logging (CloudWatch + GuardDuty)
* Data Encryption at Rest (S3 SSE-KMS)
* Continuous Verification (ZTA per-request auth)
* Adaptive WAF Rules (real-time tuning)
* Automated IAM Adjustment (revoke tokens)
* Dynamic Monitoring
* Encrypted Data Channels

### Question

Which combination of controls best prevents SSRF, detects token misuse, restricts S3 access, and responds to  exfiltration?

### Options

**1.**

* **Prevent (DiD)**: WAF Rule Validation + IAM Role Hardening
* **Detect (ASA)**: Monitoring & Logging + Behavioral Monitoring
* **Prevent Access (ZTA)**: Continuous Verification + Network Segmentation
* **Respond (ASA)**: Automated IAM Adjustment + Dynamic Monitoring

**2.**

* **Prevent (DiD)**: IAM Role Hardening + Data Encryption at Rest
* **Detect (ASA)**: GuardDuty + CloudWatch Logs
* **Prevent Access (ZTA)**: Micro-segmentation + Continuous Verification
* **Respond (ASA)**: Adaptive WAF Rules + Encrypted Data Channels

**3.**

* **Prevent (ZTA)**: Continuous Verification + WAF Rule Validation
* **Detect (ASA)**: GuardDuty + Behavioral Monitoring
* **Prevent Access (DiD)**: Network Segmentation + IAM Role Hardening
* **Respond (ASA)**: Automated IAM Adjustment + Adaptive WAF Rules

**4.**

* **Prevent (DiD)**: WAF Rule Validation + Continuous Verification
* **Detect (ASA)**: Behavioral Monitoring + CloudWatch Logs
* **Prevent Access (ZTA)**: IAM Role Hardening + Micro-segmentation
* **Respond (ASA)**: Dynamic Monitoring + Encrypted Data Channels

**5.**

* **Prevent (ASA)**: Adaptive WAF Rules + Continuous Verification
* **Detect (DiD)**: GuardDuty + Monitoring & Logging
* **Prevent Access (ZTA)**: IAM Role Hardening + Network Segmentation
* **Respond (ASA)**: Automated IAM Adjustment + Certificate Management

**6.**

* **Prevent (DiD)**: WAF Rule Validation + IAM Role Hardening
* **Detect (ASA)**: GuardDuty + Behavioral Monitoring
* **Prevent Access (ZTA)**: Continuous Verification + Micro-segmentation
* **Respond (ASA)**: Automated IAM Adjustment + Adaptive WAF Rules

### Correct Answer: 6


---


### **Analyzing the answers**  

| **Scenario**                | **Control Function**       | **Correct Answer (Controls)**       | **Why Correct?**                                                                                       | **Closest Alternative (Controls)**      | **Critical Flaw in Alternative**                                                                                  | **Real-World Lesson**                                                                                  |
|-----------------------------|----------------------------|-------------------------------------|--------------------------------------------------------------------------------------------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Target POS Breach**       | **Prevent (DiD)**          | Vendor Segregation + Patch Mgmt     | Isolates third-party access; patches prevent exploit (e.g., CVE-2013-3900).                           | Network Seg + Patch Mgmt (Opt 1)        | ❌ **Coarse isolation:** Network seg doesn’t restrict vendor over-access; HVAC exploit still possible.  | **Lesson:** Third-party vendors need strict isolation, not just patching; broad access amplifies risk. |
|                             | **Detect (ASA)**           | Behavioral Analytics + SIEM         | Flags unusual POS traffic (e.g., memory scraping); SIEM correlates logs adaptively.                   | SIEM + Vuln Scanning (Opt 2)            | ❌ **Static gap:** Vuln scanning misses active RAM scraping; no behavioral detection.                   | **Lesson:** Static scans can’t catch live malware; behavioral analytics is key for stealthy attacks.   |
|                             | **Prevent Access (ZTA)**   | Micro-segmentation + Least Priv     | Blocks POS→backend traffic; least priv limits stolen creds’ impact.                                   | Network Seg + Encryption (Opt 3)        | ❌ **Irrelevant control:** Encryption doesn’t stop lateral movement; coarse seg allows pivots.          | **Lesson:** Encryption won’t block access; micro-segmentation enforces Zero Trust boundaries.          |
|                             | **Respond (ASA)**          | SOAR + IRT Coordination             | SOAR isolates POS; IRT investigates stolen data scope.                                                | SOAR + Audit Logs (Opt 4)               | ⚠️ **Passive:** Audit logs don’t enable active containment; delays response.                           | **Lesson:** Automation needs human oversight; logs alone slow down breach response.                    |
| **Home Depot Malware**      | **Prevent (DiD)**          | Patch Mgmt + Endpoint Hardening     | Patches vuln (e.g., CVE-2014-3566); hardened endpoints block malware install.                         | AV + Patch Mgmt (Opt 1)                 | ❌ **Detection lag:** AV missed custom malware; prevention incomplete without hardening.                | **Lesson:** AV isn’t enough for custom threats; harden endpoints proactively.                          |
|                             | **Detect (ASA)**           | EDR + Behavioral Monitoring         | EDR catches memory scraping; behavioral mon flags anomalies.                                          | SIEM + AV (Opt 2)                       | ❌ **Weak detection:** AV failed on zero-day; SIEM lacks endpoint granularity.                         | **Lesson:** Legacy AV misses new threats; EDR provides real-time endpoint visibility.                  |
|                             | **Prevent Access (ZTA)**   | Micro-segmentation + Cert Mgmt      | Micro-seg stops lateral spread; valid certs ensure alerts work.                                       | Network Seg + IDS (Opt 3)               | ❌ **Coarse flaw:** Network seg too broad; expired certs disable IDS.                                   | **Lesson:** Expired certs kill detection; micro-segmentation beats broad network controls.             |
|                             | **Respond (ASA)**          | SOAR + Dynamic Policies             | SOAR quarantines endpoints; policies block exfil traffic.                                             | IRT + Audit Logs (Opt 4)                | ❌ **Slow:** Manual IRT can’t match SOAR speed; logs don’t act.                                         | **Lesson:** Automated response outpaces manual efforts in fast-moving breaches.                       |
| **Marriott Data Leak**      | **Prevent (DiD)**          | Data Encryption + IAM Hardening     | Encryption protects stored PII; IAM limits DB access.                                                 | Encryption + Network Seg (Opt 1)        | ❌ **Access gap:** Network seg doesn’t stop stolen creds; IAM was weak.                                 | **Lesson:** Weak IAM lets attackers in; encryption needs strict access controls.                      |
|                             | **Detect (ASA)**           | DLP + Anomaly Detection             | DLP flags PII exfil; anomaly detection spots unusual queries.                                         | SIEM + Audit Logs (Opt 2)               | ⚠️ **Limited scope:** SIEM misses PII-specific leaks; logs lack proactive alerts.                      | **Lesson:** Generic SIEM misses sensitive data leaks; DLP is critical for PII.                         |
|                             | **Prevent Access (ZTA)**   | Continuous Validation + Least Priv  | Per-request auth blocks stolen creds; least priv limits damage.                                       | Least Priv + Encryption (Opt 3)         | ❌ **Trust flaw:** Encryption irrelevant post-auth; no continuous validation.                          | **Lesson:** Static auth fails; continuous validation enforces Zero Trust.                              |
|                             | **Respond (ASA)**          | Auto IAM Adjust + SOAR              | Revokes compromised creds; SOAR contains breach.                                                      | IRT + Audit Logs (Opt 4)                | ❌ **Manual delay:** IRT too slow vs. auto IAM; logs don’t act.                                         | **Lesson:** Automated credential revocation beats manual response for data leaks.                      |
| **Twitter API Abuse**       | **Prevent (DiD)**          | API Rate Limiting + Input Val       | Rate limits block brute force; validation stops malformed requests.                                   | Rate Limiting + Encryption (Opt 1)      | ❌ **Irrelevant:** Encryption doesn’t prevent API abuse; no input validation.                          | **Lesson:** Encryption doesn’t stop API exploits; validate inputs to block abuse.                      |
|                             | **Detect (ASA)**           | API Monitoring + Behavioral Analytics | Flags abnormal API calls; behavioral analytics adapts to new patterns.                               | SIEM + Audit Logs (Opt 2)               | ⚠️ **Generic:** SIEM lacks API-specific context; logs miss real-time anomalies.                        | **Lesson:** Generic logging misses API threats; specialized monitoring is essential.                   |
|                             | **Prevent Access (ZTA)**   | Continuous Verif + Micro-seg        | Verifies each API call; micro-seg limits app exposure.                                                | Least Priv + Network Seg (Opt 3)        | ❌ **Weak scope:** Network seg too broad; no per-request verification.                                  | **Lesson:** Broad controls fail; continuous verification secures APIs.                                 |
|                             | **Respond (ASA)**          | Dynamic Policies + SOAR             | Blocks abusive IPs; SOAR isolates affected services.                                                  | IRT + Audit Logs (Opt 4)                | ❌ **Slow:** Manual IRT can’t keep up; logs don’t respond.                                              | **Lesson:** Automation is critical for rapid API breach response.                                      |

