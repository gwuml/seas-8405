
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

| **Question Description**                                                                                      | **Scenario**                | **Control Function**       | **Correct Answer (Controls)**       | **Why Correct?**                                                                                       | **Closest Alternative (Controls)**      | **Critical Flaw in Alternative**                                                                                  | **Real-World Lesson**                                                                                  |
|----------------------------------------------------------------------------------------------------------------|-----------------------------|----------------------------|-------------------------------------|--------------------------------------------------------------------------------------------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Equifax Multi-Stage Breach**: Unpatched Struts exploit on EC2 → SSH pivot to RDS → PII exfil via C2.         | Equifax Multi-Stage         | **Prevent (DiD)**          | Patch Mgmt + Auto Patching          | Fixes root cause (CVE-2017-5638); layered prevention.                                                  | WAF + Patch Mgmt (Opt 5)                | ❌ **Detection gap:** Misconfigured vuln scanning misses exploit; no SSH detection.                        | **Lesson:** Systematic patching and tool configuration are critical.                  |
|                                                                                                                |                             | **Detect (ASA)**           | Behavioral Analytics + SIEM         | Catches anomalous SSH pivots; real-time correlation adapts to threats.                                 | SIEM + Vuln Scanning (Opt 5)            | ❌ **Broken:** Misconfigured scanning fails; SIEM alone misses live movement.                             | **Lesson:** Behavioral analytics detect what static scans miss.                       |
|                                                                                                                |                             | **Prevent Access (ZTA)**   | Micro-segmentation + WAF            | Blocks web-to-DB traffic (Zero Trust); WAF stops initial exploit.                                      | Encrypted Data + Network Seg (Opt 2)    | ❌ **Weak:** Encryption doesn’t stop SSH; coarse segmentation allows pivots.                              | **Lesson:** Micro-segmentation enforces Zero Trust; encryption isn’t enough.          |
|                                                                                                                |                             | **Respond (ASA)**          | SOAR + IRT Coordination             | Automates containment; IRT drives rapid forensics.                                                     | Behavioral Analytics + SOAR (Opt 5)     | ⚠️ **Limited:** No human oversight (IRT) for complex response.                                            | **Lesson:** Automation plus human expertise tackles multi-stage attacks.             |

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

| **Question Description**                                                                                      | **Scenario**                | **Control Function**       | **Correct Answer (Controls)**       | **Why Correct?**                                                                                       | **Closest Alternative (Controls)**      | **Critical Flaw in Alternative**                                                                                  | **Real-World Lesson**                                                                                  |
|----------------------------------------------------------------------------------------------------------------|-----------------------------|----------------------------|-------------------------------------|--------------------------------------------------------------------------------------------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Equifax Lateral Movement & Exfiltration**: SSH pivot across subnets → PII harvest → exfil via encrypted C2.  | Equifax Lateral             | **Prevent (DiD)**          | WAF + Auto Patching                 | Blocks initial exploit; patching prevents recurrence.                                                  | Micro-seg + Encrypted Data (Opt 2)      | ❌ **Gap:** Encryption irrelevant to SSH; no WAF for exploit prevention.                                  | **Lesson:** WAF stops web exploits; encryption doesn’t block movement.                |
|                                                                                                                |                             | **Detect (ASA)**           | CloudWatch + Behavioral Analytics   | Flags unusual DB access; adapts to new tactics.                                                        | Behavioral Analytics + SIEM (Opt 2)     | ⚠️ **Partial:** Lacks CloudWatch’s AWS-specific context.                                                  | **Lesson:** Native cloud logs enhance detection in AWS.                               |
|                                                                                                                |                             | **Prevent Access (ZTA)**   | Micro-segmentation + Cert Mgmt      | Stops pivots; valid certs ensure IDS alerts (Zero Trust).                                              | Network Seg + IDS (Opt 2)               | ❌ **Coarse:** Broad segmentation allows web-to-DB traffic.                                               | **Lesson:** Granular micro-segmentation beats broad controls.                         |
|                                                                                                                |                             | **Respond (ASA)**          | IRT + SOAR                          | SOAR isolates hosts; IRT investigates.                                                                 | SOAR + IRT (Opt 2)                      | ✅ **Matches:** Strong, but other alternatives lack IRT.                                                   | **Lesson:** Human and automated response together are key.                            |


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
| **Question Description**                                                                                      | **Scenario**                | **Control Function**       | **Correct Answer (Controls)**       | **Why Correct?**                                                                                       | **Closest Alternative (Controls)**      | **Critical Flaw in Alternative**                                                                                  | **Real-World Lesson**                                                                                  |
|----------------------------------------------------------------------------------------------------------------|-----------------------------|----------------------------|-------------------------------------|--------------------------------------------------------------------------------------------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **SolarWinds Supply-Chain Compromise**: Backdoor in signed binaries → distributed to 18,000+ clients.          | SolarWinds Supply Chain     | **Prevent (DiD)**          | Code Signing + Network Segmentation | Prevents backdoor injection; contains compromise.                                                      | Network Seg + Micro-seg (Opt 3)         | ❌ **Flaw:** Allows malicious signed binaries without verification.                                        | **Lesson:** Verify signatures; segmentation alone fails against signed malware.       |
|                                                                                                                |                             | **Detect (ASA)**           | Audit Logs + Anomaly Detection      | Logs tampering (CloudTrail); flags malicious builds.                                                   | Tamper Detection + Audit Logs (Opt 1)   | ⚠️ **Reactive:** Tamper detection lags; anomaly detection is proactive.                                   | **Lesson:** Proactive detection beats reactive checks.                                |
|                                                                                                                |                             | **Prevent Access (ZTA)**   | Continuous Validation + Least Priv  | Validates artifacts pre-run (Zero Trust); limits damage.                                               | Continuous Val + Micro-seg (Opt 1)      | ❌ **Weak:** Micro-segmentation doesn’t stop bad binaries.                                                | **Lesson:** Continuous validation enforces Zero Trust for artifacts.                 |
|                                                                                                                |                             | **Respond (ASA)**          | Dynamic Policies + Encrypted Chans  | Isolates nodes; encryption blocks C2.                                                                  | Dynamic Policies + SOAR (Opt 1)         | ⚠️ **Incomplete:** No encryption to hinder exfiltration.                                                  | **Lesson:** Encrypt response channels to thwart attackers.                           |

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

| **Question Description**                                                                                      | **Scenario**                | **Control Function**       | **Correct Answer (Controls)**       | **Why Correct?**                                                                                       | **Closest Alternative (Controls)**      | **Critical Flaw in Alternative**                                                                                  | **Real-World Lesson**                                                                                  |
|----------------------------------------------------------------------------------------------------------------|-----------------------------|----------------------------|-------------------------------------|--------------------------------------------------------------------------------------------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **SolarWinds Lateral Movement & Persistence**: Pivot from build to update servers → install backdoors.         | SolarWinds Lateral          | **Prevent (DiD)**          | Code Signing + Network Segmentation | Blocks bad binaries; restricts pivot paths.                                                            | Tamper Detection + Code Signing (Opt 2) | ❌ **Gap:** Tamper detection doesn’t prevent installation.                                                | **Lesson:** Prevention trumps detection for persistence.                              |
|                                                                                                                |                             | **Detect (ASA)**           | Tamper Detection + Behavioral Mon   | Flags backdoor writes; spots process anomalies.                                                        | Audit Logs + Behavioral Mon (Opt 2)     | ⚠️ **Slow:** Audit logs lack real-time alerts.                                                            | **Lesson:** Real-time detection catches persistence early.                           |
|                                                                                                                |                             | **Prevent Access (ZTA)**   | Micro-seg + Continuous Validation   | Limits access; ensures trusted binaries (Zero Trust).                                                  | Least Priv + Encrypted Comm (Opt 2)     | ❌ **Misplaced:** Encryption doesn’t stop pivots; least priv can’t block signed code.                     | **Lesson:** Micro-segmentation and validation enforce Zero Trust.                    |
|                                                                                                                |                             | **Respond (ASA)**          | SOAR + Dynamic Policies             | Isolates servers; blocks malicious traffic.                                                            | SOAR + Audit Logging (Opt 1)            | ❌ **Passive:** Logging doesn’t act against breaches.                                                     | **Lesson:** Active automation contains breaches; logging isn’t enough.               |
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

| **Question Description**                                                                                      | **Scenario**                | **Control Function**       | **Correct Answer (Controls)**       | **Why Correct?**                                                                                       | **Closest Alternative (Controls)**      | **Critical Flaw in Alternative**                                                                                  | **Real-World Lesson**                                                                                  |
|----------------------------------------------------------------------------------------------------------------|-----------------------------|----------------------------|-------------------------------------|--------------------------------------------------------------------------------------------------------|-----------------------------------------|------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| **Capital One SSRF & Exfiltration**: SSRF exploit → steal EC2 metadata creds → exfil S3 data via C2.           | Capital One SSRF            | **Prevent (DiD)**          | WAF Validation + IAM Hardening      | Blocks SSRF; restricts S3 access (least privilege).                                                    | Continuous Verif + WAF (Opt 3)          | ❌ **Flaw:** No IAM hardening lets stolen creds work.                                                     | **Lesson:** Harden IAM to stop credential abuse.                                      |
|                                                                                                                |                             | **Detect (ASA)**           | GuardDuty + Behavioral Monitoring   | Detects S3 misuse; adapts to new TTPs.                                                                 | GuardDuty + CloudWatch (Opt 2)          | ⚠️ **Limited:** CloudWatch misses behavioral context.                                                     | **Lesson:** Behavioral analytics catch misuse; logs need context.                    |
|                                                                                                                |                             | **Prevent Access (ZTA)**   | Continuous Verif + Micro-seg        | Verifies each request (Zero Trust); limits credential scope.                                           | IAM Hardening + Micro-seg (Opt 4)       | ✅ **Strong:** Matches correct answer; slightly less focus elsewhere.                                      | **Lesson:** Continuous verification enforces Zero Trust per request.                 |
|                                                                                                                |                             | **Respond (ASA)**          | Auto IAM Adjust + Adaptive WAF      | Revokes tokens; blocks exfil IPs dynamically.                                                          | SOAR + IRT (Opt 2)                      | ❌ **Slow:** Manual IRT can’t match automated speed.                                                      | **Lesson:** Automated IAM responses outpace manual fixes in the cloud.               |
