## Question: Equifax Exfiltration Response

### Scenario

Same 2017 Equifax setup. After downloading PII, attackers packaged it and exfiltrated over an encrypted C2 channel to external servers.


### Tactics Used (Aligned with MITRE ATT&CK)
- **Initial Access**: SQL Injection
- **Execution**: Ran malicious code
- **Collection**: Stole user data and source code
- **Exfiltration**: Transferred data externally

### Security Controls
- **Web Application Firewall (WAF) with SQL Injection Rules**: Protects web applications.
- **SQL Injection Prevention**: Blocks SQL injection attacks.
- **AES-256 Encryption**: Secures data at rest.
- **TLS 1.3 Encryption**: Secures data in transit.
- **Security Information and Event Management (SIEM) with Real-Time Log Analysis**: Analyzes logs.
- **Incident Response Team (IRT)**: Coordinates response.
- **Multi-Factor Authentication (MFA) with Biometric Authentication**: Secures access.
- **Network Segmentation**: Isolates systems.
- **Role-Based Access Control (RBAC)**: Restricts permissions.
- **Automated Patch Management**: Patches flaws.
- **User Behavior Analytics (UBA)**: Detects anomalies.
- **Intrusion Detection System (IDS)**: Detects threats.


### Question

Which combination of controls, leveraging DiD, ASA, and ZTA, best detects exfiltration attempts and automates  containment?

### Options

**1.**

* **Prevent (DiD)**: WAF + Patch Management System
* **Detect (ASA)**: Behavioral Analytics + SIEM with CloudWatch Logs
* **Prevent Access (ZTA)**: Micro-Segmentation + Encrypted Data Channels
* **Respond (ASA)**: SOAR Playbooks + Certificate Management

**2.**

* **Prevent (DiD)**: WAF + Automated Patching
* **Detect (ASA)**: SIEM Alerts + IDS with valid certificates
* **Prevent Access (ZTA)**: Network Segmentation + Certificate Management
* **Respond (ASA)**: IRT Coordination + Encrypted Data Channels

**3.**

* **Prevent (DiD)**: Patch Management System + Vulnerability Scanning
* **Detect (ASA)**: Behavioral Analytics + CloudWatch Logs
* **Prevent Access (ZTA)**: Micro-Segmentation + WAF
* **Respond (ASA)**: Automated Patching + SOAR Playbooks

**4.**

* **Prevent (DiD)**: Encrypted Data Channels + WAF
* **Detect (ASA)**: Behavioral Analytics + SIEM
* **Prevent Access (ZTA)**: Network Segmentation + IDS with valid certificates
* **Respond (ASA)**: SOAR Playbooks + Automated Patching

**5.**

* **Prevent (DiD)**: WAF + Network Segmentation
* **Detect (ASA)**: SIEM + Behavioral Analytics
* **Prevent Access (ZTA)**: Micro-Segmentation + Certificate Management
* **Respond (ASA)**: IRT Coordination + Dynamic Network Policies

**6.**

* **Prevent (DiD)**: WAF + Automated Patching
* **Detect (ASA)**: Behavioral Analytics + SIEM with CloudWatch Logs
* **Prevent Access (ZTA)**: Micro-Segmentation + Encrypted Data Channels
* **Respond (ASA)**: SOAR Playbooks + Certificate Management

---

## Question: SolarWinds Defense Evasion Counter

### Scenario

Same 2020 SolarWinds pipeline: Build → Update → Client subnets; signed artifacts; no tamper checks. Attackers forged  code-signing to evade signature validation.

### Tactics Used

* **Defense Evasion (T1553.002)**: Code Signing Forgery

### Security Controls

* **Code Signing Verification**
* **Tamper Detection**
* **Audit Logging**
* **Behavioral Monitoring**
* **Continuous Validation**
* **Network Segmentation**
* **Micro-Segmentation**
* **Encrypted Communication**
* **SOAR Playbooks**
* **Dynamic Network Policies**

### Question

Which combination of controls, leveraging DiD, ASA, and ZTA, best counters code-signing forgery and surfaces tampering?

### Options

**1.**

* **Prevent (DiD)**: Code Signing Verification + Tamper Detection
* **Detect (ASA)**: Audit Logging + Behavioral Monitoring
* **Prevent Access (ZTA)**: Micro-Segmentation + Continuous Validation
* **Respond (ASA)**: SOAR Playbooks + Dynamic Network Policies

**2.**

* **Prevent (DiD)**: Tamper Detection + Continuous Validation
* **Detect (ASA)**: Behavioral Monitoring + Anomaly Detection in Builds
* **Prevent Access (ZTA)**: Network Segmentation + Code Signing Verification
* **Respond (ASA)**: Encrypted Communication + IRT Coordination

**3.**

* **Prevent (DiD)**: Code Signing Verification + Network Segmentation
* **Detect (ASA)**: Audit Logging + Anomaly Detection in Builds
* **Prevent Access (ZTA)**: Micro-Segmentation + Encrypted Communication
* **Respond (ASA)**: Dynamic Network Policies + SOAR Playbooks

**4.**

* **Prevent (DiD)**: Tamper Detection + Audit Logging
* **Detect (ASA)**: Behavioral Monitoring + Continuous Validation
* **Prevent Access (ZTA)**: Code Signing Verification + Micro-Segmentation
* **Respond (ASA)**: SOAR Playbooks + Certificate Management

**5.**

* **Prevent (DiD)**: Code Signing Verification + Automated Integrity Checks
* **Detect (ASA)**: Anomaly Detection in Builds + Audit Logging
* **Prevent Access (ZTA)**: Micro-Segmentation + Least Privilege Access
* **Respond (ASA)**: Dynamic Network Policies + Encrypted Data Channels

**6.**

* **Prevent (DiD)**: Tamper Detection + Behavioral Monitoring
* **Detect (ASA)**: Audit Logging + Anomaly Detection in Builds
* **Prevent Access (ZTA)**: Continuous Validation + Network Segmentation
* **Respond (ASA)**: SOAR Playbooks + IRT Coordination

---

## Question: SolarWinds Exfiltration Prevention

### Scenario

Same SolarWinds pipeline. Attackers exfiltrated stolen credentials and backdoor-ed artifacts from client subnets back to their C2 infrastructure.

### Tactics Used

* **Exfiltration (T1041)**: Exfiltration Over C2

### Security Controls

* **Encrypted Updates**
* **Dynamic Network Policies**
* **Audit Logging**
* **Behavioral Monitoring**
* **Network Segmentation**
* **SOAR Playbooks**
* **Continuous Validation**
* **Encrypted Data Channels**
* **Micro-Segmentation**
* **Code Signing Verification**

### Question

Which combination of controls, leveraging DiD, ASA, and ZTA, best prevents exfiltration of malicious artifacts to external hosts?

### Options

**1.**

* **Prevent (DiD)**: Code Signing Verification + Encrypted Updates
* **Detect (ASA)**: Audit Logging + Behavioral Monitoring
* **Prevent Access (ZTA)**: Micro-Segmentation + Continuous Validation
* **Respond (ASA)**: Dynamic Network Policies + SOAR Playbooks

**2.**

* **Prevent (DiD)**: Encrypted Updates + Network Segmentation
* **Detect (ASA)**: Anomaly Detection in Builds + Audit Logging
* **Prevent Access (ZTA)**: Encrypted Data Channels + Micro-Segmentation
* **Respond (ASA)**: SOAR Playbooks + IRT Coordination

**3.**

* **Prevent (DiD)**: Tamper Detection + Dynamic Network Policies
* **Detect (ASA)**: Behavioral Monitoring + Audit Logging
* **Prevent Access (ZTA)**: Continuous Validation + Code Signing Verification
* **Respond (ASA)**: Encrypted Data Channels + SOAR Playbooks

**4.**

* **Prevent (DiD)**: Network Segmentation + Encrypted Updates
* **Detect (ASA)**: Audit Logging + Anomaly Detection in Builds
* **Prevent Access (ZTA)**: Micro-Segmentation + Encrypted Communication
* **Respond (ASA)**: SOAR Playbooks + Dynamic Network Policies

**5.**

* **Prevent (DiD)**: Code Signing Verification + Encrypted Data Channels
* **Detect (ASA)**: Behavioral Monitoring + Audit Logging
* **Prevent Access (ZTA)**: Continuous Validation + Micro-Segmentation
* **Respond (ASA)**: Dynamic Network Policies + Certificate Management

**6.**

* **Prevent (DiD)**: Code Signing Verification + Encrypted Updates
* **Detect (ASA)**: Audit Logging + Behavioral Monitoring
* **Prevent Access (ZTA)**: Continuous Validation + Micro-Segmentation
* **Respond (ASA)**: Dynamic Network Policies + SOAR Playbooks

---

## Question: Capital One Collection Block

### Scenario

Same Capital One SSRF-based breach. After SSRF and token theft, attackers attempted to download large volumes of S3 objects containing sensitive customer data.

### Tactics Used

* **Collection (T1005)**: Data from Local System

### Security Controls

* **Data Encryption at Rest** (S3 SSE-KMS)
* **WAF Rule Validation**
* **IAM Role Hardening**
* **Network Segmentation**
* **Monitoring & Logging**
* **Behavioral Analytics**
* **Continuous Verification**
* **Adaptive WAF Rules**
* **Automated IAM Adjustment**
* **Encrypted Data Channels**

### Question

Which combination of controls, leveraging DiD, ASA, and ZTA, best prevents unauthorized mass downloads of S3 data?

### Options

**1.**

* **Prevent (DiD)**: Data Encryption at Rest + WAF Rule Validation
* **Detect (ASA)**: Monitoring & Logging + Behavioral Analytics
* **Prevent Access (ZTA)**: IAM Role Hardening + Network Segmentation
* **Respond (ASA)**: Automated IAM Adjustment + Adaptive WAF Rules

**2.**

* **Prevent (DiD)**: WAF Rule Validation + Data Encryption at Rest
* **Detect (ASA)**: Behavioral Analytics + CloudWatch Logs
* **Prevent Access (ZTA)**: Continuous Verification + Micro-Segmentation
* **Respond (ASA)**: Dynamic Network Policies + Automated IAM Adjustment

**3.**

* **Prevent (ZTA)**: Continuous Verification + IAM Role Hardening
* **Detect (ASA)**: GuardDuty + Behavioral Analytics
* **Prevent Access (DiD)**: Network Segmentation + WAF Rule Validation
* **Respond (ASA)**: Automated IAM Adjustment + Certificate Management

**4.**

* **Prevent (DiD)**: Data Encryption at Rest + IAM Role Hardening
* **Detect (ASA)**: GuardDuty + Monitoring & Logging
* **Prevent Access (ZTA)**: Micro-Segmentation + Encrypted Data Channels
* **Respond (ASA)**: Automated IAM Adjustment + SOAR Playbooks

**5.**

* **Prevent (ASA)**: Behavioral Analytics + Adaptive WAF Rules
* **Detect (DiD)**: GuardDuty + CloudWatch Logs
* **Prevent Access (ZTA)**: IAM Role Hardening + Continuous Verification
* **Respond (ASA)**: Automated IAM Adjustment + Dynamic Network Policies

**6.**

* **Prevent (DiD)**: Data Encryption at Rest + IAM Role Hardening
* **Detect (ASA)**: Behavioral Analytics + Monitoring & Logging
* **Prevent Access (ZTA)**: Micro-Segmentation + Network Segmentation
* **Respond (ASA)**: Automated IAM Adjustment + Adaptive WAF Rules

---

## Question: Capital One Discovery Detection

### Scenario

Same Capital One breach. Attackers first scanned S3 buckets and attempted directory probes to find sensitive objects, generating unusual access patterns.

### Tactics Used

* **Discovery (T1083)**: File and Directory Discovery

### Security Controls

* **Monitoring & Logging** (CloudWatch + GuardDuty)
* **Behavioral Analytics**
* **WAF Rule Validation**
* **Network Segmentation**
* **Continuous Verification**
* **Automated IAM Adjustment**
* **Adaptive WAF Rules**
* **Data Encryption at Rest**
* **Micro-Segmentation**
* **SOAR Playbooks**

### Question

Which combination of controls, leveraging DiD, ASA, and ZTA, best detects bucket-scanning activity and prevents enumeration?

### Options

**1.**

* **Prevent (DiD)**: WAF Rule Validation + Network Segmentation
* **Detect (ASA)**: Monitoring & Logging + Behavioral Analytics
* **Prevent Access (ZTA)**: Continuous Verification + IAM Role Hardening
* **Respond (ASA)**: Automated IAM Adjustment + Adaptive WAF Rules

**2.**

* **Prevent (DiD)**: Network Segmentation + Data Encryption at Rest
* **Detect (ASA)**: GuardDuty + CloudWatch Logs
* **Prevent Access (ZTA)**: Micro-Segmentation + Continuous Verification
* **Respond (ASA)**: SOAR Playbooks + Automated IAM Adjustment

**3.**

* **Prevent (DiD)**: WAF Rule Validation + Network Segmentation
* **Detect (ASA)**: GuardDuty + Behavioral Analytics
* **Prevent Access (ZTA)**: Continuous Verification + IAM Role Hardening
* **Respond (ASA)**: SOAR Playbooks + Automated IAM Adjustment

**4.**

* **Prevent (DiD)**: WAF Rule Validation + Automated IAM Adjustment
* **Detect (ASA)**: GuardDuty + Behavioral Analytics
* **Prevent Access (ZTA)**: Continuous Verification + Network Segmentation
* **Respond (ASA)**: Adaptive WAF Rules + SOAR Playbooks

**5.**

* **Prevent (ZTA)**: Continuous Verification + WAF Rule Validation
* **Detect (ASA)**: Monitoring & Logging + Behavioral Analytics
* **Prevent Access (DiD)**: IAM Role Hardening + Micro-Segmentation
* **Respond (ASA)**: Automated IAM Adjustment + Dynamic Network Policies

**6.**

* **Prevent (DiD)**: WAF Rule Validation + Data Encryption at Rest
* **Detect (ASA)**: Behavioral Analytics + Monitoring & Logging
* **Prevent Access (ZTA)**: IAM Role Hardening + Micro-Segmentation
* **Respond (ASA)**: Dynamic WAF Rules + Certificate Management

---

## Question: Capital One Lateral Movement Prevention

### Scenario

Same Capital One breach. After SSRF token theft, attackers attempted to use the same credentials to pivot from the web tier into internal application servers and other EC2 instances in the VPC.

### Tactics Used

* **Lateral Movement (T1021.003)**: Use Valid Accounts

### Security Controls

* **Network Segmentation / Micro-Segmentation**
* **WAF Rule Validation**
* **IAM Role Hardening**
* **Continuous Verification**
* **GuardDuty**
* **Behavioral Analytics**
* **Adaptive WAF Rules**
* **Automated IAM Adjustment**
* **Encrypted Data Channels**
* **SOAR Playbooks**

### Question

Which combination of controls, leveraging DiD, ASA, and ZTA, best prevents lateral movement of stolen credentials within the VPC?

### Options

**1.**

* **Prevent (DiD)**: WAF Rule Validation + Network Segmentation
* **Detect (ASA)**: GuardDuty + Behavioral Analytics
* **Prevent Access (ZTA)**: IAM Role Hardening + Continuous Verification
* **Respond (ASA)**: Automated IAM Adjustment + SOAR Playbooks

**2.**

* **Prevent (DiD)**: Network Segmentation + Micro-Segmentation
* **Detect (ASA)**: Monitoring & Logging + GuardDuty
* **Prevent Access (ZTA)**: IAM Role Hardening + Continuous Verification
* **Respond (ASA)**: Adaptive WAF Rules + Automated IAM Adjustment

**3.**

* **Prevent (DiD)**: Micro-Segmentation + WAF Rule Validation
* **Detect (ASA)**: GuardDuty + Behavioral Analytics
* **Prevent Access (ZTA)**: Continuous Verification + IAM Role Hardening
* **Respond (ASA)**: Automated IAM Adjustment + Dynamic Network Policies

**4.**

* **Prevent (DiD)**: Network Segmentation + Continuous Verification
* **Detect (ASA)**: GuardDuty + CloudWatch Logs
* **Prevent Access (ZTA)**: IAM Role Hardening + Encrypted Data Channels
* **Respond (ASA)**: SOAR Playbooks + Automated IAM Adjustment

**5.**

* **Prevent (DiD)**: Network Segmentation + IAM Role Hardening
* **Detect (ASA)**: GuardDuty + Behavioral Analytics
* **Prevent Access (ZTA)**: Micro-Segmentation + Continuous Verification
* **Respond (ASA)**: Adaptive WAF Rules + Automated IAM Adjustment

**6.**

* **Prevent (DiD)**: WAF Rule Validation + Network Segmentation
* **Detect (ASA)**: Monitoring & Logging + Behavioral Analytics
* **Prevent Access (ZTA)**: Micro-Segmentation + IAM Role Hardening
* **Respond (ASA)**: Automated IAM Adjustment + SOAR Playbooks

---

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

### Security Controls

* **Patch Management System** (automated update orchestration)
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

---

## Question: Equifax Defense Evasion & Discovery

### Scenario

In 2017, an Equifax-style environment on AWS had: an Apache Struts EC2 web server in a public subnet behind an ELB; RDS
PostgreSQL with PII in a private subnet; Route 53 DNS; misconfigured AWS Inspector scans; a disabled GuardDuty IDS (
expired certs); no micro-segmentation; CloudWatch→SIEM; AWS Systems Manager available for patching. Attackers exploited
CVE-2017-5638, disabled IDS, scanned for credentials, and surveyed network topology undetected.

### Tactics Used

* **Defense Evasion (T1562.001)**: Disable or Impair Defenses
* **Discovery (T1087)**: Account and Network Discovery

### Security Controls

* Patch Management System
* Automated Patching
* WAF
* IDS with valid certificates
* Vulnerability Scanning
* Network Segmentation

### Question

Which combination of controls best counters both Defense Evasion and Discovery in this breach?

### Options

**1.**

* **Prevent (DiD)**: Patch Management System + Automated Patching
* **Detect (ASA)**: IDS with valid certificates + Behavioral Analytics
* **Prevent Access (ZTA)**: Network Segmentation + WAF
* **Respond (ASA)**: SOAR Playbooks + CloudWatch Alerting

**2.**

* **Prevent (DiD)**: Automated Patching + WAF
* **Detect (ASA)**: Behavioral Analytics + IDS with valid certificates
* **Prevent Access (ZTA)**: Micro-segmentation + Encrypted Data in Transit
* **Respond (ASA)**: IRT Coordination + Certificate Management

**3.**

* **Prevent (DiD)**: Patch Management System + Vulnerability Scanning
* **Detect (ASA)**: IDS with valid certificates + Automated Patching
* **Prevent Access (ZTA)**: Network Segmentation + WAF
* **Respond (ASA)**: SOAR Playbooks + Behavioral Analytics

**4.**

* **Prevent (DiD)**: WAF + Vulnerability Scanning
* **Detect (ASA)**: CloudWatch Logs + Behavioral Analytics
* **Prevent Access (ZTA)**: Encrypted Data in Transit + Patch Management System
* **Respond (ASA)**: SOAR Playbooks + Audit Logging

**5.**

* **Prevent (DiD)**: Automated Patching + IDS with valid certificates
* **Detect (ASA)**: SIEM + Vulnerability Scanning
* **Prevent Access (ZTA)**: Micro-segmentation + Certificate Management
* **Respond (ASA)**: Behavioral Analytics + IRT Coordination

**6.**

* **Prevent (DiD)**: Patch Management System + WAF
* **Detect (ASA)**: CloudWatch Logs + IDS with valid certificates
* **Prevent Access (ZTA)**: Network Segmentation + Automated Patching
* **Respond (ASA)**: SOAR Playbooks + Behavioral Analytics

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

Which combination of controls best prevents SSRF, detects token misuse, restricts S3 access, and responds to
exfiltration?

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

---

## Linux Basics

#### Question: The Linux kernel’s Completely Fair Scheduler (CFS) guarantees that a process pinned to a specific CPU core will never be preempted by another process, even if the latter has a higher priority, due to the per-CPU runqueue design. (False)

The Completely Fair Scheduler (CFS) is the default process scheduler in the Linux kernel, designed to fairly allocate CPU time among running processes. While it uses a per-CPU runqueue design—where each CPU core maintains its own queue of runnable processes—this does not mean a process pinned to a specific core is immune to preemption.

- **Per-CPU Runqueues**: Each core manages its own runqueue to reduce contention and improve scalability. A process pinned to a core (via CPU affinity) will only run on that core.
- **Preemption**: CFS allows preemption based on priority and fairness. It uses a "virtual runtime" metric to track how much CPU time a process has consumed. If a higher-priority process (one with less virtual runtime or an explicitly higher priority) becomes runnable on the same core, it can preempt the current process.
- **Pinning Limitation**: Pinning restricts a process to a specific core but doesn’t disable the scheduler’s ability to switch between processes on that core.

Thus, the statement is **false**: CFS does not guarantee that a pinned process will never be preempted by a higher-priority process on the same core.

---

#### Question 2: In containerized environments using overlayfs, a write operation to a file in the lower layer directly modifies the original file, bypassing the upper layer, unless explicitly configured otherwise. (False)

Overlayfs is a union filesystem commonly used in containerized environments (e.g., Docker) to manage layered storage. It combines a read-only **lower layer** (the base image) and a writable **upper layer** (for container-specific changes) into a single merged view.

- **How Writes Work**: When a file in the lower layer is modified, overlayfs employs a copy-on-write (CoW) mechanism. The original file is copied to the upper layer, and the write operation modifies this copy, leaving the lower layer intact.
- **Read-Only Lower Layer**: The lower layer is inherently read-only in typical container setups, ensuring the base image remains unchanged for reuse across multiple containers.
- **No Direct Modification**: There’s no default behavior or configuration in overlayfs that allows writes to directly alter the lower layer, bypassing the upper layer.

The statement is **false**: Write operations do not modify the original file in the lower layer; changes are always applied to the upper layer via CoW.

---

#### Question 3: The Linux kernel’s handling of Non-Maskable Interrupts (NMIs) allows them to be deferred to a later execution context, such as a softirq, to avoid disrupting critical kernel operations. (False)

Non-Maskable Interrupts (NMIs) are critical interrupts in the Linux kernel, typically triggered by severe hardware events (e.g., memory errors or watchdog timeouts), and they differ from regular interrupts in key ways.

- **Immediate Execution**: NMIs cannot be masked or ignored by the CPU. When an NMI occurs, it interrupts the current execution—whether in user space or kernel space, even within critical sections—and its handler runs immediately.
- **No Deferral Mechanism**: Unlike regular interrupts, which can be deferred to softer contexts like softirqs or tasklets, NMIs lack a deferral mechanism. Their handlers must execute in the interrupt context right away.
- **Design Implication**: Because NMIs can disrupt critical operations, their handlers are kept minimal and carefully written to avoid instability.

The statement is **false**: NMIs cannot be deferred to a later context like a softirq; they are handled immediately.

---

#### Question 4: Docker’s use of user namespaces enables a container to run as root within its isolated environment while mapping to an unprivileged user on the host, preventing direct access to host-level privileged operations. (True)

User namespaces are a Linux kernel feature that Docker uses to isolate user and group ID mappings, enhancing container security.

- **Inside the Container**: A process can run as root (UID 0) within the container’s user namespace, giving it administrative privileges in that isolated environment.
- **Host Mapping**: On the host, this container root is mapped to an unprivileged UID (e.g., 100000) via the user namespace configuration. This mapping ensures that the process has no privileged access outside the container.
- **Security Benefit**: Even if the process escapes the container, it operates as an unprivileged user on the host, unable to perform actions like modifying system files or accessing restricted resources.

The statement is **true**: Docker’s use of user namespaces allows a container to run as root internally while mapping to an unprivileged host user, preventing privileged host operations.

---

#### Question 5: The Linux kernel’s memory management subsystem allows the slab allocator to dynamically resize its caches at runtime to accommodate varying object sizes, improving memory utilization without requiring a reboot. (False)

The slab allocator is a Linux kernel memory management system that caches fixed-size objects (e.g., inodes, dentries) to optimize allocation and reduce fragmentation.

- **Fixed-Size Caches**: Each slab cache is created for a specific object size. Once established, the cache’s size is static and cannot be resized at runtime to handle different object sizes.
- **Dynamic Adjustments**: While the kernel can create or destroy slab caches as needed, resizing an existing cache to accommodate varying object sizes isn’t supported without altering the kernel code or reloading modules—operations that typically require a reboot or recompilation.
- **Purpose**: The slab allocator improves memory utilization by reusing fixed-size slots, but its design doesn’t include runtime resizing of caches.

The statement is **false**: The slab allocator does not dynamically resize its caches at runtime for varying object sizes.


---


---

### **Security Incident Analysis Master Table**  
| **Scenario**                     | **Control Function**       | **Correct Answer (Controls)**           | **Why Correct? (Official Explanation)**                                                                 | **Why Alternatives Fail**                                                                                                 | **Real-World Lesson**                                                                 |  
|----------------------------------|----------------------------|-----------------------------------------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------|  
| **Equifax Exfiltration Response** | **Prevent (DiD)**          | WAF + Automated Patch Management        | • Blocks SQLi and exploits                                                                             | ❌ *Opt 3/4/5:* Missing WAF for SQLi prevention; encryption irrelevant to exfil                                        | • SSRF allowed token theft → exfiltration of 143M records                            |  
|                                  | **Detect (ASA)**           | Behavioral Analytics + SIEM             | • Flags outbound data transfers                                                                        | ❌ *Opt 2/4:* IDS expired; CloudWatch lacks UEBA for anomaly detection                                                 | • Disabled GuardDuty missed exfil alerts for 76 days                                 |  
|                                  | **Prevent Access (ZTA)**   | Micro-Seg + Encrypted Channels          | • Hinders exfil channels                                                                               | ❌ *Opt 1/6:* "Network Segmentation" too broad; lacks micro-seg precision                                              | • No micro-segmentation allowed unfettered network access                            |  
|                                  | **Respond (ASA)**          | SOAR + Certificate Management           | • Locks down communications                                                                            | ❌ *Opt 3:* Automated patching irrelevant to response                                                                   | • Manual processes delayed C2 channel shutdown                                       |  
| **SolarWinds Defense Evasion**   | **Prevent (DiD)**          | Code Signing + Network Segmentation     | • Keeps tampered binaries out                                                                          | ❌ *Opt 1/4:* Tamper detection reactive; least privilege doesn’t prevent forgery                                       | • Weak build-server passwords allowed code-signing compromise                        |  
|                                  | **Detect (ASA)**           | Audit Logs + Anomaly Detection          | • Exposes forgery in builds                                                                            | ❌ *Opt 2:* Behavioral monitoring alone misses signature anomalies                                                     | • No audit checks allowed backdoored binaries for 9+ months                          |  
|                                  | **Prevent Access (ZTA)**   | Micro-Seg + Encrypted Comm              | • Denies bypass routes                                                                                 | ❌ *Opt 5:* Continuous validation ≠ encryption; no network controls                                                    | • Minimal segmentation enabled lateral evasion                                       |  
|                                  | **Respond (ASA)**          | SOAR + Dynamic Policies                 | • Isolates threats                                                                                     | ❌ *Opt 6:* IRT coordination lacks automation speed                                                                     | • Slow response let attackers maintain presence                                      |  
| **SolarWinds Exfiltration Prev** | **Prevent (DiD)**          | Code Signing + Encrypted Updates        | • Stops payload leaks                                                                                  | ❌ *Opt 1/2:* Network segmentation alone can’t stop encrypted exfil                                                    | • Unencrypted updates exposed artifacts to interception                              |  
|                                  | **Detect (ASA)**           | Audit Logging + Behavioral Mon          | • Catches exfil attempts                                                                               | ❌ *Opt 4:* Anomaly detection in builds ≠ exfil detection                                                               | • Behavioral monitoring disabled; missed C2 traffic                                 |  
|                                  | **Prevent Access (ZTA)**   | Continuous Val + Micro-Seg              | • Blocks staging of malicious artifacts                                                                | ❌ *Opt 3:* Continuous Val + Code Signing redundant; no segmentation                                                   | • Flat network allowed attackers to stage data from client subnets                   |  
|                                  | **Respond (ASA)**          | Dynamic Policies + SOAR                 | • Automates containment                                                                                | ❌ *Opt 5:* Certificate management irrelevant to response                                                              | • Delayed isolation let exfiltration continue for weeks                              |  
| **Capital One Collection Block** | **Prevent (DiD)**          | Data Encryption + IAM Hardening         | • Encrypts data; restricts S3 access                                                                   | ❌ *Opt 1/3:* WAF irrelevant to data access; network segmentation too coarse                                           | • Overly permissive IAM role allowed access to 100+ S3 buckets                      |  
|                                  | **Detect (ASA)**           | GuardDuty + Monitoring & Logging        | • Catches bulk access patterns                                                                         | ❌ *Opt 6:* Behavioral Analytics + Monitoring lacks GuardDuty’s S3-specific alerts                                    | • CloudWatch alerts misconfigured; missed mass download patterns                    |  
|                                  | **Prevent Access (ZTA)**   | Micro-Seg + Encrypted Channels          | • Limits credential scope                                                                              | ❌ *Opt 2:* Continuous Verif + Micro-Seg duplicates ZTA; no encryption                                                 | • No micro-segmentation let attackers traverse network                               |  
|                                  | **Respond (ASA)**          | Auto IAM Adjust + SOAR                  | • Blocks further attempts                                                                              | ❌ *Opt 5:* Dynamic Network Policies slow without IAM revocation                                                       | • Manual IAM changes took hours; attackers exfiltrated 30GB                         |  
| **Capital One Discovery Detect** | **Prevent (DiD)**          | WAF + Data Encryption                   | • Blocks scans; encrypts data                                                                          | ❌ *Opt 1/3:* Network segmentation alone insufficient; IAM hardening doesn’t prevent discovery                         | • Weak WAF rules allowed S3 bucket scanning                                          |  
|                                  | **Detect (ASA)**           | Behavioral Analytics + Monitoring       | • Flags enumeration patterns                                                                           | ❌ *Opt 4:* GuardDuty without UEBA misses behavioral anomalies                                                         | • GuardDuty active but no UEBA; missed 12M+ probe requests                          |  
|                                  | **Prevent Access (ZTA)**   | IAM Hardening + Micro-Seg               | • Hardens roles; isolates systems                                                                      | ❌ *Opt 2:* Micro-Seg + Continuous Verif lacks IAM context                                                              | • Broad IAM policies enabled credential reuse                                       |  
|                                  | **Respond (ASA)**          | Dynamic WAF + Cert Mgmt                 | • Adapts rules; manages trust                                                                          | ❌ *Opt 6:* IRT Coordination too slow for real-time response                                                            | • Static WAF rules failed to block novel scan patterns                              |  
| **Capital One Lateral Movement** | **Prevent (DiD)**          | Network Seg + Micro-Seg                 | • Isolates workloads                                                                                   | ❌ *Opt 1/3:* WAF irrelevant to lateral movement; Continuous Verif not preventive                                      | • No segmentation allowed pivoting with stolen tokens                               |  
|                                  | **Detect (ASA)**           | Monitoring & Logging + GuardDuty        | • Catches cross-tier attempts                                                                          | ❌ *Opt 5:* GuardDuty + Behavioral Analytics lacks log context                                                         | • CloudWatch logs not fed to GuardDuty; missed lateral movement                     |  
|                                  | **Prevent Access (ZTA)**   | IAM Hardening + Continuous Verif        | • Blocks stolen tokens                                                                                 | ❌ *Opt 4:* IAM Hardening + Encryption doesn’t validate per-request access                                             | • Tokens valid for 6+ hours; allowed extensive pivoting                             |  
|                                  | **Respond (ASA)**          | Adaptive WAF + Auto IAM Adjust          | • Rotates credentials; tunes defenses                                                                  | ❌ *Opt 6:* Auto IAM Adjust + SOAR lacks WAF tuning for active blocking                                                | • Delayed credential rotation let attackers explore VPC                             |  
| **Equifax Defense Evasion**      | **Prevent (DiD)**          | Patch Mgmt + Vuln Scanning              | • Closes flaws; eliminates scan triggers                                                               | ❌ *Opt 1/2:* Automated patching alone misses vuln scanning; WAF irrelevant to defense disabling                       | • Unpatched Struts for 2 months let attackers disable defenses                      |  
|                                  | **Detect (ASA)**           | IDS + Behavioral Analytics              | • Catches defense disabling & recon                                                                    | ❌ *Opt 5/6:* SIEM/Vuln Scanning can’t detect live attacks; expired IDS useless                                        | • GuardDuty offline due to expired certs                                            |  
|                                  | **Prevent Access (ZTA)**   | Network Seg + WAF                       | • Blocks lateral scans                                                                                 | ❌ *Opt 4:* Encryption + Patch Mgmt misaligned; no segmentation                                                        | • Attackers mapped network via RDP scans                                           |  
|                                  | **Respond (ASA)**          | SOAR + CloudWatch Alerting              | • Speeds containment                                                                                   | ❌ *Opt 3:* SOAR + Behavioral Analytics lacks CloudWatch integration                                                   | • Alerts not configured; attackers operated undetected for 78 days                  |  
| **Equifax Multi-Stage**          | **Prevent (DiD)**          | Patch Mgmt + Auto Patching              | • Removes Struts vulnerability                                                                         | ❌ *Opt 1/2/4/5/6:* Rely on WAF alone; miss automated patching for root cause fix                                       | • Unpatched CVE-2017-5638 for 2 months allowed initial access                        |  
|                                  | **Detect (ASA)**           | Behavioral Analytics + SIEM             | • Spots lateral SSH pivot attempts                                                                     | ❌ *Opt 1/5:* Use misconfigured vuln scanning (false negatives); miss behavioral analysis                               | • Expired GuardDuty certs disabled critical alerts                                   |  
|                                  | **Prevent Access (ZTA)**   | Micro-segmentation + WAF                | • Blocks east-west traffic from web to DB                                                              | ❌ *Opt 2:* Encrypts data but doesn’t block SSH pivots                                                                  | • No micro-segmentation allowed direct EC2→RDS access                                |  
|                                  | **Respond (ASA)**          | SOAR + IRT Coordination                 | • Ensures rapid containment                                                                            | ❌ *Opt 4:* Behavioral Analytics ≠ IRT coordination                                                                     | • Slow response allowed 143M records exfiltration                                    |  
| **Equifax Lateral**              | **Prevent (DiD)**          | WAF + Auto Patching                     | • Stops pivot/harvest with micro-seg + TLS                                                            | ❌ *Opt 1/3:* Encryption irrelevant to SSH; WAF misplaced in "Prevent Access"                                           | • GuardDuty offline for 4 months missed pivot detection                              |  
|                                  | **Detect (ASA)**           | CloudWatch + Behavioral Analytics       | • Reveals unusual DB access via UEBA + SIEM                                                           | ❌ *Opt 4:* IDS expired (no alerts); lacks cloud-native context                                                          | • Misconfigured Inspector produced false negatives                                   |  
|                                  | **Prevent Access (ZTA)**   | Micro-segmentation + Cert Mgmt          | • Halts unauthorized connections with segmentation + IDS                                              | ❌ *Opt 2:* "Network segmentation" too broad; allows web→DB traffic                                                     | • Flat network permitted SSH pivots across subnets                                   |  
|                                  | **Respond (ASA)**          | IRT + SOAR                              | • Enables rapid lock-down/forensics                                                                   | ❌ *Opt 5:* IRT + Behavioral Analytics lacks SOAR automation                                                            | • Manual processes delayed containment by 76 days                                    |  
| **SolarWinds Supply Chain**      | **Prevent (DiD)**          | Code Signing + Network Segmentation     | • Blocks tampered builds                                                                               | ❌ *Opt 3:* Network + micro-segmentation alone allows malicious signed binaries                                         | • Weak build-server passwords (`solarwinds123`) compromised pipeline                 |  
|                                  | **Detect (ASA)**           | Audit Logs + Anomaly Detection          | • Catches unauthorized modifications                                                                  | ❌ *Opt 1:* Tamper detection is reactive (post-breach)                                                                  | • No tamper checks allowed backdoored binaries for 9+ months                         |  
|                                  | **Prevent Access (ZTA)**   | Continuous Validation + Least Priv      | • Ensures only genuine artifacts deploy                                                               | ❌ *Opt 4:* Least Privilege + Continuous Val misses network controls                                                    | • Blind trust in signed binaries infected 18,000+ systems                            |  
|                                  | **Respond (ASA)**          | Dynamic Policies + Encrypted Chans      | • Enables rapid containment/rollback                                                                  | ❌ *Opt 6:* Dynamic Policies + IRT lacks encryption to block C2                                                          | • Delayed response allowed attackers to maintain persistence                         |  
| **SolarWinds Lateral**           | **Prevent (DiD)**          | Code Signing + Network Segmentation     | • Blocks pivot to update tier                                                                          | ❌ *Opt 2:* Least Privilege + Encryption can’t stop binary execution                                                    | • Minimal segmentation allowed Build→Update server pivots                            |  
|                                  | **Detect (ASA)**           | Tamper Detection + Behavioral Mon       | • Flags unauthorized backdoor writes                                                                  | ❌ *Opt 3:* Anomaly detection in builds ≠ real-time backdoor detection                                                  | • No integrity checks for system services                                            |  
|                                  | **Prevent Access (ZTA)**   | Micro-seg + Continuous Validation       | • Stops execution of unapproved binaries                                                              | ❌ *Opt 5:* Micro-seg + Encryption doesn’t validate artifacts                                                           | • Attackers installed persistent backdoors in system processes                       |  
|                                  | **Respond (ASA)**          | SOAR + Dynamic Policies                 | • Isolates compromised nodes                                                                          | ❌ *Opt 1:* SOAR + Audit Logging is passive (no isolation)                                                              | • Passive logging failed to catch live attacker movement                             |  
| **Capital One SSRF**             | **Prevent (DiD)**          | WAF Validation + IAM Hardening          | • Stops SSRF and credential overreach                                                                 | ❌ *Opt 3:* Continuous Verif + WAF misses IAM hardening (stolen tokens still work)                                      | • Overly permissive IAM role allowed S3 bucket access                                |  
|                                  | **Detect (ASA)**           | GuardDuty + Behavioral Monitoring       | • Catches metadata misuse                                                                             | ❌ *Opt 4:* Behavioral Mon + CloudWatch lacks GuardDuty’s AWS-specific threat intel                                    | • WAF rules too permissive allowed SSRF to metadata service                          |  
|                                  | **Prevent Access (ZTA)**   | Continuous Verif + Micro-seg            | • Blocks unauthorized S3 calls                                                                        | ❌ *Opt 2:* Micro-seg + Continuous Verif duplicates functions; lacks IAM context                                        | • No micro-segmentation let attackers traverse network with stolen creds             |  
|                                  | **Respond (ASA)**          | Auto IAM Adjust + Adaptive WAF          | • Throttles/locks exfiltration channels                                                               | ❌ *Opt 5:* Auto IAM Adjust + Cert Mgmt misses WAF tuning for active blocking                                           | • Slow token revocation allowed access to 100+ S3 buckets                            |  
| **DeFi Ponzi Scheme**            | **Prevent (DiD)**          | DID + Homomorphic Encryption            | • Secures investor trust (prevents anonymous scams)                                                   | ❌ *Opt 1/4:* SIEM/UEBA/RF detect but don’t prevent; IDS irrelevant on-chain                                            | • Unaudited contracts promised "guaranteed returns" to 12K+ investors                |  
|                                  | **Detect (ASA)**           | AI-SIEM + UEBA                          | • Identifies Ponzi patterns                                                                           | ❌ *Opt 2/3:* IDS/SOAR not designed for financial anomaly detection                                                     | • No behavioral checks missed abnormal ROI patterns                                  |  
|                                  | **Prevent Access (ZTA)**   | Blockchain Audit + Smart Contract Audit | • Verifies contract legitimacy                                                                      | ❌ *Opt 5:* RF + IDS can’t audit contracts; SOAR not access control                                                     | • Pseudonymous launches enabled fake "high-yield" projects                           |  
|                                  | **Respond (ASA)**          | SOAR + Graph Neural Networks            | • Automates response (aligns with RF-based detection)                                                | ❌ *Opt 6:* HE + GNN not response tools; Blockchain Audit ≠ action                                                      | • Delayed takedowns allowed $34M in losses                                          |  
| **DeFi Money Laundering**        | **Prevent (DiD)**          | DID + Homomorphic Encryption            | • Prevents anonymous wallet creation                                                                  | ❌ *Opt 2/3:* SIEM/UEBA detect but don’t prevent; Blockchain Audit not preventive                                       | • Anonymous wallets enabled ByBit hack ($8M laundered)                              |  
|                                  | **Detect (ASA)**           | AI-SIEM + UEBA                          | • Traces transaction chains in real-time                                                              | ❌ *Opt 4/5:* SOAR/RF not detection tools; IDS useless for cross-DEX analysis                                           | • Traditional tools failed to track wallet-hopping                                  |  
|                                  | **Prevent Access (ZTA)**   | Blockchain Audit + Smart Contract Audit | • Blocks laundering logic in contracts                                                              | ❌ *Opt 6:* RF + IDS can’t restrict contract access; HE not access control                                              | • Weak analytics missed multi-wallet transaction chains                              |  
|                                  | **Respond (ASA)**          | SOAR + Graph Neural Networks            | • Automates tracing/containment (uses GNN-based tracking)                                            | ❌ *Opt 1:* SOAR + GNN correct but other functions flawed                                                                | • Manual investigations allowed obfuscated fund flows                                |  

---

### **TRUE/FALSE Questions**  
| **Question**                                                                                                                                 | **Answer** | **Explanation**                                                                                                                                                                |  
|----------------------------------------------------------------------------------------------------------------------------------------------|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|  
| **The Linux kernel’s CFS guarantees pinned processes avoid preemption by higher-priority tasks on the same core.**                            | **False**  | CFS allows core-local preemption; pinning restricts CPU affinity but not scheduling priority.                                                                                  |  
| **Overlayfs writes directly modify lower-layer files without CoW.**                                                                          | **False**  | Overlayfs always uses copy-on-write: modifies are applied to the upper layer, preserving lower-layer integrity.                                                                |  
| **Linux defers NMIs to softirqs to avoid disrupting critical operations.**                                                                   | **False**  | NMIs cannot be deferred; handlers execute immediately in interrupt context.                                                                                                    |  
| **Docker user namespaces map container-root to unprivileged host users, blocking host-level privileges.**                                    | **True**   | UID remapping (e.g., container root → host UID 100000) confines container escapes to unprivileged host access.                                                                 |  
| **Linux slab allocator dynamically resizes caches at runtime for varying object sizes.**                                                     | **False**  | Slab caches are fixed-size; resizing requires cache destruction/recreation (e.g., via `kmem_cache_destroy()`).                                                                 |  

---

### **Key Elimination Patterns**  
1. **Irrelevant Controls**:  
   - Encryption for lateral movement (SSH/S3 pivots)  
   - IDS for on-chain DeFi fraud  
2. **Misaligned Functions**:  
   - Patching in "Detect" roles  
   - SIEM in "Prevent" roles  
3. **Ignoring Root Causes**:  
   - No auto-patching for Equifax CVE-2017-5638  
   - No IAM least privilege for Capital One  
4. **Framework Violations**:  
   - Zero Trust without per-request verification  
   - Defense-in-Depth with single-layer controls  

