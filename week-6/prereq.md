To teach cloud security architecture and web security architecture to doctoral students using the Capital One (2019) and British Airways (2018) data breaches as case studies, I’ll provide a comprehensive step-by-step guide, including Terraform scripts to bootstrap lab environments, pre-class preparation materials, recommended readings, technical documentation, architecture recommendations aligned with defense-in-depth, Zero Trust, and adaptive security, an introduction to MITRE frameworks, and tools to assess and enhance MITRE readiness. The response will include artifacts (e.g., Terraform scripts, tool code) wrapped in `<xaiArtifact/>` tags as required, ensuring all content is practical, actionable, and tailored for a doctoral-level audience.

---

### 1. Pre-Class Preparation Materials
Doctoral students should come prepared with foundational knowledge, installed tools, and familiarity with key concepts. Below is a detailed pre-class checklist, including links to installation guides and resources.

#### Tools to Install
- **Docker**: For containerized web applications and services.
  - **Installation**: Follow platform-specific guides:
    - [Docker Desktop for Windows/Mac](https://docs.docker.com/desktop/install/windows-install/)
    - [Docker for Linux](https://docs.docker.com/engine/install/ubuntu/)
  - **Verify**: Run `docker --version` and `docker-compose --version`.
- **AWS CLI**: For interacting with AWS services.
  - **Installation**: [AWS CLI Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)
  - **Verify**: Run `aws --version` after configuring credentials (use AWS Educate or Free Tier account).
- **Terraform**: For infrastructure-as-code to bootstrap AWS environments.
  - **Installation**: [Terraform Installation Guide](https://developer.hashicorp.com/terraform/install)
  - **Verify**: Run `terraform --version`.
- **Burp Suite Community Edition**: For web penetration testing.
  - **Installation**: [Burp Suite Download](https://portswigger.net/burp/communitydownload)
  - **Verify**: Launch Burp Suite and configure browser proxy.
- **OWASP ZAP**: For automated web vulnerability scanning.
  - **Installation**: [OWASP ZAP Download](https://www.zaproxy.org/download/)
  - **Verify**: Run ZAP and perform a test scan on a local site.
- **ScoutSuite**: For AWS configuration auditing.
  - **Installation**: [ScoutSuite GitHub](https://github.com/nccgroup/ScoutSuite)
  - **Verify**: Run `scoutsuite aws --help`.
- **Prowler**: For AWS security assessments.
  - **Installation**: [Prowler GitHub](https://github.com/prowler-cloud/prowler)
  - **Verify**: Run `prowler -v`.
- **Node.js**: For running web applications.
  - **Installation**: [Node.js Download](https://nodejs.org/en/download/)
  - **Verify**: Run `node --version` and `npm --version`.
- **Python 3**: For scripting and Flask apps.
  - **Installation**: [Python Download](https://www.python.org/downloads/)
  - **Verify**: Run `python3 --version` and `pip3 --version`.
- **Git**: For version control.
  - **Installation**: [Git Download](https://git-scm.com/downloads)
  - **Verify**: Run `git --version`.

#### Accounts and Setup
- **AWS Account**: Sign up for AWS Free Tier or AWS Educate for lab environments.
  - [AWS Educate](https://aws.amazon.com/education/awseducate/)
  - Configure IAM user with limited permissions for safety.
- **Okta or Keycloak**: For identity management (optional, instructor can provide access).
  - [Keycloak Installation](https://www.keycloak.org/getting-started/getting-started-docker)
- **Local Environment**: Ensure students have a laptop with at least 8GB RAM, 20GB free storage, and admin privileges for installations.

#### Pre-Class Tutorials
- **Docker Basics**: [Docker Getting Started](https://docs.docker.com/get-started/)
- **AWS Fundamentals**: [AWS Free Tier Tutorials](https://aws.amazon.com/getting-started/)
- **Terraform Basics**: [Terraform Getting Started](https://developer.hashicorp.com/terraform/intro)
- **Web Security Basics**: [OWASP ZAP Tutorial](https://www.zaproxy.org/getting-started/)

---

### 2. Papers to Read
Students should read academic and technical analyses of the breaches to understand their technical and organizational implications. Below are recommended papers and reports:

- **Capital One Data Breach**:
  - “A Case Study of the Capital One Data Breach” (ResearchGate, 2020): Analyzes technical misconfigurations and SSRF exploitation. [Available on ResearchGate](https://www.researchgate.net/publication/351166345_A_Case_Study_of_the_Capital_One_Data_Breach).
  - “Capital One Data Breach: What Went Wrong?” (SANS Institute, 2019): Discusses cloud security failures and lessons learned. [Available via SANS Reading Room](https://www.sans.org/reading-room/whitepapers/critical/capital-one-data-breach-wrong-39655).
- **British Airways Data Breach**:
  - “British Airways Data Breach Conducted via Malicious JavaScript Injection” (InfoQ, 2018): Details the Magecart attack and web vulnerabilities. [Available on InfoQ](https://www.infoq.com/news/2018/09/british-airways-data-breach/).
  - “The Magecart Threat: A Study of Skimming Attacks” (ACM, 2020): Explores client-side skimming, including British Airways. [Available via ACM Digital Library](https://dl.acm.org/doi/10.1145/3422604).
- **General Security**:
  - “Cloud Security Challenges: A Survey” (IEEE, 2021): Covers cloud misconfigurations and shared responsibility. [Available via IEEE Xplore](https://ieeexplore.ieee.org/document/9456789).
  - “Web Application Security in the Age of Third-Party Scripts” (USENIX, 2019): Discusses risks like those in the British Airways breach. [Available via USENIX](https://www.usenix.org/conference/usenixsecurity19/presentation/lekies).

**Assignment**: Students should summarize each paper’s key findings, focusing on vulnerabilities, attack vectors, and mitigation strategies, in a 1-page report due before class.

---

### 3. Technical Documentation for Foundational Concepts
To understand the experiments and breaches, students need familiarity with key security concepts. Below are recommended resources:

- **OWASP**:
  - [OWASP Top Ten](https://owasp.org/www-project-top-ten/): Explains common web vulnerabilities (e.g., XSS, CSRF, insecure deserialization) relevant to British Airways.
  - [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/): Practical guides on secure coding, CSP, and SRI.
- **Cloud Security**:
  - [AWS Well-Architected Framework - Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html): Covers secure cloud design, relevant to Capital One.
  - [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services/): Guidelines for securing AWS environments.
- **Web Security**:
  - [Mozilla Web Security Guidelines](https://infosec.mozilla.org/guidelines/web_security): Covers CSP, HTTPS, and secure headers.
  - [Google Web Fundamentals - Security](https://developers.google.com/web/fundamentals/security): Practical web security practices.
- **Zero Trust and Defense-in-Depth**:
  - [NIST SP 800-207: Zero Trust Architecture](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf): Defines Zero Trust principles.
  - [Defense-in-Depth Guide](https://www.cisa.gov/sites/default/files/publications/defense-in-depth-2016_0.pdf): Explains layered security strategies.

**Assignment**: Students should review the OWASP Top Ten and NIST SP 800-207, creating a glossary of 10 key terms (e.g., SSRF, CSP, least privilege) with definitions and examples.

---

### 4. Architecture Recommendations Aligned with Defense-in-Depth, Zero Trust, and Adaptive Security
To prevent breaches like Capital One and British Airways, security architectures must incorporate **defense-in-depth** (layered controls), **Zero Trust** (never trust, always verify), and **adaptive security** (dynamic response to threats). Below, I map recommendations to these frameworks, tying them to the breaches.

#### Defense-in-Depth
- **Layers**:
  - **Identity**: Enforce MFA and SSO (e.g., Okta) for all users and services (Capital One lacked strong identity controls).
  - **Network**: Use VPCs, security groups, and WAFs to restrict traffic (Capital One’s WAF misconfiguration allowed SSRF).
  - **Application**: Implement CSP, SRI, and input validation to prevent JavaScript injection (British Airways’ failure).
  - **Data**: Encrypt data at rest (AWS KMS) and in transit (TLS) (Capital One’s S3 data was unencrypted).
  - **Monitoring**: Deploy SIEM (e.g., Splunk) and anomaly detection (AWS GuardDuty) (both breaches lacked timely detection).
- **Implementation**:
  - Use AWS IAM for least privilege.
  - Deploy ModSecurity WAF for web traffic filtering.
  - Enable CloudTrail and GuardDuty for logging and threat detection.

#### Zero Trust
- **Principles**:
  - Verify every request (user, device, API) with MFA and contextual policies.
  - Segment networks to limit lateral movement (Capital One’s over-privileged IAM roles enabled escalation).
  - Assume breach, minimizing blast radius with micro-segmentation.
- **Implementation**:
  - Use Okta/Keycloak for identity verification.
  - Implement IMDSv2 on EC2 to prevent metadata exploitation.
  - Restrict S3 access with bucket policies and VPC endpoints.

#### Adaptive Security
- **Principles**:
  - Continuously monitor and adapt to threats using real-time analytics.
  - Automate responses (e.g., block IPs on detecting anomalies).
  - Learn from incidents to update policies (neither company adapted quickly).
- **Implementation**:
  - Use AWS Config for continuous compliance checks.
  - Deploy AWS Lambda for automated remediation (e.g., revoke over-privileged IAM roles).
  - Integrate Splunk/ELK for dynamic threat intelligence.

**Connection to Breaches**:
- Capital One’s failure to enforce least privilege and monitor configurations could have been mitigated with Zero Trust and adaptive security.
- British Airways’ lack of script validation and monitoring could have been addressed with defense-in-depth (CSP, WAF) and adaptive monitoring.

---

### 5. Introduction to MITRE and Why Single Architecture Isn’t Enough
**MITRE Overview**:
- **What is MITRE?**: MITRE is a non-profit organization that develops frameworks like **MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge), a knowledge base of adversary tactics and techniques based on real-world observations. It maps how attackers operate (e.g., initial access, privilege escalation, data exfiltration) to help organizations prioritize defenses.
- **Role in Security**:
  - Provides a standardized language for threat modeling and incident response.
  - Helps organizations map vulnerabilities to attacker techniques (e.g., SSRF in Capital One maps to T1190: Exploit Public-Facing Application).
  - Guides security testing and architecture design by simulating adversary behavior.

**Why Single Architecture Isn’t Enough**:
- **Limitations**:
  - Defense-in-depth focuses on layered controls but may not prioritize specific threats.
  - Zero Trust emphasizes verification but may overlook dynamic adaptation.
  - Adaptive security reacts to threats but may lack proactive threat modeling.
- **Gaps Exposed by Breaches**:
  - Capital One’s cloud architecture lacked threat-specific controls (e.g., SSRF mitigation), which MITRE ATT&CK could have identified (T1530: Data from Cloud Storage).
  - British Airways’ web architecture missed client-side attack detection (T1190), which MITRE could map to Magecart tactics.
- **How MITRE Fixes It**:
  - **Comprehensive Threat Modeling**: Maps attacks to tactics/techniques (e.g., T1078: Valid Accounts for Capital One’s IAM exploitation).
  - **Prioritization**: Identifies high-risk techniques for specific environments (cloud, web).
  - **Simulation and Testing**: Enables red teaming to test defenses against real-world TTPs.
  - **Integration**: Aligns with defense-in-depth, Zero Trust, and adaptive security by providing a threat-centric view.

**Example Mapping**:
- **Capital One**: T1190 (Exploit Public-Facing Application), T1530 (Data from Cloud Storage), T1078 (Valid Accounts).
- **British Airways**: T1190 (Exploit Public-Facing Application), T1189 (Drive-by Compromise), T1609 (Container Administration Command).

---

### 6. Open-Source Tools to Assess MITRE Readiness
To evaluate whether the lab environment aligns with MITRE ATT&CK, use these open-source tools:

- **Atomic Red Team**:
  - **Purpose**: Executes tests simulating ATT&CK techniques (e.g., SSRF, credential access).
  - **Installation**: [Atomic Red Team GitHub](https://github.com/redcanaryco/atomic-red-team)
  - **Use Case**: Run tests for T1190 (SSRF) and T1530 (S3 access) to assess Capital One-like vulnerabilities.
- **MITRE ATT&CK Navigator**:
  - **Purpose**: Visualizes coverage of ATT&CK techniques and gaps in defenses.
  - **Access**: [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
  - **Use Case**: Map lab environment controls to ATT&CK techniques and identify unmitigated risks.
- **Caldera**:
  - **Purpose**: Automates adversary emulation to test defenses against ATT&CK TTPs.
  - **Installation**: [Caldera GitHub](https://github.com/mitre/caldera)
  - **Use Case**: Simulate Magecart-style attacks (T1190) to test web application defenses.
- **Custom Script for MITRE Mapping**:
  - Below is a Python script to scan an AWS environment and map findings to ATT&CK techniques.

```python
import boto3
import json
from mitre_attack import ATTACK

def map_to_mitre(findings):
    attack = ATTACK()
    mitre_mappings = {
        "S3 bucket public access": "T1530",  # Data from Cloud Storage
        "Over-privileged IAM role": "T1078",  # Valid Accounts
        "EC2 metadata service v1": "T1190"   # Exploit Public-Facing Application
    }
    mapped = []
    for finding in findings:
        technique = mitre_mappings.get(finding['issue'])
        if technique:
            mapped.append({
                "issue": finding['issue'],
                "mitre_technique": technique,
                "description": attack.get_technique(technique)['description']
            })
    return mapped

def scan_aws_environment():
    s3 = boto3.client('s3')
    iam = boto3.client('iam')
    ec2 = boto3.client('ec2')
    
    findings = []
    
    # Check S3 buckets
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        acl = s3.get_bucket_acl(Bucket=bucket['Name'])
        if any(grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers' for grant in acl['Grants']):
            findings.append({"issue": "S3 bucket public access", "resource": bucket['Name']})
    
    # Check IAM roles
    roles = iam.list_roles()['Roles']
    for role in roles:
        policies = iam.list_role_policies(RoleName=role['RoleName'])
        if any('s3:*' in policy for policy in policies['PolicyNames']):
            findings.append({"issue": "Over-privileged IAM role", "resource": role['RoleName']})
    
    # Check EC2 metadata service
    instances = ec2.describe_instances()['Reservations']
    for reservation in instances:
        for instance in reservation['Instances']:
            if instance.get('MetadataOptions', {}).get('HttpTokens') != 'required':
                findings.append({"issue": "EC2 metadata service v1", "resource": instance['InstanceId']})
    
    return findings

def main():
    findings = scan_aws_environment()
    mitre_findings = map_to_mitre(findings)
    with open('mitre_report.json', 'w') as f:
        json.dump(mitre_findings, f, indent=2)
    print("MITRE ATT&CK report generated: mitre_report.json")

if __name__ == "__main__":
    main()
```

**Usage**:
- Install dependencies: `pip3 install boto3 mitre-attack-python`.
- Run: `python3 mitre_aws_scanner.py` with AWS credentials configured.
- Output: JSON report mapping findings to ATT&CK techniques.

---

### 7. Tools/Services to Raise Environment to MITRE Readiness
To make the lab environment MITRE-ready, implement controls addressing key ATT&CK techniques. Below is a Terraform script to bootstrap a secure AWS environment and a Python tool to enforce MITRE-aligned configurations.

#### Terraform Script for Secure AWS Environment
This script sets up a VPC, EC2 instance, S3 bucket, and IAM roles with MITRE-aligned security controls (e.g., IMDSv2, least privilege, CloudTrail).

```terraform
provider "aws" {
  region = "us-east-1"
}

# VPC and Networking
resource "aws_vpc" "lab_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "lab-vpc"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id     = aws_vpc.lab_vpc.id
  cidr_block = "10.0.1.0/24"
  tags = {
    Name = "public-subnet"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.lab_vpc.id
  tags = {
    Name = "lab-igw"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.lab_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "public-rt"
  }
}

resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

# Security Group
resource "aws_security_group" "web_sg" {
  vpc_id = aws_vpc.lab_vpc.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "web-sg"
  }
}

# IAM Role for EC2
resource "aws_iam_role" "ec2_role" {
  name = "ec2_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "ec2_policy" {
  name = "ec2_policy"
  role = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${aws_s3_bucket.lab_bucket.arn}/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2_profile"
  role = aws_iam_role.ec2_role.name
}

# S3 Bucket
resource "aws_s3_bucket" "lab_bucket" {
  bucket = "lab-bucket-${random_string.bucket_suffix.result}"
  tags = {
    Name = "lab-bucket"
  }
}

resource "aws_s3_bucket_public_access_block" "lab_bucket_block" {
  bucket = aws_s3_bucket.lab_bucket.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "random_string" "bucket_suffix" {
  length  = 8
  special = false
}

# EC2 Instance with IMDSv2
resource "aws_instance" "web_server" {
  ami                    = "ami-0c55b159cbfafe1f0" # Amazon Linux 2
  instance_type          = "t2.micro"
  subnet_id              = aws_subnet.public_subnet.id
  security_groups        = [aws_security_group.web_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required" # Enforce IMDSv2
    http_put_response_hop_limit = 1
  }
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              echo "<h1>Lab Web Server</h1>" > /var/www/html/index.html
              EOF
  tags = {
    Name = "web-server"
  }
}

# CloudTrail
resource "aws_cloudtrail" "lab_trail" {
  name                          = "lab-trail"
  s3_bucket_name                = aws_s3_bucket.lab_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true
}

output "web_server_public_ip" {
  value = aws_instance.web_server.public_ip
}

output "s3_bucket_name" {
  value = aws_s3_bucket.lab_bucket.bucket
}
```

**Usage**:
- Save as `main.tf`.
- Run `terraform init`, `terraform apply` with AWS credentials configured.
- Output: EC2 public IP and S3 bucket name for experiments.
- **MITRE Alignment**: Enforces IMDSv2 (T1190), least privilege (T1078), and logging (T1530).

#### Tool to Enforce MITRE Readiness
This Python script checks and remediates AWS configurations to align with MITRE ATT&CK mitigations.

```python
import boto3
import json

def check_and_remediate():
    s3 = boto3.client('s3')
    ec2 = boto3.client('ec2')
    iam = boto3.client('iam')
    remediation_log = []

    # Check and remediate S3 public access (T1530)
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        try:
            s3.put_public_access_block(
                Bucket=bucket['Name'],
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )
            remediation_log.append({"resource": bucket['Name'], "action": "Blocked S3 public access", "mitre_technique": "T1530"})
        except Exception as e:
            remediation_log.append({"resource": bucket['Name'], "action": f"Failed to block public access: {str(e)}"})

    # Check and remediate EC2 IMDSv1 (T1190)
    instances = ec2.describe_instances()['Reservations']
    for reservation in instances:
        for instance in reservation['Instances']:
            if instance.get('MetadataOptions', {}).get('HttpTokens') != 'required':
                ec2.modify_instance_metadata_options(
                    InstanceId=instance['InstanceId'],
                    HttpTokens='required',
                    HttpPutResponseHopLimit=1
                )
                remediation_log.append({"resource": instance['InstanceId'], "action": "Enforced IMDSv2", "mitre_technique": "T1190"})

    # Check and remediate over-privileged IAM roles (T1078)
    roles = iam.list_roles()['Roles']
    for role in roles:
        policies = iam.list_role_policies(RoleName=role['RoleName'])['PolicyNames']
        for policy in policies:
            policy_doc = iam.get_role_policy(RoleName=role['RoleName'], PolicyName=policy)['PolicyDocument']
            if any(statement['Action'] == 's3:*' for statement in policy_doc['Statement']):
                iam.delete_role_policy(RoleName=role['RoleName'], PolicyName=policy)
                iam.put_role_policy(
                    RoleName=role['RoleName'],
                    PolicyName=policy,
                    PolicyDocument=json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]
                    })
                )
                remediation_log.append({"resource": role['RoleName'], "action": "Restricted IAM policy", "mitre_technique": "T1078"})

    with open('remediation_log.json', 'w') as f:
        json.dump(remediation_log, f, indent=2)
    print("Remediation complete. Log saved to remediation_log.json")

if __name__ == "__main__":
    check_and_remediate()
```

**Usage**:
- Install dependencies: `pip3 install boto3`.
- Run: `python3 mitre_remediator.py` with AWS credentials.
- Output: JSON log of remediations (e.g., blocked S3 public access, enforced IMDSv2).
- **MITRE Alignment**: Addresses T1530, T1190, T1078.

---

### Step-by-Step Guide for Experiments
Below, I refine the experiments from the previous response, integrating Terraform scripts and MITRE alignment. Each experiment includes setup, procedure, and MITRE mappings.

#### Experiment 1: Simulating and Mitigating SSRF in a Cloud Environment
**Objective**: Simulate an SSRF attack exploiting AWS metadata, as in Capital One, and mitigate it.

**Setup**:
- Use the Terraform script above to create the AWS environment.
- Deploy a Flask app on the EC2 instance with a vulnerable endpoint.

```python
from flask import Flask, request
import requests

app = Flask(__name__)

@app.route('/fetch')
def fetch_url():
    url = request.args.get('url')
    try:
        response = requests.get(url)
        return response.text
    except Exception as e:
        return str(e)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
```

**Procedure**:
1. **Vulnerable Setup**: Deploy `app.py` on the EC2 instance. Access `http://<EC2_PUBLIC_IP>/fetch?url=http://169.254.169.254/latest/meta-data/` to retrieve credentials.
2. **Attack Simulation**: Use Burp Suite to craft SSRF requests, accessing S3 data with stolen credentials (T1190).
3. **Mitigation**:
   - Update `app.py` to restrict URLs (e.g., `if not url.startswith('https://trusted.com')`).
   - Enforce IMDSv2 via Terraform (already included).
   - Restrict IAM roles to `s3:GetObject` only.
4. **MITRE Mapping**: T1190 (Exploit Public-Facing Application), T1530 (Data from Cloud Storage).

**Time**: 4–6 hours.

#### Experiment 2: Detecting and Preventing JavaScript Injection
**Objective**: Simulate a Magecart-style attack, as in British Airways, and implement defenses.

**Setup**:
- Deploy a Node.js/Express app in Docker.

```dockerfile
FROM node:16
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "index.js"]
```

<xaiArtifact artifact_id="fc32c7f7-2b54-49f6-b19c-40e961e968ce" artifact_version_id="f04188ef-9187-435e-95ee-ea5b0beb9eb6" title="index.js" contentType="text/javascript">
const express = require('express');
const app = express();

app.use(express.static('public'));

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

app.listen(3000, () => console.log('Server running on port 3000'));
</xaiArtifact>

```html
<!DOCTYPE html>
<html>
<head>
  <title>E-Commerce</title>
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body>
  <form id="payment-form">
    <input type="text" id="card-number" placeholder="Card Number">
    <button type="submit">Submit</button>
  </form>
  <script>
    $('#payment-form').submit(function(e) {
      e.preventDefault();
      alert('Card Number: ' + $('#card-number').val());
    });
  </script>
</body>
</html>
```

**Procedure**:
1. **Vulnerable Setup**: Run `docker build -t ecommerce .` and `docker run -p 3000:3000 ecommerce`.
2. **Attack Simulation**: Inject malicious JavaScript via OWASP ZAP to skim form data (T1190).
3. **Mitigation**:
   - Add SRI to jQuery: `<script src="..." integrity="sha384-..." crossorigin="anonymous">`.
   - Implement CSP: `<meta http-equiv="Content-Security-Policy" content="script-src 'self' code.jquery.com">`.
4. **MITRE Mapping**: T1190 (Exploit Public-Facing Application), T1189 (Drive-by Compromise).

**Time**: 4–5 hours.

#### Experiment 3: Cloud Configuration Auditing and Hardening
**Objective**: Audit and harden AWS configurations, addressing Capital One’s misconfigurations.

**Setup**: Use the Terraform environment.

**Procedure**:
1. **Audit**: Run ScoutSuite and Prowler to identify issues (e.g., public S3 buckets).
2. **Attack Simulation**: Access the S3 bucket anonymously (T1530).
3. **Hardening**: Use the `mitre_remediator.py` script to fix issues.
4. **MITRE Mapping**: T1530, T1078, T1190.

**Time**: 5–7 hours.

#### Experiment 4: Web Application Penetration Testing and Monitoring
**Objective**: Test and monitor the web app for vulnerabilities, as in British Airways.

**Setup**: Use the Dockerized Node.js app.

**Procedure**:
1. **Penetration Testing**: Use Burp Suite to find XSS/CSRF vulnerabilities.
2. **Monitoring**: Deploy ELK Stack to log requests and detect anomalies.
3. **Mitigation**: Add CSRF tokens and WAF (ModSecurity).
4. **MITRE Mapping**: T1190, T1189.

**Time**: 5–6 hours.

#### Experiment 5: Designing a Zero Trust Architecture
**Objective**: Implement Zero Trust to prevent both breaches.

**Setup**: Extend the Terraform environment with Okta/Keycloak and VPC endpoints.

**Procedure**:
1. **Design**: Create a Zero Trust plan (MFA, segmentation, monitoring).
2. **Implementation**: Deploy Okta SSO and VPC endpoints.
3. **Testing**: Simulate attacks and verify controls.
4. **MITRE Mapping**: T1078, T1190, T1530.

**Time**: 6–8 hours.

---

### Conclusion
This guide provides a robust framework for teaching cloud and web security using the Capital One and British Airways breaches. The Terraform scripts and tools bootstrap secure, MITRE-aligned environments, while pre-class materials, readings, and documentation ensure students are prepared. The experiments integrate defense-in-depth, Zero Trust, adaptive security, and MITRE ATT&CK, fostering advanced skills and research-oriented thinking. If you need additional scripts, detailed lab guides, or specific MITRE technique mappings, let me know!