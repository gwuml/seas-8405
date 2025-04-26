# main.tf – Terraform configuration to simulate the Capital One breach scenario

# ---------------------------------------------------------------------------
# 0. Provider Configuration
# ---------------------------------------------------------------------------
# Define the required Terraform provider (AWS) and its version
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

# Configure the AWS provider with a specific region
provider "aws" {
  region = "us-west-2"   # Specifies the AWS region; change if needed for your use case
}

# ---------------------------------------------------------------------------
# 1. SSH Key Management
# ---------------------------------------------------------------------------
# Generate an RSA private key for SSH access
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"      # Algorithm for key generation
  rsa_bits  = 4096       # Key size for security
}

# Create an AWS key pair using the generated public key
resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "my-ec2-key"                                 # Name of the key pair in AWS
  public_key = tls_private_key.ec2_key.public_key_openssh   # Public key from the generated private key
}

# Save the private key locally with secure permissions
resource "local_file" "private_key" {
  content         = tls_private_key.ec2_key.private_key_pem  # Private key content
  filename        = "${path.module}/my-ec2-key.pem"          # Local file path
  file_permission = "0400"                                   # Read-only for owner
}

# Delete the private key file when resources are destroyed
resource "null_resource" "delete_key" {
  triggers = {
    key_file = local_file.private_key.filename               # Track the private key file
  }

  provisioner "local-exec" {
    when    = destroy                                        # Run on destroy
    command = "rm -f ${self.triggers.key_file}"              # Delete the private key file
  }
}

# ---------------------------------------------------------------------------
# 2. Security Group Configuration
# ---------------------------------------------------------------------------
# Data source to get the local public IP address for security group rules
data "http" "local_ip" {
  url = "http://ipv4.icanhazip.com"                          # Fetches the public IP of the host running Terraform
}

# Create a security group allowing SSH and HTTP from the local IP
resource "aws_security_group" "allow_local_ip" {
  name        = "allow_local_ip"                             # Security group name
  description = "Allow inbound SSH and HTTP from local IP"   # Description for clarity

  # Allow SSH (port 22) from the local IP
  ingress {
    description = "SSH from local IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
#     cidr_blocks = ["${chomp(data.http.local_ip.body)}/32"]   # Restrict to the host's public IP
    cidr_blocks = ["${chomp(data.http.local_ip.response_body)}/32"]
  }

  # Allow HTTP (port 80) from the local IP
  ingress {
    description = "HTTP from local IP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
#     cidr_blocks = ["${chomp(data.http.local_ip.body)}/32"]   # Restrict to the host's public IP
    cidr_blocks = ["${chomp(data.http.local_ip.response_body)}/32"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"                                       # All protocols
    cidr_blocks = ["0.0.0.0/0"]                              # Allow all outbound traffic
  }

  tags = {
    Name = "allow_local_ip"                                  # Tag for identification
  }
}

# ---------------------------------------------------------------------------
# 3. Vulnerable S3 Bucket
# ---------------------------------------------------------------------------
# Create an S3 bucket to simulate the target of data exfiltration
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "seas8405-week6-lab1-vulnerable-s3"        # Unique bucket name
  force_destroy = true                                       # Allows Terraform to delete the bucket even if it contains objects
  tags = {
    Name = "seas8405-week6-lab1-vulnerable-s3"               # Tag for identification
  }
}

# Set ownership controls to ensure the bucket owner has control over objects
resource "aws_s3_bucket_ownership_controls" "vulnerable_bucket_ownership" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"                # Bucket owner retains control over objects
  }
}

# Set the bucket ACL to private, though it’s still accessible via IAM permissions
resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket      = aws_s3_bucket.vulnerable_bucket.id
  acl         = "private"                                    # Restricts public access
  depends_on  = [aws_s3_bucket_ownership_controls.vulnerable_bucket_ownership]  # Ensures ownership controls are applied first
}

# Upload a sample file to the bucket to simulate sensitive data
resource "aws_s3_object" "sample_object" {
  bucket  = aws_s3_bucket.vulnerable_bucket.bucket
  key     = "sample.txt"                                     # File name in the bucket
  content = "Sensitive Test Data"                            # Content of the sample file
}

# ---------------------------------------------------------------------------
# 4. IAM Role and Policy for EC2 Instance
# ---------------------------------------------------------------------------
# Create an IAM role that the EC2 instance can assume
resource "aws_iam_role" "ec2_role" {
  name = "seas8405-week6-lab1-ec2-role"                      # Unique role name
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"                           # Allows EC2 to assume this role
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }          # Specifies EC2 as the trusted entity
    }]
  })
}

# Attach an over-permissive policy to the role for the breach simulation
resource "aws_iam_role_policy" "ec2_policy" {
  name   = "seas8405-week6-lab1-ec2-policy"                  # Policy name
  role   = aws_iam_role.ec2_role.id                          # Associates policy with the role
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action   = ["s3:GetObject", "s3:ListBucket"]           # Grants permissions to get objects and list buckets
      Effect   = "Allow"
      Resource = "*"                                          # Intentionally over-broad to allow access to all S3 resources
    }]
  })
}

# Create an instance profile to link the IAM role to the EC2 instance
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "seas8405-week6-lab1-ec2-instance-profile"          # Instance profile name
  role = aws_iam_role.ec2_role.name                          # Associates the role with the profile
}

# ---------------------------------------------------------------------------
# 5. EC2 Instance with Vulnerable Flask App
# ---------------------------------------------------------------------------
# Launch an EC2 instance running a vulnerable Flask app with an SSRF endpoint
resource "aws_instance" "ec2_instance" {
  ami                    = "ami-0c2ab3b8efb09f272"           # AMI ID (Amazon Linux 2); update for your region if necessary
  instance_type          = "t2.micro"                        # Free-tier eligible instance type
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name  # Attaches the IAM profile
  key_name               = aws_key_pair.ec2_key_pair.key_name  # Associates the SSH key pair
  vpc_security_group_ids = [aws_security_group.allow_local_ip.id]  # Attaches the security group

  # User data script to install dependencies and start the Flask app
  user_data = <<-EOF
              #!/bin/bash
              yum update -y                             # Update the system packages
              yum install -y python3                    # Install Python 3
              pip3 install flask requests               # Install Flask and Requests libraries

              # Create a vulnerable Flask app with an SSRF endpoint
              cat <<'PY' > /home/ec2-user/app.py
              from flask import Flask, request
              import requests, os

              app = Flask(__name__)

              @app.route('/fetch')
              def fetch_url():
                  url = request.args.get('url')         # Get URL parameter from the request
                  if url:
                      try:
                          resp = requests.get(url, timeout=3)  # Fetch the URL (vulnerable to SSRF)
                          return resp.text
                      except Exception as e:
                          return str(e)
                  return 'provide ?url='                # Prompt for URL if none provided

              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=80)     # Run the app on port 80, accessible publicly
              PY
              nohup python3 /home/ec2-user/app.py &>/var/log/app.log &  # Run the app in the background
              EOF

  tags = {
    Name = "seas8405-week6-lab1-ec2-instance"           # Tag for identification
  }
}

# ---------------------------------------------------------------------------
# 6. CloudTrail Logging Bucket and Configuration
# ---------------------------------------------------------------------------
# Create an S3 bucket to store CloudTrail logs
resource "aws_s3_bucket" "trail_bucket" {
  bucket        = "seas8405-week6-lab1-cloudtrail-s3"   # Unique bucket name for logs
  force_destroy = true                                  # Allows Terraform to delete the bucket even if it contains objects
}

# Set ownership controls for the CloudTrail bucket
resource "aws_s3_bucket_ownership_controls" "trail_bucket_ownership" {
  bucket = aws_s3_bucket.trail_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"           # Bucket owner retains control over objects
  }
}

# Set the CloudTrail bucket ACL to private
resource "aws_s3_bucket_acl" "trail_bucket_acl" {
  bucket      = aws_s3_bucket.trail_bucket.id
  acl         = "private"                               # Restricts public access
  depends_on  = [aws_s3_bucket_ownership_controls.trail_bucket_ownership]  # Ensures ownership controls are applied first
}

# Define a bucket policy to allow CloudTrail to write logs and the account owner to manage the bucket
resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_bucket.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"            # Allow CloudTrail to check the bucket ACL
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_bucket.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"               # Allow CloudTrail to write logs
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_bucket.arn}/AWSLogs/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid      = "AllowAccountOwnerReadWrite"        # Allow the AWS account owner full access
        Effect   = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = [
          "s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
          "s3:GetBucketPolicy", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"
        ]
        Resource = [aws_s3_bucket.trail_bucket.arn, "${aws_s3_bucket.trail_bucket.arn}/*"]
      }
    ]
  })
}

# Retrieve the current AWS account ID for use in the bucket policy
data "aws_caller_identity" "current" {}

# Configure CloudTrail to log API calls to the bucket
resource "aws_cloudtrail" "trail" {
  name                          = "seas8405-week6-lab1-cloudtrail"  # Trail name
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id     # Bucket to store logs
  include_global_service_events = true                              # Log global events (e.g., IAM actions)
  is_multi_region_trail         = true                              # Log events across all regions
  depends_on                    = [aws_s3_bucket_policy.trail_bucket_policy]  # Ensures policy is applied first
}

# ---------------------------------------------------------------------------
# 7. Outputs
# ---------------------------------------------------------------------------
# Output the public IP of the EC2 instance for easy access
output "ec2_public_ip" {
  value = aws_instance.ec2_instance.public_ip            # Displays the IP after `terraform apply`
}

