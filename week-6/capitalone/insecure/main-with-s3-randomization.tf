# main.tf – Terraform configuration to simulate the Capital One breach scenario

# ---------------------------------------------------------------------------
# 0. Provider Configuration
# ---------------------------------------------------------------------------
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# Generate a random ID for unique bucket names
resource "random_id" "bucket_suffix" {
  byte_length = 4  # Generates an 8-character hex string
}

# ---------------------------------------------------------------------------
# 1. SSH Key Management
# ---------------------------------------------------------------------------
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "my-ec2-key"
  public_key = tls_private_key.ec2_key.public_key_openssh
}

resource "local_file" "private_key" {
  content         = tls_private_key.ec2_key.private_key_pem
  filename        = "${path.module}/my-ec2-key.pem"
  file_permission = "0400"
}

resource "null_resource" "delete_key" {
  triggers = {
    key_file = local_file.private_key.filename
  }

  provisioner "local-exec" {
    when    = destroy
    command = "rm -f ${self.triggers.key_file}"
  }
}

# ---------------------------------------------------------------------------
# 2. Security Group Configuration
# ---------------------------------------------------------------------------
data "http" "local_ip" {
  url = "http://ipv4.icanhazip.com"
}

resource "aws_security_group" "allow_local_ip" {
  name        = "allow_local_ip"
  description = "Allow inbound SSH and HTTP from local IP"

  ingress {
    description = "SSH from local IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.local_ip.response_body)}/32"]
  }

  ingress {
    description = "HTTP from local IP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.local_ip.response_body)}/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow_local_ip"
  }
}

# ---------------------------------------------------------------------------
# 3. Vulnerable S3 Bucket
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket        = "seas8405-week6-lab1-vulnerable-s3-${random_id.bucket_suffix.hex}"
  force_destroy = true
  tags = {
    Name = "seas8405-week6-lab1-vulnerable-s3-${random_id.bucket_suffix.hex}"
  }
}

resource "aws_s3_bucket_ownership_controls" "vulnerable_bucket_ownership" {
  bucket = aws_s3_bucket.vulnerable_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "vulnerable_bucket_acl" {
  bucket      = aws_s3_bucket.vulnerable_bucket.id
  acl         = "private"
  depends_on  = [aws_s3_bucket_ownership_controls.vulnerable_bucket_ownership]
}

resource "aws_s3_object" "sample_object" {
  bucket  = aws_s3_bucket.vulnerable_bucket.bucket
  key     = "sample.txt"
  content = "Sensitive Test Data"
}

# ---------------------------------------------------------------------------
# 4. IAM Role and Policy for EC2 Instance
# ---------------------------------------------------------------------------
resource "aws_iam_role" "ec2_role" {
  name = "seas8405-week6-lab1-ec2-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ec2_policy" {
  name   = "seas8405-week6-lab1-ec2-policy"
  role   = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "seas8405-week6-lab1-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# ---------------------------------------------------------------------------
# 5. EC2 Instance with Vulnerable Flask App
# ---------------------------------------------------------------------------
resource "aws_instance" "ec2_instance" {
  ami                    = "ami-0c2ab3b8efb09f272"
  instance_type          = "t2.micro"
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name
  key_name               = aws_key_pair.ec2_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.allow_local_ip.id]

  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y python3
              pip3 install flask requests

              cat <<'PY' > /home/ec2-user/app.py
              from flask import Flask, request
              import requests, os

              app = Flask(__name__)

              @app.route('/fetch')
              def fetch_url():
                  url = request.args.get('url')
                  if url:
                      try:
                          resp = requests.get(url, timeout=3)
                          return resp.text
                      except Exception as e:
                          return str(e)
                  return 'provide ?url='

              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=80)
              PY
              nohup python3 /home/ec2-user/app.py &>/var/log/app.log &
              EOF

  tags = {
    Name = "seas8405-week6-lab1-ec2-instance"
  }
}

# ---------------------------------------------------------------------------
# 6. CloudTrail Logging Bucket and Configuration
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "trail_bucket" {
  bucket        = "seas8405-week6-lab1-cloudtrail-s3-${random_id.bucket_suffix.hex}"
  force_destroy = true
  tags = {
    Name = "seas8405-week6-lab1-cloudtrail-s3-${random_id.bucket_suffix.hex}"
  }
}

resource "aws_s3_bucket_ownership_controls" "trail_bucket_ownership" {
  bucket = aws_s3_bucket.trail_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "trail_bucket_acl" {
  bucket      = aws_s3_bucket.trail_bucket.id
  acl         = "private"
  depends_on  = [aws_s3_bucket_ownership_controls.trail_bucket_ownership]
}

resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.trail_bucket.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.trail_bucket.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.trail_bucket.arn}/AWSLogs/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      },
      {
        Sid      = "AllowAccountOwnerReadWrite"
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

data "aws_caller_identity" "current" {}

resource "aws_cloudtrail" "trail" {
  name                          = "seas8405-week6-lab1-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  depends_on                    = [aws_s3_bucket_policy.trail_bucket_policy]
}

# ---------------------------------------------------------------------------
# 7. Outputs
# ---------------------------------------------------------------------------
output "ec2_public_ip" {
  value = aws_instance.ec2_instance.public_ip
}
