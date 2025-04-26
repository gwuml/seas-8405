# Terraform configuration to secure the Capital One breach simulation environment

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

# ---------------------------------------------------------------------------
# 1. VPC and Network Configuration (DiD: Network Layer)
# ---------------------------------------------------------------------------
resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "secure-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.secure_vpc.id
  tags = {
    Name = "secure-igw"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.secure_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-west-2a"
  map_public_ip_on_launch = true
  tags = {
    Name = "public-subnet"
  }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-west-2a"
  tags = {
    Name = "private-subnet"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.secure_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "public-rt"
  }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_eip" "nat_eip" {
  vpc = true
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public.id
  tags = {
    Name = "nat-gateway"
  }
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.secure_vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }
  tags = {
    Name = "private-rt"
  }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private_rt.id
}

# ---------------------------------------------------------------------------
# 2. SSH Key Management
# ---------------------------------------------------------------------------
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "secure-ec2-key"
  public_key = tls_private_key.ec2_key.public_key_openssh
}

resource "local_file" "private_key" {
  content         = tls_private_key.ec2_key.private_key_pem
  filename        = "${path.module}/secure-ec2-key.pem"
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
# 3. Security Groups (DiD: Network Layer, ZTA: Micro-segmentation)
# ---------------------------------------------------------------------------
data "http" "local_ip" {
  url = "http://ipv4.icanhazip.com"
}

resource "aws_security_group" "bastion_sg" {
  vpc_id      = aws_vpc.secure_vpc.id
  name        = "bastion-sg"
  description = "Allow SSH from local IP"
  ingress {
    from_port   = 22
    to_port     = 22
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
    Name = "bastion-sg"
  }
}

resource "aws_security_group" "ec2_sg" {
  vpc_id      = aws_vpc.secure_vpc.id
  name        = "ec2-sg"
  description = "Allow HTTP from public subnet and SSH from bastion"
  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.public.cidr_block]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "ec2-sg"
  }
}

# ---------------------------------------------------------------------------
# 4. S3 Bucket Configuration (DiD: Data Layer, ZTA: Least Privilege)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "secure_bucket" {
  bucket        = "seas8405-week6-lab1-secure-s3"
  force_destroy = true
  tags = {
    Name = "secure-s3-bucket"
  }
}

resource "aws_s3_bucket_versioning" "versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "logging" {
  bucket        = aws_s3_bucket.secure_bucket.id
  target_bucket = aws_s3_bucket.trail_bucket.id
  target_prefix = "s3-access-logs/"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encryption" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_ownership_controls" "secure_bucket_ownership" {
  bucket = aws_s3_bucket.secure_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "secure_bucket_acl" {
  bucket     = aws_s3_bucket.secure_bucket.id
  acl        = "private"
  depends_on = [aws_s3_bucket_ownership_controls.secure_bucket_ownership]
}

resource "aws_s3_object" "sample_object" {
  bucket  = aws_s3_bucket.secure_bucket.bucket
  key     = "sample.txt"
  content = "Sensitive Test Data"
}

# ---------------------------------------------------------------------------
# 5. IAM Role and Policy (ZTA: Least Privilege)
# ---------------------------------------------------------------------------
resource "aws_iam_role" "ec2_role" {
  name = "secure-ec2-role"
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
  name   = "secure-ec2-policy"
  role   = aws_iam_role.ec2_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.secure_bucket.arn,
        "${aws_s3_bucket.secure_bucket.arn}/*"
      ]
      Condition = {
        IpAddress = { "aws:SourceIp" = "10.0.2.0/24" }
      }
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "secure-ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# ---------------------------------------------------------------------------
# 6. EC2 Instance with Hardened Flask App (DiD: Application Layer)
# ---------------------------------------------------------------------------
resource "aws_instance" "ec2_instance" {
  ami                    = "ami-0c2ab3b8efb09f272"
  instance_type          = "t2.micro"
  iam_instance_profile   = aws_iam_instance_profile.ec2_instance_profile.name
  key_name               = aws_key_pair.ec2_key_pair.key_name
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  user_data              = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y python3
              pip3 install flask requests
              cat <<'PY' > /home/ec2-user/app.py
              from flask import Flask, request
              import requests, os
              app = Flask(__name__)
              ALLOWED_DOMAINS = ['example.com', 'trusted.com']
              @app.route('/fetch')
              def fetch_url():
                  url = request.args.get('url')
                  if url:
                      from urllib.parse import urlparse
                      domain = urlparse(url).netloc
                      if domain in ALLOWED_DOMAINS:
                          try:
                              resp = requests.get(url, timeout=3)
                              return resp.text
                          except Exception as e:
                              return str(e)
                      else:
                          return "Domain not allowed"
                  return 'provide ?url='
              if __name__ == '__main__':
                  app.run(host='0.0.0.0', port=80)
              PY
              nohup python3 /home/ec2-user/app.py &>/var/log/app.log &
              EOF
  tags = {
    Name = "secure-ec2-instance"
  }
}

# ---------------------------------------------------------------------------
# 7. CloudTrail Logging (ASA: Continuous Monitoring)
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "trail_bucket" {
  bucket        = "seas8405-week6-lab1-secure-trail-s3"
  force_destroy = true
}

resource "aws_s3_bucket_ownership_controls" "trail_bucket_ownership" {
  bucket = aws_s3_bucket.trail_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "trail_bucket_acl" {
  bucket     = aws_s3_bucket.trail_bucket.id
  acl        = "private"
  depends_on = [aws_s3_bucket_ownership_controls.trail_bucket_ownership]
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
      }
    ]
  })
}

resource "aws_cloudtrail" "trail" {
  name                          = "secure-cloudtrail"
  s3_bucket_name                = aws_s3_bucket.trail_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::"]
    }
  }
  depends_on = [aws_s3_bucket_policy.trail_bucket_policy]
}

# ---------------------------------------------------------------------------
# 8. Monitoring and Threat Detection (ASA: Continuous Monitoring)
# ---------------------------------------------------------------------------
resource "aws_guardduty_detector" "gd" {
  enable = true
}

# ---------------------------------------------------------------------------
# 9. Outputs
# ---------------------------------------------------------------------------
output "ec2_private_ip" {
  value = aws_instance.ec2_instance.private_ip
}
