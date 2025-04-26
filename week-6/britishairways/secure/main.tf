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

# VPC and Network Configuration
resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "secure-vpc"
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

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.secure_vpc.id
  tags = {
    Name = "secure-igw"
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

# SSH Key Management
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

# Security Groups
data "http" "local_ip" {
  url = "http://ipv4.icanhazip.com"
}

resource "aws_security_group" "allow_local_ip" {
  name        = "allow_local_ip"
  description = "Allow SSH from local IP and HTTP from public subnet"
  vpc_id      = aws_vpc.secure_vpc.id
  ingress {
    description = "SSH from local IP"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.local_ip.response_body)}/32"]
  }
  ingress {
    description = "HTTP from public subnet"
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
    Name = "allow_local_ip"
  }
}

# EC2 Instance with Hardened Web Server
resource "aws_instance" "web_server" {
  ami                    = "ami-0c2ab3b8efb09f272"
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.ec2_key_pair.key_name
  subnet_id              = aws_subnet.private.id
  vpc_security_group_ids = [aws_security_group.allow_local_ip.id]
  user_data              = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y httpd
              systemctl start httpd
              systemctl enable httpd
              cat <<HTML > /var/www/html/index.html
              <!DOCTYPE html>
              <html lang="en">
              <head>
                  <meta charset="UTF-8">
                  <meta name="viewport" content="width=device-width, initial-scale=1.0">
                  <title>Payment Page</title>
                  <meta http-equiv="Content-Security-Policy" content="script-src 'self' https://trusted.cdn.com; object-src 'none';">
              </head>
              <body>
                  <h1>Payment Information</h1>
                  <form id="payment-form">
                      <label for="card-number">Card Number:</label>
                      <input type="text" id="card-number" name="card-number"><br><br>
                      <label for="cvv">CVV:</label>
                      <input type="text" id="cvv" name="cvv"><br><br>
                      <button type="submit">Submit</button>
                  </form>
                  <script src="https://trusted.cdn.com/payment.js" integrity="sha384-..."></script>
              </body>
              </html>
              HTML
              EOF
  tags = {
    Name = "british-airways-secure-ec2"
  }
}

# CloudWatch Monitoring
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "high-cpu-utilization"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "Monitors EC2 CPU utilization"
  dimensions = {
    InstanceId = aws_instance.web_server.id
  }
}

# Output
output "web_server_private_ip" {
  value = aws_instance.web_server.private_ip
}
