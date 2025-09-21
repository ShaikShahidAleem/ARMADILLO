# Create a simple Terraform file with intentional security issues (for learning)
# Sample Terraform configuration with security issues for learning
# DO NOT use this in production!

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# Example 1: S3 bucket with security issues
resource "aws_s3_bucket" "example" {
  bucket = "my-example-bucket-12345"
  
  # Security Issue: Public read access
  acl = "public-read"
}

# Example 2: Security group with overly permissive rules
resource "aws_security_group" "web" {
  name_prefix = "web-"
  
  # Security Issue: Allows all traffic from anywhere
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Example 3: EC2 instance with security issues
resource "aws_instance" "web" {
  ami           = "ami-0c02fb55956c7d316"  # Amazon Linux 2
  instance_type = "t3.micro"
  
  # Security Issue: No encryption for root volume
  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = false  # This should be true
  }
  
  # Security Issue: Using default VPC
  vpc_security_group_ids = [aws_security_group.web.id]
  
  tags = {
    Name = "WebServer"
  }
}

# Example 4: RDS instance with security issues
resource "aws_db_instance" "main" {
  identifier = "main-database"
  
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage = 20
  storage_type      = "gp2"
  
  db_name  = "myapp"
  username = "admin"
  password = "password123"  # Security Issue: Hardcoded password
  
  # Security Issue: Publicly accessible
  publicly_accessible = true
  
  # Security Issue: No encryption
  storage_encrypted = false
  
  # Security Issue: No backup retention
  backup_retention_period = 0
  
  skip_final_snapshot = true
}