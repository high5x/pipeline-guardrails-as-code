terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "production_payroll_storage" {
  bucket        = "corp-production-payroll-data-backend"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "vulnerable_leak_path" {
  bucket = aws_s3_bucket.production_payroll_storage.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_ebs_volume" "production_database_vol" {
  availability_zone = "us-east-1a"
  size              = 500
  type              = "gp3"
  encrypted         = true
}
