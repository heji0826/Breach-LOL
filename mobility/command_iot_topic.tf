# 1) API Gateway -> Amazon RDS -> EC2 인스턴스 -> Command IoT Topic -> AWS IoT Core
# 2) API Gateway -> Amazon RDS -> EC2 인스턴스 -> Critical Command IoT Topic -> AWS IoT Core

terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.76.0"
    }
  }
}

# Provider 설정
provider "aws" {
  profile = "hyeji"
  region  = "ap-northeast-2"
}

# VPC 생성
resource "aws_vpc" "main_vpc" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "Main-VPC"
  }
}

# Subnets
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-northeast-2b"
  map_public_ip_on_launch = true
  tags = {
    Name = "Public-Subnet"
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-northeast-2b"
  tags = {
    Name = "Private-Subnet-1"
  }
}
resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "ap-northeast-2a"
  tags = {
    Name = "Private-Subnet-2"
  }
}
resource "aws_db_subnet_group" "main" {
  name       = "main-db-subnet-group"
  subnet_ids = [
    aws_subnet.private_subnet_1.id,
    aws_subnet.private_subnet_2.id
  ]

  tags = {
    Name = "Main-DB-Subnet-Group"
  }
}
# Internet Gateway
resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id
}

# NAT Gateway
resource "aws_eip" "nat_eip" {
  tags = {
    Name = "NAT-EIP"
  }
}

resource "aws_nat_gateway" "main_nat" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet.id
  tags = {
    Name = "Main-NAT-Gateway"
  }
}

# Route Tables
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_igw.id
  }
}

resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main_nat.id
  }
}

resource "aws_route_table_association" "private_rta_1" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

# Security Groups
resource "aws_security_group" "common_sg" {
  vpc_id = aws_vpc.main_vpc.id
  tags = {
    Name = "Common-Security-Group"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
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

# IAM Role for IoT
resource "aws_iam_role" "iot_role" {
  name               = "iot-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "iot.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "iot_instance_profile" {
  name = "iot-instance-profile"
  role = aws_iam_role.iot_role.name
}

# IAM Role for Firehose
resource "aws_iam_role" "firehose_role" {
  name = "firehose-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "firehose.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_policy" "firehose_policy" {
  name = "firehose-policy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = ["s3:PutObject", "s3:PutObjectAcl"],
        Resource = "${aws_s3_bucket.waf_logs.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "firehose_attach" {
  role       = aws_iam_role.firehose_role.name
  policy_arn = aws_iam_policy.firehose_policy.arn
}

resource "aws_api_gateway_deployment" "api" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  triggers = {
    redeployment = timestamp()
  }

  depends_on = [
    aws_api_gateway_method.command_post,
    aws_api_gateway_method.critical_post,
    aws_api_gateway_integration.command,
    aws_api_gateway_integration.critical
  ]
}

resource "aws_api_gateway_stage" "api_stage" {
  deployment_id = aws_api_gateway_deployment.api.id
  rest_api_id   = aws_api_gateway_rest_api.api.id
  stage_name    = "prod"
}

resource "aws_api_gateway_method" "command_post" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.command.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "critical_post" {
  rest_api_id   = aws_api_gateway_rest_api.api.id
  resource_id   = aws_api_gateway_resource.critical.id
  http_method   = "POST"
  authorization = "NONE"
}

# S3 버킷 생성 (WAF 로그 저장용)
resource "aws_s3_bucket" "waf_logs" {
  bucket = "waf-logs-bucket-unique-id"

  tags = {
    Name        = "WAF Logs Bucket"
    Environment = "Production"
  }
}

resource "aws_s3_bucket_policy" "waf_logs_policy" {
  bucket = aws_s3_bucket.waf_logs.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "firehose.amazonaws.com"
        },
        Action = ["s3:PutObject", "s3:PutObjectAcl"],
        Resource = "${aws_s3_bucket.waf_logs.arn}/*"
      }
    ]
  })
}

# Kinesis Firehose
resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "waf-logs-firehose"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_role.arn
    bucket_arn = aws_s3_bucket.waf_logs.arn

    compression_format = "GZIP"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "firehose-logs"
      log_stream_name = "waf-logs-stream"
    }
  }

  tags = {
    Environment = "Production"
  }
}

# WAFv2 Web ACL 생성
resource "aws_wafv2_web_acl" "api_waf" {
  name  = "api-waf"
  scope = "REGIONAL"
  tags = {
    Name = "API-WAF"
  }

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "api-waf"
    sampled_requests_enabled   = true
  }

  # SQL Injection 방지 규칙
  rule {
    name     = "sql-injection-rule"
    priority = 1

    statement {
      sqli_match_statement {
        field_to_match {
          body {}
        }

        text_transformation {
          priority = 0
          type     = "URL_DECODE"
        }
      }
    }

    action {
      block {} # SQL Injection 요청 차단
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sql-injection-rule"
      sampled_requests_enabled   = true
    }
  }

  # XSS 방지 규칙
  rule {
    name     = "xss-protection-rule"
    priority = 2

    statement {
      xss_match_statement {
        field_to_match {
          body {}
        }

        text_transformation {
          priority = 0
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    action {
      block {} # XSS 공격 차단
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "xss-protection-rule"
      sampled_requests_enabled   = true
    }
  }
}

# WAF와 API Gateway Stage 연동
resource "aws_wafv2_web_acl_association" "api_waf_assoc" {
  resource_arn = "arn:aws:apigateway:ap-northeast-2::/restapis/${aws_api_gateway_rest_api.api.id}/stages/${aws_api_gateway_stage.api_stage.stage_name}"
  web_acl_arn  = aws_wafv2_web_acl.api_waf.arn
}

resource "aws_db_instance" "rds_command" {
  allocated_storage      = 20
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  db_name                = "commanddb"
  username               = "admin"
  password               = "password123"
  vpc_security_group_ids = [aws_security_group.common_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  skip_final_snapshot    = true
  multi_az               = false
  availability_zone      = "ap-northeast-2b"
  tags = {
    Name = "RDS-Command-Instance"
  }
}

resource "aws_db_instance" "rds_critical" {
  allocated_storage      = 20
  engine                 = "mysql"
  instance_class         = "db.t3.micro"
  db_name                = "criticaldb"
  username               = "admin"
  password               = "password123"
  vpc_security_group_ids = [aws_security_group.common_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
  skip_final_snapshot    = true
  multi_az               = false
  availability_zone      = "ap-northeast-2b"
  tags = {
    Name = "RDS-Command-Instance"
  }
}


# EC2 Instances
resource "aws_instance" "ec2_command" {
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private_subnet_1.id
  vpc_security_group_ids      = [aws_security_group.common_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.iot_instance_profile.name
  tags = {
    Name = "EC2-Command-Instance"
  }
}

resource "aws_instance" "ec2_critical" {
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t3.micro"
  subnet_id                   = aws_subnet.private_subnet_1.id
  vpc_security_group_ids      = [aws_security_group.common_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.iot_instance_profile.name
  tags = {
    Name = "EC2-Critical-Instance"
  }
}

# API Gateway
resource "aws_api_gateway_rest_api" "api" {
  name = "iot-api"
  tags = {
    Name = "IoT-API"
  }
}

resource "aws_api_gateway_resource" "command" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "command"
}

resource "aws_api_gateway_resource" "critical" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  parent_id   = aws_api_gateway_rest_api.api.root_resource_id
  path_part   = "critical"
}

resource "aws_api_gateway_integration" "command" {
  rest_api_id             = aws_api_gateway_rest_api.api.id
  resource_id             = aws_api_gateway_resource.command.id
  http_method             = "POST"
  integration_http_method = "POST"
  type                    = "HTTP"
  uri                     = "http://${aws_instance.ec2_command.private_ip}"
}

resource "aws_api_gateway_integration" "critical" {
  rest_api_id             = aws_api_gateway_rest_api.api.id
  resource_id             = aws_api_gateway_resource.critical.id
  http_method             = "POST"
  integration_http_method = "POST"
  type                    = "HTTP"
  uri                     = "http://${aws_instance.ec2_critical.private_ip}"
}

output "firehose_arn" {
  value = aws_kinesis_firehose_delivery_stream.waf_logs.arn
}