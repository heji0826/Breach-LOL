terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.76.0"
    }
  }
}

provider "aws" {
  profile = "ChoiHyunseob"
}

# SNS 주제 리소스 생성
resource "aws_sns_topic" "request_sns" {
  name = "request-topic"
}

resource "aws_sns_topic" "response_sns" {
  name = "response-topic"
}

# IoT Topic Rule (Request)
resource "aws_iot_topic_rule" "request_topic_rule" {
  name        = "request_topic_rule"
  sql         = "SELECT * FROM 'request/topic'"
  sql_version = "2016-03-23"
  enabled     = true

  sns {
    target_arn = aws_sns_topic.request_sns.arn
    role_arn   = aws_iam_role.iot_role.arn
  }
}

# IoT Topic Rule (Response)
resource "aws_iot_topic_rule" "response_topic_rule" {
  name        = "response_topic_rule"
  sql         = "SELECT * FROM 'response/topic'"
  sql_version = "2016-03-23"
  enabled     = true

  sns {
    target_arn = aws_sns_topic.response_sns.arn
    role_arn   = aws_iam_role.iot_role.arn
  }
}

# IAM 역할 생성
resource "aws_iam_role" "iot_role" {
  name               = "IoTRole"
  assume_role_policy = data.aws_iam_policy_document.iot_trust_policy.json
}

# IAM 역할 정책 생성
resource "aws_iam_policy" "iot_policy" {
  name        = "IoTPolicy"
  description = "Policy to allow IoT service to publish to SNS topics"
  policy      = data.aws_iam_policy_document.iot_policy.json
}

# IAM 역할에 정책 연결
resource "aws_iam_role_policy_attachment" "iot_policy_attachment" {
  role       = aws_iam_role.iot_role.name
  policy_arn = aws_iam_policy.iot_policy.arn
}

# 신뢰 정책
data "aws_iam_policy_document" "iot_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["iot.amazonaws.com"]
    }
  }
}

# 권한 정책
data "aws_iam_policy_document" "iot_policy" {
  statement {
    actions   = ["sns:Publish"]
    resources = [
      aws_sns_topic.request_sns.arn,
      aws_sns_topic.response_sns.arn
    ]
  }
}

# VPC 생성
resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

# Subnet 생성
resource "aws_subnet" "subnet_a" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-southeast-1a"
  map_public_ip_on_launch = true
}

# Private Subnet 생성
resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "ap-southeast-1a"
  map_public_ip_on_launch = false
}

# Private Subnet 생성 (추가된 AZ)
resource "aws_subnet" "private_subnet_b" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "ap-southeast-1b"
  map_public_ip_on_launch = false
}

# RDS 생성 (Single AZ 설정)
resource "aws_db_instance" "iot_rds" {
  identifier              = "iot-rds"
  engine                  = "mysql"
  engine_version          = "8.0.39"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "admin"
  password                = "securepassword123"
  vpc_security_group_ids  = [aws_security_group.rds_sg.id]
  db_subnet_group_name    = aws_db_subnet_group.iot_db_subnet_group.name
  multi_az                = false  # Multi-AZ 비활성화
  skip_final_snapshot     = true
}

# DB 서브넷 그룹 (두 개의 AZ 포함)
resource "aws_db_subnet_group" "iot_db_subnet_group" {
  name       = "iot-db-subnet-group"
  subnet_ids = [
    aws_subnet.private_subnet.id,    # ap-southeast-1a
    aws_subnet.private_subnet_b.id  # ap-southeast-1b (다른 AZ)
  ]
}

# 네트워크 로드 밸런서 생성
resource "aws_lb" "nlb" {
  name               = "iot-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.subnet_a.id]
}

# 로드 밸런서 대상 그룹 생성
resource "aws_lb_target_group" "nlb_target_group" {
  name     = "iot-nlb-target-group"
  port     = 80
  protocol = "TCP"
  vpc_id   = aws_vpc.main_vpc.id

  health_check {
    protocol            = "TCP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
  }
}

# 대상 그룹에 EC2 인스턴스 추가
resource "aws_lb_target_group_attachment" "nlb_target_group_attachment" {
  target_group_arn = aws_lb_target_group.nlb_target_group.arn
  target_id        = aws_instance.iot_instance.id
}

# EC2 (Private Subnet)
resource "aws_instance" "iot_instance" {
  ami                         = "ami-047126e50991d067b"
  instance_type               = "t2.micro"
  key_name                    = aws_key_pair.ec2_key_pair.key_name
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  subnet_id                   = aws_subnet.private_subnet.id  # Private Subnet
}

# Bastion Host (Public Subnet)
resource "aws_instance" "bastion_host" {
  ami                         = "ami-047126e50991d067b"
  instance_type               = "t2.micro"
  key_name                    = aws_key_pair.ec2_key_pair.key_name
  vpc_security_group_ids      = [aws_security_group.bastion_sg.id]
  subnet_id                   = aws_subnet.subnet_a.id  # Public Subnet
}

# Bastion Host 보안 그룹
resource "aws_security_group" "bastion_sg" {
  vpc_id      = aws_vpc.main_vpc.id
  name        = "bastion-sg"
  description = "Allow SSH to Bastion Host"

  ingress {
    from_port   = 22
    to_port     = 22
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

resource "aws_security_group" "ec2_sg" {
  vpc_id      = aws_vpc.main_vpc.id
  name        = "ec2-security-group"
  description = "Allow traffic only from Bastion Host"

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion_sg.id] # Bastion Host에서만 SSH 허용
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # 모든 출력 허용
  }
}

# RDS 보안 그룹 생성
resource "aws_security_group" "rds_sg" {
  vpc_id      = aws_vpc.main_vpc.id
  name        = "rds-sg"
  description = "Allow access to RDS from the private subnet"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private_subnet.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# 인터넷 게이트웨이 생성
resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id
}

# VPC의 라우팅 테이블에 인터넷 게이트웨이 연결
resource "aws_route_table" "main_route_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_igw.id
  }
}

# 서브넷에 라우팅 테이블 연결
resource "aws_route_table_association" "subnet_a_association" {
  subnet_id      = aws_subnet.subnet_a.id
  route_table_id = aws_route_table.main_route_table.id
}

# EC2 키 페어 자동 생성 (SSH 접속용)
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "aws_key_pair" "ec2_key_pair" {
  key_name   = "ec2-key-pair"
  public_key = tls_private_key.ec2_key.public_key_openssh
}

# API Gateway 리소스 설정
resource "aws_api_gateway_rest_api" "iot_api" {
  name        = "iot-api"
  description = "API for IoT interactions"
}

resource "aws_api_gateway_resource" "iot_resource" {
  rest_api_id = aws_api_gateway_rest_api.iot_api.id
  parent_id   = aws_api_gateway_rest_api.iot_api.root_resource_id
  path_part   = "device"
}

resource "aws_api_gateway_method" "iot_method" {
  rest_api_id   = aws_api_gateway_rest_api.iot_api.id
  resource_id   = aws_api_gateway_resource.iot_resource.id
  http_method   = "POST"
  authorization = "NONE"
}

# Amplify 앱 설정
resource "aws_amplify_app" "amplify_app" {
  name        = "iot-amplify-app"
  description = "Amplify app for IoT integration"

  environment_variables = {
    "ENV_VAR" = "value"
  }
}

resource "aws_amplify_branch" "main_branch" {
  app_id      = aws_amplify_app.amplify_app.id
  branch_name = "main"
}

# API Gateway 스테이지 생성
resource "aws_api_gateway_stage" "iot_stage" {
  stage_name    = "prod"
  deployment_id = aws_api_gateway_deployment.iot_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.iot_api.id
}

# HTTP 엔드포인트 통합
resource "aws_api_gateway_integration" "iot_integration" {
  rest_api_id             = aws_api_gateway_rest_api.iot_api.id
  resource_id             = aws_api_gateway_resource.iot_resource.id
  http_method             = aws_api_gateway_method.iot_method.http_method
  integration_http_method = "POST"
  type                    = "HTTP"
  uri                     = "http://your-backend-endpoint.example.com"
}

# API Gateway 배포
resource "aws_api_gateway_deployment" "iot_deployment" {
  rest_api_id = aws_api_gateway_rest_api.iot_api.id
  depends_on  = [aws_api_gateway_integration.iot_integration] # 통합 리소스 의존성 추가
}

# WAF v2 Web ACL 생성
resource "aws_wafv2_web_acl" "iot_waf_acl" {
  name        = "iot-waf-acl"
  description = "WAF for IoT API Gateway"
  scope       = "REGIONAL" # Regional 스코프 설정 (API Gateway용)

  default_action {
    allow {} # 기본적으로 모든 요청 허용
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "iot-waf-metrics"
    sampled_requests_enabled   = true
  }

  # SQL 인젝션 방지
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
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "sql-injection-rule"
      sampled_requests_enabled   = true
    }
  }
}

# WAF와 API Gateway 연동
resource "aws_wafv2_web_acl_association" "iot_waf_association" {
  resource_arn = aws_api_gateway_stage.iot_stage.arn
  web_acl_arn  = aws_wafv2_web_acl.iot_waf_acl.arn
}
