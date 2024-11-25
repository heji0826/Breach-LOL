terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.76.0"
    }
  }
}

provider "aws" {
  profile = "ChoiHyunseob"
}

# SNS 주제 리소스 생성 (Telemetry topic)
resource "aws_sns_topic" "vehicle_telemetry_sns" {
  name = "vehicle-telemetry-topic"
}

# IoT Topic Rule (Telemetry)
resource "aws_iot_topic_rule" "vehicle_telemetry_topic_rule" {
  depends_on = [aws_iam_role.waf_log_role]
  
  name        = "vehicle_telemetry_topic_rule"
  sql         = "SELECT * FROM 'vehicle/telemetry'"
  sql_version = "2016-03-23"
  enabled     = true

  sns {
    target_arn = aws_sns_topic.vehicle_telemetry_sns.arn
    role_arn   = aws_iam_role.waf_log_role.arn
  }
}

# IAM 역할 생성
resource "aws_iam_role" "waf_log_role" {
  name = "waf-log-role-mobility"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "Service": "iot.amazonaws.com"
      }
    }
  ]
}
POLICY
}

# IAM 역할 정책 생성
resource "aws_iam_policy" "waf_s3_log_policy" {
  name        = "WAF-S3-Log-Policy-mobility"
  description = "Allow WAF to write logs to S3"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = "s3:PutObject",
        Effect   = "Allow",
        Resource = "${aws_s3_bucket.waf_log_storage.arn}/*"
      }
    ]
  })
}

# IoT 역할에 S3 정책 연결
resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  role       = aws_iam_role.waf_log_role.name
  policy_arn = aws_iam_policy.waf_s3_log_policy.arn

  depends_on = [aws_iam_policy.waf_s3_log_policy , aws_iam_role.waf_log_role]
}

# 신뢰 정책: IoT 서비스가 역할을 사용할 수 있도록 설정
data "aws_iam_policy_document" "iot_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["iot.amazonaws.com"]
    }
  }
}

# 권한 정책: SNS에 게시할 수 있도록 설정
data "aws_iam_policy_document" "iot_policy" {
  statement {
    actions   = ["sns:Publish"]
    resources = [
      aws_sns_topic.vehicle_telemetry_sns.arn
    ]
  }
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

# 보안 그룹 생성 (같은 VPC 내)
resource "aws_security_group" "ec2_sg" {
  vpc_id     = aws_vpc.main_vpc.id
  name       = "ec2-security-group"
  description = "Allow SSH (port 22) for EC2 instances"

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

resource "aws_route_table_association" "subnet_b_association" {
  subnet_id      = aws_subnet.subnet_b.id
  route_table_id = aws_route_table.main_route_table.id
}

# EC2 인스턴스 생성 (Ubuntu EC2 인스턴스 예시)
resource "aws_instance" "vehicle_ec2" {
  ami           = "ami-047126e50991d067b"  # Ubuntu 20.04 LTS AMI ID (필요에 따라 최신 AMI로 교체)
  instance_type = "t2.micro"
  key_name      = aws_key_pair.ec2_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  subnet_id            = aws_subnet.private_subnet_a.id  

  tags = {
    Name = "Vehicle-Telemetry-EC2"
  }
}

# VPC 생성
resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

# 서브넷 생성 (자동으로 가용 영역을 설정)
resource "aws_subnet" "subnet_a" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-southeast-1a"  # 첫 번째 가용 영역
  map_public_ip_on_launch = true
}

resource "aws_subnet" "subnet_b" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "ap-southeast-1b"  # 두 번째 가용 영역
  map_public_ip_on_launch = true
}

# Private Subnet 정의
resource "aws_subnet" "private_subnet_a" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "ap-southeast-1a"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "private_subnet_b" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "ap-southeast-1b"
  map_public_ip_on_launch = false
}

# Network Load Balancer 생성
resource "aws_lb" "vehicle_lb" {
  name               = "vehicle-telemetry-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.subnet_a.id, aws_subnet.subnet_b.id]
}

# NLB 리스너 생성
resource "aws_lb_listener" "vehicle_lb_listener" {
  load_balancer_arn = aws_lb.vehicle_lb.arn
  port              = 22
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vehicle_target_group.arn
  }
}

# 대상 그룹 (TCP)
resource "aws_lb_target_group" "vehicle_target_group" {
  name     = "vehicle-telemetry-target-group"
  port     = 22
  protocol = "TCP"
  vpc_id   = aws_vpc.main_vpc.id

  health_check {
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 2
    protocol            = "TCP"
    port                = 22
  }
}

# 로드밸런서와 EC2 인스턴스 연결
resource "aws_lb_target_group_attachment" "vehicle_target_group_attachment" {
  target_group_arn = aws_lb_target_group.vehicle_target_group.arn
  target_id        = aws_instance.vehicle_ec2.id
  port             = 22
}

# Amazon MSK (Managed Streaming for Kafka) 클러스터 생성
resource "aws_msk_cluster" "vehicle_kafka" {
  cluster_name          = "vehicle-telemetry-cluster"
  kafka_version         = "2.8.0"
  number_of_broker_nodes = 2

  broker_node_group_info {
    instance_type   = "kafka.m5.large"
    client_subnets  = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id] 
    security_groups = [aws_security_group.ec2_sg.id]
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}

# S3 버킷 생성 (Telemetry 데이터 저장용)
resource "aws_s3_bucket" "waf_log_storage" {
  bucket = "aws-waf-logs-mobility-service-bucket"
  force_destroy = true
}

# API Gateway 리소스 및 메서드 설정 (Telemetry API)
resource "aws_api_gateway_rest_api" "vehicle_api" {
  name        = "vehicle-api"
  description = "API for Vehicle Telemetry"
}

resource "aws_api_gateway_resource" "vehicle_resource" {
  rest_api_id = aws_api_gateway_rest_api.vehicle_api.id
  parent_id   = aws_api_gateway_rest_api.vehicle_api.root_resource_id
  path_part   = "telemetry"
}

# API Gateway 메서드 설정
resource "aws_api_gateway_method" "vehicle_method" {
  rest_api_id   = aws_api_gateway_rest_api.vehicle_api.id
  resource_id   = aws_api_gateway_resource.vehicle_resource.id
  http_method   = "POST"
  authorization = "NONE"
}

# API Gateway Integration 설정 (MOCK 통합)
resource "aws_api_gateway_integration" "vehicle_integration" {
  rest_api_id             = aws_api_gateway_rest_api.vehicle_api.id
  resource_id             = aws_api_gateway_resource.vehicle_resource.id
  http_method             = aws_api_gateway_method.vehicle_method.http_method  # 연결된 메서드와 일치해야 함
  integration_http_method = "POST"  # MOCK의 경우 무시되지만 POST로 설정
  type                    = "MOCK"
}
# 새로운 배포 리소스
resource "aws_api_gateway_deployment" "new_deployment" {
  rest_api_id = aws_api_gateway_rest_api.vehicle_api.id

  triggers = {
    redeploy = "${timestamp()}"  # 변경 시 강제로 배포
  }

  depends_on = [
    aws_api_gateway_integration.vehicle_integration  # 통합 리소스가 완료된 후에만 실행
  ]
}

# WAF v2 Web ACL 생성
resource "aws_wafv2_web_acl" "vehicle_waf_acl" {
  name        = "vehicle-waf-acl"
  description = "WAF for Vehicle API Gateway"
  scope       = "REGIONAL" # Regional 스코프 설정 (API Gateway용)

  default_action {
    allow {} # 기본적으로 모든 요청 허용
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "vehicle-waf-metrics"
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

  # XSS 방지 규칙 추가 (예시)
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
      block {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "xss-protection-rule"
      sampled_requests_enabled   = true
    }
  }
}

resource "aws_api_gateway_stage" "vehicle_stage" {
  stage_name    = "prod"
  deployment_id = aws_api_gateway_deployment.new_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.vehicle_api.id

  depends_on = [
    aws_api_gateway_deployment.new_deployment
  ]
}

# WAF와 API Gateway 연동
resource "aws_wafv2_web_acl_association" "vehicle_waf_association" {
  resource_arn = aws_api_gateway_stage.vehicle_stage.arn  # API Gateway 스테이지 ARN
  web_acl_arn  = aws_wafv2_web_acl.vehicle_waf_acl.arn
}

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging_acl_configure" {
  log_destination_configs = [aws_s3_bucket.waf_log_storage.arn]  # 버킷 ARN
  resource_arn            = aws_wafv2_web_acl.vehicle_waf_acl.arn

  redacted_fields {
    single_header {
      name = "user-agent"
    }
  }

  depends_on = [aws_s3_bucket.waf_log_storage]
}
