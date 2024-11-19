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
  name        = "vehicle_telemetry_topic_rule"
  sql         = "SELECT * FROM 'vehicle/telemetry'"
  sql_version = "2016-03-23"
  enabled     = true

  sns {
    target_arn = aws_sns_topic.vehicle_telemetry_sns.arn
    role_arn   = aws_iam_role.iot_role.arn  # IAM 역할을 사용
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
  subnet_id            = aws_subnet.subnet_a.id  

  tags = {
    Name = "Vehicle-Telemetry-EC2"
  }
}

# VPC 생성
resource "aws_vpc" "main_vpc" {
  cidr_block = "10.0.0.0/16"
}

# 가용 영역 조회
data "aws_availability_zones" "available" {}

# 서브넷 생성 (자동으로 가용 영역을 설정)
resource "aws_subnet" "subnet_a" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]  # 첫 번째 가용 영역
  map_public_ip_on_launch = true
}

resource "aws_subnet" "subnet_b" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = data.aws_availability_zones.available.names[1]  # 두 번째 가용 영역
  map_public_ip_on_launch = true
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
    client_subnets  = [aws_subnet.subnet_a.id, aws_subnet.subnet_b.id]  # 자동으로 서브넷을 사용
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
resource "aws_s3_bucket" "vehicle_telemetry_bucket" {
  bucket = "vehicle-telemetry-bucket"  # 고유한 버킷 이름 필요

  tags = {
    Name        = "Vehicle Telemetry Bucket"
    Environment = "Production"
  }
}

# S3 버킷에 파일 업로드를 위한 IAM 정책 생성
resource "aws_iam_policy" "s3_policy" {
  name        = "S3Policy"
  description = "Policy to allow writing telemetry data to S3"
  policy      = data.aws_iam_policy_document.s3_policy.json
}

# S3 버킷에 대한 IAM 정책 문서
data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.vehicle_telemetry_bucket.arn}/*"  # 버킷 내 모든 객체에 대해 PutObject 권한
    ]
  }
}

# IoT 역할에 S3 정책 연결
resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  role       = aws_iam_role.iot_role.name
  policy_arn = aws_iam_policy.s3_policy.arn
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

resource "aws_api_gateway_method" "vehicle_method" {
  rest_api_id   = aws_api_gateway_rest_api.vehicle_api.id
  resource_id   = aws_api_gateway_resource.vehicle_resource.id
  http_method   = "POST"
  authorization = "NONE"
}

# Amplify 앱 설정
resource "aws_amplify_app" "amplify_app" {
  name        = "vehicle-amplify-app"
  description = "Amplify app for Vehicle Telemetry Integration"

  environment_variables = {
    "ENV_VAR" = "value"
  }
}

resource "aws_amplify_branch" "main_branch" {
  app_id      = aws_amplify_app.amplify_app.id
  branch_name = "main"
}
