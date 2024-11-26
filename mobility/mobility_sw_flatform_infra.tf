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
  region = "ap-northeast-2"
}

# SNS 주제 리소스 생성 6번
resource "aws_sns_topic" "request_sns" {
  name = "request-topic"
}

resource "aws_sns_topic" "response_sns" {
  name = "response-topic"
}

# SNS 주제 리소스 생성 (Telemetry topic)
resource "aws_sns_topic" "vehicle_telemetry_sns" {
  name = "vehicle-telemetry-topic"
}

# IoT Topic Rule (Request) 6번
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

# IoT Topic Rule (Response) 6번
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

# IAM 역할 생성 6번
resource "aws_iam_role" "iot_role" {
  name               = "IoTRole"
  assume_role_policy = data.aws_iam_policy_document.iot_trust_policy.json
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

resource "aws_iam_instance_profile" "iot_instance_profile" {
  name = "iot-instance-profile"
  role = aws_iam_role.iot_role.name
}

# IAM Role for Firehose 혜지님
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

# IAM 역할 정책 생성 6번
resource "aws_iam_policy" "iot_policy" {
  name        = "IoTPolicy"
  description = "Policy to allow IoT service to publish to SNS topics"
  policy      = data.aws_iam_policy_document.iot_policy.json
}

# 혜지님
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

# IAM 역할에 정책 연결 6번
resource "aws_iam_role_policy_attachment" "iot_policy_attachment" {
  role       = aws_iam_role.iot_role.name
  policy_arn = aws_iam_policy.iot_policy.arn
}

# IoT 역할에 S3 정책 연결
resource "aws_iam_role_policy_attachment" "s3_policy_attachment" {
  role       = aws_iam_role.waf_log_role.name
  policy_arn = aws_iam_policy.waf_s3_log_policy.arn

  depends_on = [aws_iam_policy.waf_s3_log_policy , aws_iam_role.waf_log_role]
}

# 혜지님
resource "aws_iam_role_policy_attachment" "firehose_attach" {
  role       = aws_iam_role.firehose_role.name
  policy_arn = aws_iam_policy.firehose_policy.arn
}

# 신뢰 정책 6번
data "aws_iam_policy_document" "iot_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["iot.amazonaws.com"]
    }
  }
}

# 권한 정책 6번
data "aws_iam_policy_document" "iot_policy" {
  statement {
    actions   = ["sns:Publish"]
    resources = [
      aws_sns_topic.request_sns.arn,
      aws_sns_topic.response_sns.arn,
      aws_sns_topic.vehicle_telemetry_sns.arn
    ]
  }
}

# VPC 생성
resource "aws_vpc" "main_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}

# Subnet 생성 6번
resource "aws_subnet" "subnet_a" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true
}

# Private Subnet 생성 6번
resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false
}

# Private Subnet 생성 (추가된 AZ) 6번
resource "aws_subnet" "private_subnet_b" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.3.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = false
}

# 서브넷 생성 (자동으로 가용 영역을 설정)
resource "aws_subnet" "subnet_c" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.4.0/24"
  availability_zone       = "ap-northeast-2c"  # 첫 번째 가용 영역
  map_public_ip_on_launch = true
}

resource "aws_subnet" "subnet_d" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.5.0/24"
  availability_zone       = "ap-northeast-2b"  # 두 번째 가용 영역
  map_public_ip_on_launch = true
}

# Private Subnet 정의
resource "aws_subnet" "private_subnet_c" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.6.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = false
}

resource "aws_subnet" "private_subnet_d" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.7.0/24"
  availability_zone       = "ap-northeast-2b"
  map_public_ip_on_launch = false
}

# 혜지님 부분 subnet
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = "10.0.8.0/24"
  availability_zone       = "ap-northeast-2c"
  map_public_ip_on_launch = true
  tags = {
    Name = "Public-Subnet"
  }
}

resource "aws_subnet" "private_subnet_1" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.9.0/24"
  availability_zone = "ap-northeast-2c"
  tags = {
    Name = "Private-Subnet-1"
  }
}
resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "ap-northeast-2b"
  tags = {
    Name = "Private-Subnet-2"
  }
}

# 6번 s3
resource "aws_s3_bucket" "iot_bucket" {
  bucket        = "aws-waf-logs-iot-app-bucket"
  force_destroy = true
}

# S3 버킷 생성 (Telemetry 데이터 저장용)
resource "aws_s3_bucket" "waf_log_storage" {
  bucket = "aws-waf-logs-mobility-service-bucket"
  force_destroy = true
}

# 혜지님
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

# RDS 생성 (Single AZ 설정) 6번
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

# 혜지님 db
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
  availability_zone      = "ap-northeast-2c"
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
  availability_zone      = "ap-northeast-2c"
  tags = {
    Name = "RDS-Command-Instance"
  }
}

# ec2 혜지님
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

# DB 서브넷 그룹 (두 개의 AZ 포함) 6번
resource "aws_db_subnet_group" "iot_db_subnet_group" {
  name       = "iot-db-subnet-group"
  subnet_ids = [
    aws_subnet.private_subnet_1.id,    # ap-northeast-1a
    aws_subnet.private_subnet_b.id  # ap-northeast-1b (다른 AZ)
  ]
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

# 네트워크 로드 밸런서 생성 6번
resource "aws_lb" "nlb" {
  name               = "iot-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.subnet_a.id]
}

# Network Load Balancer 생성
resource "aws_lb" "vehicle_lb" {
  name               = "vehicle-telemetry-nlb"
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.subnet_c.id, aws_subnet.subnet_d.id]
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

# 로드 밸런서 대상 그룹 생성 6번
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

# 대상 그룹에 EC2 인스턴스 추가 6번
resource "aws_lb_target_group_attachment" "nlb_target_group_attachment" {
  target_group_arn = aws_lb_target_group.nlb_target_group.arn
  target_id        = aws_instance.iot_instance.id
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
    client_subnets  = [aws_subnet.private_subnet_c.id, aws_subnet.private_subnet_d.id] 
    security_groups = [aws_security_group.ec2_sg.id]
  }

  encryption_info {
    encryption_in_transit {
      client_broker = "TLS"
      in_cluster    = true
    }
  }
}

# EC2 (Private Subnet) 6번
resource "aws_instance" "iot_instance" {
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t3.small"
  key_name                    = aws_key_pair.ec2_key_pair.key_name
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  subnet_id                   = aws_subnet.private_subnet.id  # Private Subnet
}

# Bastion Host (Public Subnet)
resource "aws_instance" "bastion_host" {
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t3.small"
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

# Security Groups 혜지님
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

# 인터넷 게이트웨이 생성
resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id
}

# NAT Gateway 혜지님
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

# VPC의 라우팅 테이블에 인터넷 게이트웨이 연결
resource "aws_route_table" "main_route_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_igw.id
  }
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main_nat.id
  }
}

# 서브넷에 라우팅 테이블 연결
resource "aws_route_table_association" "subnet_a_association" {
  subnet_id      = aws_subnet.subnet_a.id
  route_table_id = aws_route_table.main_route_table.id
}

resource "aws_route_table_association" "subnet_c_association" {
  subnet_id      = aws_subnet.subnet_c.id
  route_table_id = aws_route_table.main_route_table.id
}

resource "aws_route_table_association" "subnet_d_association" {
  subnet_id      = aws_subnet.subnet_d.id
  route_table_id = aws_route_table.main_route_table.id
}

resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.main_route_table.id
}

resource "aws_route_table_association" "private_rta_1" {
  subnet_id      = aws_subnet.private_subnet_1.id
  route_table_id = aws_route_table.private_rt.id
}

# EC2 인스턴스 생성 (Ubuntu EC2 인스턴스 예시)
resource "aws_instance" "vehicle_ec2" {
  ami           = "ami-040c33c6a51fd5d96"  # Ubuntu 20.04 LTS AMI ID (필요에 따라 최신 AMI로 교체)
  instance_type = "t3.small"
  key_name      = aws_key_pair.ec2_key_pair.key_name
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  subnet_id            = aws_subnet.private_subnet_c.id  

  tags = {
    Name = "Vehicle-Telemetry-EC2"
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

# API Gateway 리소스 설정 6번
resource "aws_api_gateway_rest_api" "iot_api" {
  name        = "iot-api"
  description = "API for IoT interactions"
}

resource "aws_api_gateway_rest_api" "api" {
  name = "iot-api"
  tags = {
    Name = "IoT-API"
  }
}

# API Gateway 리소스 및 메서드 설정 (Telemetry API)
resource "aws_api_gateway_rest_api" "vehicle_api" {
  name        = "vehicle-api"
  description = "API for Vehicle Telemetry"
}

# 6번
resource "aws_api_gateway_resource" "iot_resource" {
  rest_api_id = aws_api_gateway_rest_api.iot_api.id
  parent_id   = aws_api_gateway_rest_api.iot_api.root_resource_id
  path_part   = "device"
}

resource "aws_api_gateway_resource" "vehicle_resource" {
  rest_api_id = aws_api_gateway_rest_api.vehicle_api.id
  parent_id   = aws_api_gateway_rest_api.vehicle_api.root_resource_id
  path_part   = "telemetry"
}

# 6번
resource "aws_api_gateway_method" "iot_method" {
  rest_api_id   = aws_api_gateway_rest_api.iot_api.id
  resource_id   = aws_api_gateway_resource.iot_resource.id
  http_method   = "POST"
  authorization = "NONE"
}

# 혜지님
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

# API Gateway 메서드 설정
resource "aws_api_gateway_method" "vehicle_method" {
  rest_api_id   = aws_api_gateway_rest_api.vehicle_api.id
  resource_id   = aws_api_gateway_resource.vehicle_resource.id
  http_method   = "POST"
  authorization = "NONE"
}

# 혜지님
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

# API Gateway 스테이지 생성 6번
resource "aws_api_gateway_stage" "iot_stage" {
  stage_name    = "prod"
  deployment_id = aws_api_gateway_deployment.iot_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.iot_api.id
}

resource "aws_api_gateway_stage" "vehicle_stage" {
  stage_name    = "prod"
  deployment_id = aws_api_gateway_deployment.new_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.vehicle_api.id

  depends_on = [
    aws_api_gateway_deployment.new_deployment
  ]
}

resource "aws_api_gateway_stage" "api_stage" {
  deployment_id = aws_api_gateway_deployment.api.id
  rest_api_id   = aws_api_gateway_rest_api.api.id
  stage_name    = "prod"
}

# HTTP 엔드포인트 통합 6번
resource "aws_api_gateway_integration" "iot_integration" {
  rest_api_id             = aws_api_gateway_rest_api.iot_api.id
  resource_id             = aws_api_gateway_resource.iot_resource.id
  http_method             = aws_api_gateway_method.iot_method.http_method
  integration_http_method = "POST"
  type                    = "HTTP"
  uri                     = "http://your-backend-endpoint.example.com"
}

# API Gateway Integration 설정 (MOCK 통합)
resource "aws_api_gateway_integration" "vehicle_integration" {
  rest_api_id             = aws_api_gateway_rest_api.vehicle_api.id
  resource_id             = aws_api_gateway_resource.vehicle_resource.id
  http_method             = aws_api_gateway_method.vehicle_method.http_method  # 연결된 메서드와 일치해야 함
  integration_http_method = "POST"  # MOCK의 경우 무시되지만 POST로 설정
  type                    = "MOCK"
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

# API Gateway 배포 6번
resource "aws_api_gateway_deployment" "iot_deployment" {
  rest_api_id = aws_api_gateway_rest_api.iot_api.id
  depends_on  = [aws_api_gateway_integration.iot_integration] # 통합 리소스 의존성 추가
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

# 혜지님
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

# WAF v2 Web ACL 생성 6번
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

# WAF와 S3 연동 (S3의 ARN을 사용)
resource "aws_wafv2_web_acl_logging_configuration" "iot_waf_logging_acl_configure" {
  log_destination_configs = [aws_s3_bucket.iot_bucket.arn]
  resource_arn            = aws_wafv2_web_acl.iot_waf_acl.arn
  redacted_fields {
    single_header {
      name = "user-agent"
    }
  }

  depends_on = [aws_s3_bucket.iot_bucket]
}


# WAF와 API Gateway 연동
resource "aws_wafv2_web_acl_association" "iot_waf_association" {
  resource_arn = aws_api_gateway_stage.iot_stage.arn
  web_acl_arn  = aws_wafv2_web_acl.iot_waf_acl.arn

  depends_on = [aws_api_gateway_stage.iot_stage]
}

# WAF와 API Gateway 연동
resource "aws_wafv2_web_acl_association" "vehicle_waf_association" {
  resource_arn = aws_api_gateway_stage.vehicle_stage.arn  # API Gateway 스테이지 ARN
  web_acl_arn  = aws_wafv2_web_acl.vehicle_waf_acl.arn
}

# WAF와 API Gateway Stage 연동
resource "aws_wafv2_web_acl_association" "api_waf_assoc" {
  resource_arn = aws_api_gateway_stage.api_stage.arn
  web_acl_arn  = aws_wafv2_web_acl.api_waf.arn
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