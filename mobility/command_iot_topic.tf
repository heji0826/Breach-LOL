# 1) API Gateway -> EC2 인스턴스 -> Amazon RDS -> EC2 인스턴스 -> Command IoT Topic -> AWS IoT Core
# 2) API Gateway -> EC2 인스턴스 -> Amazon RDS -> EC2 인스턴스 -> Critical Command IoT Topic -> AWS IoT Core


# Provider 설정
provider "aws" {
  profile = "hyeji"
  region  = "ap-northeast-2"
}

# VPC 생성 (공유 리소스)
resource "aws_vpc" "main_vpc" {
  cidr_block = "10.0.0.0/16"
}

# Subnet 생성 (공유 리소스)
resource "aws_subnet" "main_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-northeast-2a"
}

# 추가 서브넷 생성 (다른 가용 영역에서)
resource "aws_subnet" "main_subnet_2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-northeast-2b"
}

# DB Subnet Group 생성
resource "aws_db_subnet_group" "main" {
  name       = "main"
  subnet_ids = [aws_subnet.main_subnet.id, aws_subnet.main_subnet_2.id]

  tags = {
    Name = "MainSubnetGroup"
  }
}

# Internet Gateway 생성 (공유 리소스)
resource "aws_internet_gateway" "main_igw" {
  vpc_id = aws_vpc.main_vpc.id
}

# Route Table 생성 및 Internet Gateway 연결 (공유 리소스)
resource "aws_route_table" "main_route_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_igw.id
  }
}

resource "aws_route_table_association" "main_rta" {
  subnet_id      = aws_subnet.main_subnet.id
  route_table_id = aws_route_table.main_route_table.id
}

# 보안 그룹 생성 (공유 리소스)
resource "aws_security_group" "ec2_sg" {
  vpc_id = aws_vpc.main_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

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

# IAM 역할 및 정책 (AWS IoT Core와 연동을 위한 설정)
resource "aws_iam_role" "iot_role" {
  name               = "iot_role"
  assume_role_policy = data.aws_iam_policy_document.iot_assume_role_policy.json
}

data "aws_iam_policy_document" "iot_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_policy" "iot_policy" {
  name        = "iot_policy"
  description = "Policy to allow IoT Core actions"
  policy      = data.aws_iam_policy_document.iot_policy.json
}

data "aws_iam_policy_document" "iot_policy" {
  statement {
    actions   = ["iot:*"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy_attachment" "iot_policy_attachment" {
  role       = aws_iam_role.iot_role.name
  policy_arn = aws_iam_policy.iot_policy.arn
}

resource "aws_iam_instance_profile" "iot_instance_profile" {
  name = "iot_instance_profile"
  role = aws_iam_role.iot_role.name
}

# EC2 인스턴스 (경로 1: Command IoT Topic)
resource "aws_instance" "ec2_command_topic_1" {
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.main_subnet.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.iot_instance_profile.name
  key_name                    = "command_key"

  tags = {
    Name = "ec2_command_topic_1"
  }
}

resource "aws_instance" "ec2_command_topic_2" {
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.main_subnet.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.iot_instance_profile.name
  key_name                    = "command_key"

  tags = {
    Name = "ec2_command_topic_2"
  }
}

# EC2 인스턴스 (경로 2: Critical Command IoT Topic)
resource "aws_instance" "ec2_critical_command_topic_1" {
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.main_subnet.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.iot_instance_profile.name
  key_name                    = "command_key"

  tags = {
    Name = "ec2_critical_command_topic_1"
  }
}

resource "aws_instance" "ec2_critical_command_topic_2" {
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.main_subnet.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ec2_sg.id]
  iam_instance_profile        = aws_iam_instance_profile.iot_instance_profile.name
  key_name                    = "command_key"

  tags = {
    Name = "ec2_critical_command_topic_2"
  }
}

# 로드 밸런서 및 관련 설정 추가
resource "aws_lb" "main_lb" {
  name               = "main-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.ec2_sg.id]
  subnets            = [aws_subnet.main_subnet.id, aws_subnet.main_subnet_2.id]

  enable_deletion_protection = false
}

resource "aws_lb_target_group" "main_target_group" {
  name     = "main-target-group"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.main_vpc.id
}

# 로드 밸런서 리스너 추가
resource "aws_lb_listener" "main_listener" {
  load_balancer_arn = aws_lb.main_lb.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main_target_group.arn
  }
}

# EC2 인스턴스를 로드 밸런서의 대상 그룹에 등록
resource "aws_lb_target_group_attachment" "ec2_command_topic_1_attach" {
  target_group_arn = aws_lb_target_group.main_target_group.arn
  target_id        = aws_instance.ec2_command_topic_1.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "ec2_command_topic_2_attach" {
  target_group_arn = aws_lb_target_group.main_target_group.arn
  target_id        = aws_instance.ec2_command_topic_2.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "ec2_critical_command_topic_1_attach" {
  target_group_arn = aws_lb_target_group.main_target_group.arn
  target_id        = aws_instance.ec2_critical_command_topic_1.id
  port             = 80
}

resource "aws_lb_target_group_attachment" "ec2_critical_command_topic_2_attach" {
  target_group_arn = aws_lb_target_group.main_target_group.arn
  target_id        = aws_instance.ec2_critical_command_topic_2.id
  port             = 80
}

# Amazon RDS 생성 (공유)
resource "aws_db_instance" "main_rds" {
  allocated_storage      = 20
  engine                 = "mysql"
  engine_version         = "8.0.39"
  instance_class         = "db.t3.micro"
  db_name                = "exampledb"
  username               = "admin"
  password               = "password"
  parameter_group_name   = "default.mysql8.0"
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.main.name
}

# API Gateway 생성 (공유 리소스)
resource "aws_api_gateway_rest_api" "example_api" {
  name        = "example-api"
  description = "Shared API Gateway for both routes"
}

# 첫 번째 경로 (Command IoT Topic)
resource "aws_api_gateway_resource" "example_command_resource" {
  rest_api_id = aws_api_gateway_rest_api.example_api.id
  parent_id   = aws_api_gateway_rest_api.example_api.root_resource_id
  path_part   = "example_command"
}

resource "aws_api_gateway_method" "example_command_get" {
  rest_api_id   = aws_api_gateway_rest_api.example_api.id
  resource_id   = aws_api_gateway_resource.example_command_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "example_command_integration" {
  rest_api_id             = aws_api_gateway_rest_api.example_api.id
  resource_id             = aws_api_gateway_resource.example_command_resource.id
  http_method             = aws_api_gateway_method.example_command_get.http_method
  type                    = "HTTP"
  integration_http_method = "POST"
  uri                     = "http://${aws_instance.ec2_command_topic_1.public_ip}/path" # Command EC2 Instance
}

# 두 번째 경로 (Critical Command IoT Topic)
resource "aws_api_gateway_resource" "example_critical_command_resource" {
  rest_api_id = aws_api_gateway_rest_api.example_api.id
  parent_id   = aws_api_gateway_rest_api.example_api.root_resource_id
  path_part   = "example_critical_command"
}

resource "aws_api_gateway_method" "example_critical_command_get" {
  rest_api_id   = aws_api_gateway_rest_api.example_api.id
  resource_id   = aws_api_gateway_resource.example_critical_command_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "example_critical_command_integration" {
  rest_api_id             = aws_api_gateway_rest_api.example_api.id
  resource_id             = aws_api_gateway_resource.example_critical_command_resource.id
  http_method             = aws_api_gateway_method.example_critical_command_get.http_method
  type                    = "HTTP"
  integration_http_method = "POST"
  uri                     = "http://${aws_instance.ec2_critical_command_topic_1.public_ip}/path" # Critical Command EC2 Instance
}

# API Gateway 배포
resource "aws_api_gateway_deployment" "example_deployment" {
  rest_api_id = aws_api_gateway_rest_api.example_api.id

  depends_on = [
    aws_api_gateway_integration.example_command_integration,
    aws_api_gateway_integration.example_critical_command_integration
  ]
}

# 스테이지 정의
resource "aws_api_gateway_stage" "example_stage" {
  rest_api_id   = aws_api_gateway_rest_api.example_api.id
  deployment_id = aws_api_gateway_deployment.example_deployment.id
  stage_name    = "prod"
}

# WAF 설정 및 연동
resource "aws_wafv2_web_acl" "api_waf" {
  name  = "api-waf"
  scope = "REGIONAL"
  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "api-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "api_waf_assoc" {
  resource_arn = aws_api_gateway_stage.example_stage.arn
  web_acl_arn  = aws_wafv2_web_acl.api_waf.arn
}

