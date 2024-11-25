terraform {
  required_version = ">= 1.5.0"
  required_providers {
    
    aws = {
      version = "~> 5.75.0"
      source  = "hashicorp/aws"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "~> 2.3.5"
    }
    time = {
      source  = "hashicorp/time"
      version = "0.12.1"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2.1"
    }
  }
}
variable "secret_key" {
  type = string
}
variable "access_key" {
  type = string
}
provider "aws" {
  profile = "nocomplaint"
  region  = "ap-northeast-2"
}

# VPC 정의
resource "aws_vpc" "LAN_vpc" {
  cidr_block           = "192.168.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "LAN-vpc"
  }
}

resource "aws_vpc" "LAN_server_vpc" {
  cidr_block           = "172.10.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name = "LAN-server-vpc"
  }
}

# Subnet 정의
# Server VPC Subnets
resource "aws_subnet" "LAN_server_db_subnet1" {
  vpc_id            = aws_vpc.LAN_server_vpc.id
  cidr_block        = "172.10.10.0/24"
  availability_zone = "ap-northeast-2a"
  
  tags = {
    Name = "LAN-server-db-subnet1"
  }
}

resource "aws_subnet" "LAN_server_db_subnet2" {
  vpc_id            = aws_vpc.LAN_server_vpc.id
  cidr_block        = "172.10.20.0/24"
  availability_zone = "ap-northeast-2c"
  
  tags = {
    Name = "LAN-server-db-subnet2"
  }
}

resource "aws_subnet" "LAN_server_eks_subnet1" {
  vpc_id            = aws_vpc.LAN_server_vpc.id
  cidr_block        = "172.10.30.0/24"
  availability_zone = "ap-northeast-2a"
  
  tags = {
    Name = "LAN-server-eks-subnet1"
    "kubernetes.io/cluster/my-eks" = "shared"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}

resource "aws_subnet" "LAN_server_eks_subnet2" {
  vpc_id            = aws_vpc.LAN_server_vpc.id
  cidr_block        = "172.10.40.0/24"
  availability_zone = "ap-northeast-2c"
  
  tags = {
    Name = "LAN-server-eks-subnet2"
    "kubernetes.io/cluster/my-eks" = "shared"
    "kubernetes.io/role/internal-elb" = "1"
    "kubernetes.io/role/elb" = "1"
  }
}

# LAN VPC Subnets
resource "aws_subnet" "WAN_public_subnet" {
  vpc_id                  = aws_vpc.LAN_vpc.id
  cidr_block              = "192.168.10.0/24"
  availability_zone       = "ap-northeast-2a"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "WAN-public-subnet"
  }
}

resource "aws_subnet" "LAN_private_user_subnet" {
  vpc_id            = aws_vpc.LAN_vpc.id
  cidr_block        = "192.168.20.0/24"
  availability_zone = "ap-northeast-2a"
  
  tags = {
    Name = "LAN-private-user-subnet"
  }
}

resource "aws_subnet" "LAN_private_server_subnet" {
  vpc_id            = aws_vpc.LAN_vpc.id
  cidr_block        = "192.168.30.0/24"
  availability_zone = "ap-northeast-2a"
  
  tags = {
    Name = "LAN-private-server-subnet"
  }
}

resource "aws_subnet" "LAN_private_db_access_server_subnet" {
  vpc_id            = aws_vpc.LAN_vpc.id
  cidr_block        = "192.168.40.0/24"
  availability_zone = "ap-northeast-2a"
  
  tags = {
    Name = "LAN-private-db-access-server-subnet"
  }
}

# DB Subnet Group
resource "aws_db_subnet_group" "LAN_private_db_subnet_group" {
  name       = "lan-private-db-subnet-group"
  subnet_ids = [aws_subnet.LAN_server_db_subnet1.id, aws_subnet.LAN_server_db_subnet2.id]
  
  tags = {
    Name = "LAN-server-db-subnet-group"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "WAN_igw" {
  vpc_id = aws_vpc.LAN_vpc.id
  
  tags = {
    Name = "WAN-igw"
  }
}

# NAT Gateway 및 EIP
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  
  tags = {
    Name = "NAT-EIP"
  }
}

resource "aws_nat_gateway" "nat_gateway" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.WAN_public_subnet.id
  
  tags = {
    Name = "NAT-GW"
  }
}

# Route Tables
resource "aws_route_table" "WAN_public_route_table" {
  vpc_id = aws_vpc.LAN_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.WAN_igw.id
  }
  
  tags = {
    Name = "WAN-public-rt"
  }
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.LAN_vpc.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gateway.id
  }
  
  route {
    cidr_block = aws_vpc.LAN_server_vpc.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.vpc_peering.id
  }
  
  tags = {
    Name = "private-rt"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.WAN_public_subnet.id
  route_table_id = aws_route_table.WAN_public_route_table.id
}

resource "aws_route_table_association" "private_user" {
  subnet_id      = aws_subnet.LAN_private_user_subnet.id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_route_table_association" "private_server" {
  subnet_id      = aws_subnet.LAN_private_server_subnet.id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_route_table_association" "private_db_access" {
  subnet_id      = aws_subnet.LAN_private_db_access_server_subnet.id
  route_table_id = aws_route_table.private_route_table.id
}

# Security Groups
resource "aws_security_group" "WAN_USER_public_sg" {
  name        = "WAN-USER-public-sg"
  description = "Security group for public user instances"
  vpc_id      = aws_vpc.LAN_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "WAN-USER-public-sg"
  }
}

resource "aws_security_group" "LAN_USER_private_sg" {
  name        = "LAN-USER-private-sg"
  description = "Security group for private user instances"
  vpc_id      = aws_vpc.LAN_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "LAN-USER-private-sg"
  }
}

resource "aws_security_group" "LAN_db_private_sg" {
  name        = "LAN-db-private-sg"
  description = "Security group for RDS"
  vpc_id      = aws_vpc.LAN_server_vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [
      aws_security_group.LAN_db_access_server_private_sg.id,
      aws_security_group.LAN_eks_node_private_sg.id
    ]
    description     = "Allow MariaDB access from DB access server and EKS nodes"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "LAN-db-private-sg"
  }
}

# EC2 Instances
resource "aws_instance" "WAN_public_USER" {
  ami                    = "ami-040c33c6a51fd5d96"
  instance_type          = "t2.micro"
  key_name               = "nokey"
  subnet_id              = aws_subnet.WAN_public_subnet.id
  vpc_security_group_ids = [aws_security_group.WAN_USER_public_sg.id]

  tags = {
    Name = "WAN-public-USER"
  }
}

resource "aws_instance" "LAN_private_user" {
  ami                    = "ami-040c33c6a51fd5d96"
  instance_type          = "t2.micro"
  key_name               = "nokey"
  subnet_id              = aws_subnet.LAN_private_user_subnet.id
  vpc_security_group_ids = [aws_security_group.LAN_USER_private_sg.id]

  tags = {
    Name = "LAN-private-USER"
  }
}


# RDS Instance
resource "aws_db_instance" "LAN_private_rds" {
  identifier           = "database-1"
  engine              = "mariadb"
  engine_version      = "10.11.9"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  storage_type        = "gp2"
  username            = "admin"
  password            = "maria1234"
  db_name             = "care"
  skip_final_snapshot = true
  apply_immediately   = true

  db_subnet_group_name   = aws_db_subnet_group.LAN_private_db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.LAN_db_private_sg.id]

  tags = {
    Name = "LAN-private-db"
  }
}

# VPC Peering
resource "aws_vpc_peering_connection" "vpc_peering" {
  vpc_id        = aws_vpc.LAN_vpc.id
  peer_vpc_id   = aws_vpc.LAN_server_vpc.id
  auto_accept   = true

  tags = {
    Name = "VPC-Peering"
  }
}

# EKS 클러스터 보안 그룹
resource "aws_security_group" "LAN_eks_cluster_sg" {
  name        = "LAN-eks-cluster-sg"
  description = "Security group for EKS cluster control plane"
  vpc_id      = aws_vpc.LAN_server_vpc.id

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description     = "Allow pods to communicate with the cluster API Server"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "LAN-eks-cluster-sg"
  }
}

# EKS 노드 보안 그룹
resource "aws_security_group" "LAN_eks_node_private_sg" {
  name        = "LAN-eks-node-private-sg"
  description = "Security group for EKS worker nodes"
  vpc_id      = aws_vpc.LAN_server_vpc.id

  ingress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description     = "Allow cluster control plane to communicate with worker nodes"
  }

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    self      = true
    description = "Allow worker nodes to communicate with each other"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name = "LAN-eks-node-private-sg"
  }
}

# 3. EKS 모듈 설정
module "eks" {
  source  = "terraform-aws-modules/eks/aws"


  cluster_name    = "my-eks"
  cluster_version = "1.30"
  vpc_id          = aws_vpc.LAN_server_vpc.id
  
  subnet_ids = [
    aws_subnet.LAN_server_eks_subnet1.id, 
    aws_subnet.LAN_server_eks_subnet2.id
  ]

  create_cluster_security_group = false
  create_node_security_group   = false
  
  cluster_security_group_id    = aws_security_group.LAN_eks_cluster_sg.id
  node_security_group_id      = aws_security_group.LAN_eks_node_private_sg.id

  eks_managed_node_groups = {
    initial = {
      instance_types = ["t3.small"]
      min_size      = 2
      max_size      = 3
      desired_size  = 2
    }
  }

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true

  enable_cluster_creator_admin_permissions = true
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023*"]
  }
}
# 현재 AWS 계정 ID를 가져오기 위한 data source
data "aws_caller_identity" "current" {}

# DB Access Server Security Group
resource "aws_security_group" "LAN_db_access_server_private_sg" {
  name        = "LAN-db-access-server-private-sg"
  description = "Security group for DB access server"
  vpc_id      = aws_vpc.LAN_vpc.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    security_groups = [aws_security_group.LAN_SERVER_private_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "LAN-db-access-server-private-sg"
  }
}

# LAN_server_vpc용 라우팅 테이블
resource "aws_route_table" "LAN_server_route_table" {
  vpc_id = aws_vpc.LAN_server_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.LAN_server_nat_gateway.id
  }
  
  route {
    cidr_block = aws_vpc.LAN_vpc.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.vpc_peering.id
  }
  
  tags = {
    Name = "LAN-server-private-rt"
  }
}

# LAN_server_vpc용 퍼블릭 서브넷
resource "aws_subnet" "LAN_server_public_subnet" {
  vpc_id            = aws_vpc.LAN_server_vpc.id
  cidr_block        = "172.10.0.0/24"  # 새로운 CIDR 블록 할
  availability_zone = "ap-northeast-2a"
  map_public_ip_on_launch = true
  
  tags = {
    Name = "LAN-server-public-subnet"
  }
}

# LAN_server_vpc용 Internet Gateway
resource "aws_internet_gateway" "LAN_server_igw" {
  vpc_id = aws_vpc.LAN_server_vpc.id
  
  tags = {
    Name = "LAN-server-igw"
  }
}

# LAN_server_vpc용 NAT Gateway EIP
resource "aws_eip" "LAN_server_nat_eip" {
  domain = "vpc"
  
  tags = {
    Name = "LAN-server-NAT-EIP"
  }
}

# LAN_server_vpc용 NAT Gateway
resource "aws_nat_gateway" "LAN_server_nat_gateway" {
  allocation_id = aws_eip.LAN_server_nat_eip.id
  subnet_id     = aws_subnet.LAN_server_public_subnet.id
  
  tags = {
    Name = "LAN-server-NAT-GW"
  }
}

# LAN_server_vpc용 퍼블릭 라우팅 테이블
resource "aws_route_table" "LAN_server_public_route_table" {
  vpc_id = aws_vpc.LAN_server_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.LAN_server_igw.id
  }
  
  route {
    cidr_block = aws_vpc.LAN_vpc.cidr_block
    vpc_peering_connection_id = aws_vpc_peering_connection.vpc_peering.id
  }
  
  tags = {
    Name = "LAN-server-public-rt"
  }
}

# 퍼블릭 서브과 라우팅 테이블 연결
resource "aws_route_table_association" "server_public" {
  subnet_id      = aws_subnet.LAN_server_public_subnet.id
  route_table_id = aws_route_table.LAN_server_public_route_table.id
}

# Private Server Security Group 추가
resource "aws_security_group" "LAN_SERVER_private_sg" {
  name        = "LAN-SERVER-private-sg"
  description = "Security group for private server instances"
  vpc_id      = aws_vpc.LAN_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "LAN-SERVER-private-sg"
  }
}

# LAN_private_server Instance 수정
resource "aws_instance" "LAN_private_server" {
  ami                    = "ami-040c33c6a51fd5d96"
  instance_type          = "t2.micro"
  key_name               = "nokey"
  subnet_id              = aws_subnet.LAN_private_server_subnet.id
  vpc_security_group_ids = [aws_security_group.LAN_SERVER_private_sg.id]  # 새로운 보안 그룹 적

  tags = {
    Name = "LAN-private-SERVER"
  }
}

resource "aws_instance" "LAN_db_access_server" {
  ami                    = "ami-040c33c6a51fd5d96"
  instance_type          = "t2.micro"
  key_name               = "nokey"
  subnet_id              = aws_subnet.LAN_private_db_access_server_subnet.id
  vpc_security_group_ids = [aws_security_group.LAN_db_access_server_private_sg.id]  # 새로운 보안 그룹 적

  tags = {
    Name = "LAN-db-access-server"
  }
}

# EKS 관리 서버용 Security Group
resource "aws_security_group" "LAN_eks_admin_private_sg" {
  name        = "LAN-eks-admin-private-sg"
  description = "Security group for EKS admin server"
  vpc_id      = aws_vpc.LAN_server_vpc.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "LAN-eks-admin-private-sg"
  }
}

# EKS 관리 서버 인스턴스
resource "aws_instance" "LAN_eks_admin_server" {
  ami           = "ami-040c33c6a51fd5d96"
  instance_type = "t2.micro"
  key_name      = "nokey"
  subnet_id     = aws_subnet.LAN_server_eks_subnet1.id
  vpc_security_group_ids = [aws_security_group.LAN_eks_admin_private_sg.id]
  monitoring                  = true
  tags = {
    Name = "LAN-eks-admin-server"
  }
  user_data = templatefile("${path.module}/userdata.sh.tpl", {

    ACCESS_KEY = var.access_key
    SECRET_KEY = var.secret_key
  })
}

# LAN_server_vpc의 서브넷들과 라우팅 테이블 연결
resource "aws_route_table_association" "server_eks_subnet1" {
  subnet_id      = aws_subnet.LAN_server_eks_subnet1.id
  route_table_id = aws_route_table.LAN_server_route_table.id
}

resource "aws_route_table_association" "server_eks_subnet2" {
  subnet_id      = aws_subnet.LAN_server_eks_subnet2.id
  route_table_id = aws_route_table.LAN_server_route_table.id
}

resource "aws_route_table_association" "server_db_subnet1" {
  subnet_id      = aws_subnet.LAN_server_db_subnet1.id
  route_table_id = aws_route_table.LAN_server_route_table.id
}

resource "aws_route_table_association" "server_db_subnet2" {
  subnet_id      = aws_subnet.LAN_server_db_subnet2.id
  route_table_id = aws_route_table.LAN_server_route_table.id
}

resource "aws_guardduty_detector" "wan_guardduty" {
  enable = true
  finding_publishing_frequency = "ONE_HOUR"
}

# WAF ACL 생성 (최소 설정)
resource "aws_wafv2_web_acl" "wan_waf" {
  name        = "wan-waf-acl"
  description = "WAF ACL for WAN entry"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  # 기본 Rate limit 규칙 (과도한 요청 차단)
  rule {
    name     = "RateLimitRule"
    priority = 1

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = 2000  # 5분당 2000개 요청으로 제한
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "RateLimitMetric"
      sampled_requests_enabled  = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name               = "WANWAFMetric"
    sampled_requests_enabled  = true
  }
}

# WAF 로그 저장용 S3 버킷 (프리티어 범위 내)
resource "aws_s3_bucket" "waf_logs" {
  bucket = "wan-waf-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy = true

  tags = {
    Name = "WAF-Logs"
  }
}

# S3 버킷 암호화 설정 (무료)
resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# CloudWatch 로그 그룹 생성 (무료 티어: 5GB/월까지 무료)
resource "aws_cloudwatch_log_group" "waf_log_group" {
  name              = "/aws/waf/wan"
  retention_in_days = 7  # 7일간 보관 (비용 최소화)

  tags = {
    Name = "WAF-Logs"
  }
}

# CloudTrail 설정 (무료 티어: 관리 이벤트는 무료)
resource "aws_cloudtrail" "wan_trail" {
  name                          = "wan-cloudtrail"
  s3_bucket_name               = aws_s3_bucket.waf_logs.id
  include_global_service_events = false  # 글로벌 서비스 이벤트 제외 (비용 절감)
  is_multi_region_trail        = false   # 단일 리전으로 제한 (비용 절감)
  enable_logging               = true

  event_selector {
    read_write_type           = "WriteOnly"  # 쓰기 작업만 로깅
    include_management_events = true
  }

  tags = {
    Name = "WAN-CloudTrail"
  }
}

# CloudTrail 로그를 위한 S3 버킷 정책
resource "aws_s3_bucket_policy" "cloudtrail_policy" {
  bucket = aws_s3_bucket.waf_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.waf_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.waf_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
          StringLike = {
            "s3:x-amz-acl" = ["bucket-owner-full-control"]
          }
        }
      },
      {
        Sid    = "AllowCloudTrailService"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ]
        Resource = aws_s3_bucket.waf_logs.arn
      }
    ]
  })
}

# S3 버킷 버전 관리 활성화 (CloudTrail 요구사항)
resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# S3 버킷 퍼블릭 액세스 차단
resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudWatch 메트릭 알람 (무료 티어: 기본 모니터링 메트릭 10개까지 무료)
resource "aws_cloudwatch_metric_alarm" "waf_requests" {
  alarm_name          = "waf-high-request-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "RequestCount"
  namespace           = "AWS/WAF"
  period              = "300"  # 5분
  statistic           = "Sum"
  threshold           = "1000"
  alarm_description   = "This metric monitors WAF request count"
  
  dimensions = {
    WebACL = aws_wafv2_web_acl.wan_waf.name
    Region = "ap-northeast-2"
  }
}
