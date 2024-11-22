provider "aws" {
  profile = "terraform-user"
}

/*
va
*/
data "aws_availability_zones" "available" {
  state = "available"
}

/*
web-vpc
*/

resource "aws_vpc" "web_vpc" {
  tags = {
    "Name" = "web_service_vpc"
  }

  cidr_block           = "192.168.0.0/16"
  enable_dns_hostnames = true
}

resource "aws_internet_gateway" "web_igw" {
  vpc_id = aws_vpc.web_vpc.id
  tags = {
    "Name" = "web_service_internet_gateway"
  }
}

/*
 subnet 선언 
*/
resource "aws_subnet" "public_elb_subnet" {
  count = 2
  vpc_id = aws_vpc.web_vpc.id
  cidr_block = element(["192.168.21.0/24", "192.168.22.0/24"], count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index % length(data.aws_availability_zones.available.names)]

  tags = {
    "Name" = "elb_public_subnet${count.index + 1 }"
  }

}

resource "aws_subnet" "private_web_subnet" {
  count = 3

  vpc_id            = aws_vpc.web_vpc.id
  cidr_block        = element(["192.168.10.0/24", "192.168.11.0/24", "192.168.12.0/24"], count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index % length(data.aws_availability_zones.available.names)]
  tags = {
    "Name" = "web_web_subnet${count.index + 1}"
  }
}

resource "aws_subnet" "private_db_subnet" {
  count = 3

  vpc_id            = aws_vpc.web_vpc.id
  cidr_block        = element(["192.168.13.0/24", "192.168.14.0/24", "192.168.15.0/24"], count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index % length(data.aws_availability_zones.available.names)]
  tags = {
    "Name" = "web_db_subnet${count.index + 1}"
  }
}

resource "aws_subnet" "public_nat_subnet" {
  vpc_id     = aws_vpc.web_vpc.id
  cidr_block = "192.168.20.0/24"

  tags = {
    "Name" = "web_nat_subnet"
  }
}

resource "aws_subnet" "public_bastion_host_subnet" {
  vpc_id     = aws_vpc.web_vpc.id
  cidr_block = "192.168.16.0/24"

  tags = {
    "Name" = "public_bastion_host_subnet"
  }
}

/*
  
*/


/*
  nacl 구현 장소

*/

resource "aws_network_acl" "web_nat_gateway_nacl" {
  vpc_id = aws_vpc.web_vpc.id

  ingress {
    rule_no    = 100
    protocol   = "tcp"
    from_port  = 80
    to_port    = 80
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }

  ingress {
    rule_no    = 110
    protocol   = "tcp"
    from_port  = 443
    to_port    = 443
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }
  
  ingress {
    rule_no = 100
    protocol = "-1"
    #룰 추가해야함
    
  }
  egress {
    rule_no    = 100
    protocol   = "-1"
    from_port  = 0
    to_port    = 0
    cidr_block = "0.0.0.0/0"
    action     = "allow"
  }

  tags = {
    "Name" = "nat_gateway_acl"
  }

}

resource "aws_network_acl_association" "nat_network_acl_" {
  network_acl_id = aws_network_acl.web_nat_gateway_nacl.id
  subnet_id      = aws_subnet.public_nat_subnet.id
}

/*
    route table 쓰는 장소
*/

resource "aws_route_table" "internet_route_table" {
  vpc_id = aws_vpc.web_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.web_igw.id
  }

  tags = {
    "Name" = "internet_route_table"
  }
}

resource "aws_route_table" "private_nat_route_table" {
  vpc_id = aws_vpc.web_vpc.id
  
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.web_nat_gateway.id
  }

  tags = {
    "Name" = "nat_gateway_route_table"
  }
}

resource "aws_route_table_association" "elb_route_associate" {
  count = length(aws_subnet.public_elb_subnet[*].id)
  subnet_id = aws_subnet.public_elb_subnet[count.index].id
  route_table_id = aws_route_table.internet_route_table.id
}

resource "aws_route_table_association" "nat_nat_associate" {
  subnet_id      = aws_subnet.public_nat_subnet.id
  route_table_id = aws_route_table.internet_route_table.id
}

resource "aws_route_table_association" "private_web_route_associate" {
  count          = 3
  route_table_id = aws_route_table.private_nat_route_table.id
  subnet_id      = aws_subnet.private_web_subnet[count.index].id
}

resource "aws_route_table_association" "private_db_route_associate" {
  count          = 3
  route_table_id = aws_route_table.private_nat_route_table.id
  subnet_id      = aws_subnet.private_db_subnet[count.index].id
}

resource "aws_route_table_association" "public_bastion_host_subnet_route_associate" {
  route_table_id = aws_route_table.internet_route_table.id
  subnet_id      = aws_subnet.public_bastion_host_subnet.id
}

/*
  security group
*/

resource "aws_security_group" "public_bastion_host_sg" {
  vpc_id = aws_vpc.web_vpc.id


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

resource "aws_security_group" "icmpopen" {
  vpc_id = aws_vpc.web_vpc.id
  ingress {
    from_port   = "-1"
    to_port     = "-1"
    protocol    = "icmp"
    cidr_blocks = ["192.168.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}
resource "aws_security_group" "http_open" {
  vpc_id = aws_vpc.web_vpc.id

  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_security_group" "https_open" {
  vpc_id = aws_vpc.web_vpc.id
  
  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

/*
  eip 할당
*/
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  #instance = aws_nat_gateway.web_nat_gateway.id
}

/*

  data 영역 aim 정의

*/



/*
  instance 생성 구문
*/

resource "aws_nat_gateway" "web_nat_gateway" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_nat_subnet.id

  tags = {
    "Name" = "web_nat_gateway"
  }
}

resource "aws_instance" "bastion_host" {
  ami           = "ami-040c33c6a51fd5d96"
  instance_type = "t3.small"
  subnet_id     = aws_subnet.public_bastion_host_subnet.id
  key_name = "public-ec2-key"
  associate_public_ip_address = true
  security_groups = [aws_security_group.icmpopen.id,aws_security_group.public_bastion_host_sg.id]

  tags = {
    "Name" = "web_service_bastion_host_instance"
  }

}

resource "aws_instance" "aws_web_servers" {
  count         = (length(aws_subnet.private_web_subnet))
  ami           = "ami-040c33c6a51fd5d96"
  instance_type = "t3.small"
  subnet_id     = aws_subnet.private_web_subnet[count.index].id
  key_name = "public-ec2-key"
  security_groups = [ aws_security_group.icmpopen.id , aws_security_group.public_bastion_host_sg.id , aws_security_group.http_open.id, aws_security_group.https_open.id]
  tags = {
    "Name" = "web_server_instance_${count.index}"
  }
}

/*
  db config

*/

resource "aws_db_subnet_group" "web_db_subnet_group" {
  name       = "web_db_subnet_group"
  subnet_ids = aws_subnet.private_db_subnet[*].id
  tags = {
    "Name" = "web_db_subnet_group"
  }
}

resource "aws_db_subnet_group" "web_db_master_subnet_group" {
  name = "web_master_subnet_group"
  subnet_ids = aws_subnet.private_db_subnet[*].id
  tags = {
    "Name" = "web_db_subnet_group"
  }
}
/*

 db instance

*/

resource "aws_db_instance" "web_primary_db_server" {
  allocated_storage = 10
  db_name = "web_db"
  engine = "mariadb"
  engine_version = "10.11.9"
  instance_class = "db.t3.micro"
  username = "admin"
  password = "SecurePssw0rd"
  db_subnet_group_name = aws_db_subnet_group.web_db_master_subnet_group.id
  publicly_accessible = false
  backup_retention_period = 7
  final_snapshot_identifier = "web-primary-db"
  identifier = "web-primary-db"
  tags = {
    "Name" = "web_Server_Primary_DB"
  }
}

resource "aws_db_instance" "aws_read_replica_db_server" {

  count                = 2
  engine               = "mariadb"
  engine_version       = "10.11.9"
  instance_class       = "db.t3.micro"
  
  replicate_source_db = aws_db_instance.web_primary_db_server.identifier
  skip_final_snapshot = false
  publicly_accessible  = false

  identifier           = "web-read-replica-db${count.index}"
  tags = {
    "Name" = "webDatabase${count.index}"
  }
  depends_on = [ aws_db_instance.web_primary_db_server ]
}



/*

  load balancer 설정

*/




resource "aws_lb_target_group" "web_server_loadbalancer_tg" {
  name     = "webServerLoadLanaberTargetGroup"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.web_vpc.id
}


/*
 load balancer security group
*/

resource "aws_security_group" "web_alb_sg" {
  vpc_id = aws_vpc.web_vpc.id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
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
}

resource "aws_lb_target_group_attachment" "regist_web_instance" {
  count            = length(aws_instance.aws_web_servers[*])
  target_group_arn = aws_lb_target_group.web_server_loadbalancer_tg.arn
  target_id        = aws_instance.aws_web_servers[count.index].id
  port             = 80
}

# /*
#  로드 밸런서 생성
# */
resource "aws_lb" "web_servcer_loadbalancer" {
  name               = "webServiceAlb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.web_alb_sg.id]
  subnets            = [for subnet in aws_subnet.public_elb_subnet : subnet.id]
}

# /*
#   load balancer와 연결 설정
# */

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.web_servcer_loadbalancer.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_server_loadbalancer_tg.arn
  }
}

/*
  auto scaling 설정

*/

/*
  보안 기능 코드 블록
*/

/*
  waf 및 보안 장비 log 서버

*/
resource "aws_s3_bucket" "waf_log_storage" {
  bucket = "web-waf-logs-bucket"
}

resource "aws_s3_bucket" "cloudtrail_backup_storage" {
  bucket = "cloudtrail-backup-log"
}
/*
 iam 계정생성 
*/

resource "aws_iam_role" "waf_log_role" {
  name = "waf-log-role"

  assume_role_policy = jsondecode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "wafv2.amazonaws.com"
        }
      }
    ]
  })
}

/*
  정책 생성
*/

resource "aws_iam_policy" "waf_s3_log_policy" {
  name        = "WAF-S3-Log-Policy"
  description = "Allow WAF to write logs to S3"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action    = "s3:PutObject",
        Effect    = "Allow",
        Resource  = "arn:aws:s3:::web-waf-logs-bucket/*"  # WAF가 로그를 쓸 S3 버킷
      }
    ]
  })
}

/*
  정책 연결
*/

resource "aws_iam_role_policy_attachment" "waf_log_role_policy_attachment" {
  policy_arn = aws_iam_policy.waf_s3_log_policy.arn
  role = aws_iam_role.waf_log_role.name

  depends_on = [ aws_iam_policy.waf_s3_log_policy, aws_iam_role.waf_log_role]
}

# 기본적으로 elb에는 standard aws_shield가 활성화되어 있음.
# resource "aws_shield_protection" "web_alb_shield_protection" {
#   name = "web-service-aws-shield"
#   resource_arn = aws_lb.web_servcer_loadbalancer.arn

#   tags = {
#     "Name" = "web-elb-aws-shield"
#   }
#   depends_on = [ aws_lb.web_servcer_loadbalancer ]
# }


/*
 보안장비 instance code block

*/

# resource "cloudtrail" "web_service_cloudtrail" {
  
# }


resource "aws_wafv2_web_acl" "web_acl" {
  name ="web-acl-for-alb"
  scope = "REGIONAL"
  default_action {
    allow {
      
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name = "AWSManagedRulesCommonRuleSet"
    sampled_requests_enabled = true
  }  
}

/*
  log backup 정책 설정
*/

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging_acl_configure" {
  log_destination_configs = [aws_s3_bucket.waf_log_storage.arn]
  resource_arn = aws_wafv2_web_acl.web_acl.arn
  redacted_fields {
    single_header {
      name = "user-agent"
    }
  }
}


/*


*/

output "aws_bastion_public_ip" {
  value = aws_instance.bastion_host.public_ip
}
