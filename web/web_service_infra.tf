provider "aws" {
  profile = "terraform-user"  
}

/*d
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
  count             = 2
  vpc_id            = aws_vpc.web_vpc.id
  cidr_block        = element(["192.168.21.0/24", "192.168.22.0/24"], count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index % length(data.aws_availability_zones.available.names)]
  
  tags = {
    "Name" = "elb_public_subnet${count.index + 1}"
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
    rule_no = 100
    protocol = "tcp"
    from_port = 1024
    to_port = 65534
    cidr_block = "0.0.0.0/0"
    action = "allow"
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
  count          = length(aws_subnet.public_elb_subnet[*].id)
  subnet_id      = aws_subnet.public_elb_subnet[count.index].id
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
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 8080
    to_port = 8080
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

resource "aws_security_group" "https_open" {
  vpc_id = aws_vpc.web_vpc.id

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
  ami                         = "ami-040c33c6a51fd5d96"
  instance_type               = "t3.small"
  subnet_id                   = aws_subnet.public_bastion_host_subnet.id
  key_name                    = "public-ec2-key"
  associate_public_ip_address = true
  security_groups             = [aws_security_group.icmpopen.id, aws_security_group.public_bastion_host_sg.id]

  tags = {
    "Name" = "web_service_bastion_host_instance"
  }

}

resource "aws_instance" "aws_web_servers" {
  count           = (length(aws_subnet.private_web_subnet))
  ami             = "ami-0b793e03812de20d6"
  instance_type   = "t3.small"
  subnet_id       = aws_subnet.private_web_subnet[count.index].id
  key_name        = "public-ec2-key"
  security_groups = [aws_security_group.icmpopen.id, aws_security_group.public_bastion_host_sg.id, aws_security_group.http_open.id, aws_security_group.https_open.id]
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
  name       = "web_master_subnet_group"
  subnet_ids = aws_subnet.private_db_subnet[*].id
  tags = {
    "Name" = "web_db_subnet_group"
  }
}
/*

 db instance

*/

resource "aws_db_instance" "web_primary_db_server" {
  allocated_storage         = 10
  db_name                   = "web_db"
  engine                    = "mariadb"
  engine_version            = "10.11.9"
  instance_class            = "db.t3.micro"
  username                  = "admin"
  password                  = "SecurePssw0rd"
  vpc_security_group_ids = [aws_security_group.rds_sg.id]
  db_subnet_group_name      = aws_db_subnet_group.web_db_master_subnet_group.id
  publicly_accessible       = false
  backup_retention_period   = 7
  skip_final_snapshot = true
  identifier                = "web-primary-db"
  tags = {
    "Name" = "web_Server_Primary_DB"
  }
}

resource "aws_db_instance" "aws_read_replica_db_server" {

  count          = 2
  engine         = "mariadb"
  engine_version = "10.11.9"
  instance_class = "db.t3.micro"

  replicate_source_db = aws_db_instance.web_primary_db_server.identifier
  skip_final_snapshot = true
  publicly_accessible = false
  identifier = "web-read-replica-db${count.index}"
  tags = {
    "Name" = "webDatabase${count.index}"
  }
  depends_on = [aws_db_instance.web_primary_db_server]
}



/*

  load balancer 설정

*/




resource "aws_lb_target_group" "web_server_loadbalancer_tg" {
  name     = "web-service-loadbalancer-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.web_vpc.id
  
  health_check {
    protocol = "HTTP"
    path = "/"
    port = "8080"
    interval = 30
    timeout = 5
    healthy_threshold = 3
    unhealthy_threshold = 3
  }
}


/*
 load balancer security group
*/

resource "aws_security_group" "rds_sg" {
  name = "rds-security-group"
  vpc_id =  aws_vpc.web_vpc.id

  ingress {
    from_port = 3306
    to_port = 3306
    protocol = "tcp"
    cidr_blocks = ["192.168.0.0/16"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

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
    from_port = 8080
    to_port = 8080
    protocol = "tcp"
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
  port             = 8080
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

  # access_logs {
  #   enabled = true
  #   bucket = ""
  #   prefix = "logs/alb/"
  # }

}

# /*
#   load balancer와 연결 설정
# */
resource "aws_lb_listener" "http80" {
  load_balancer_arn = aws_lb.web_servcer_loadbalancer.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type             = "redirect"
   redirect {
      protocol     = "HTTPS"
      port         = "443"
      status_code  = "HTTP_301"  # 영구적 리다이렉션
    }
  }
}

resource "aws_lb_listener" "https_listener" {
  load_balancer_arn = aws_lb.web_servcer_loadbalancer.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn = "arn:aws:acm:ap-northeast-2:137068221242:certificate/699e2e65-4fec-45a5-a732-c5d9b8914f4d"
  
  default_action {
    type = "forward"
    forward {
      target_group {
        arn = aws_lb_target_group.web_server_loadbalancer_tg.arn  
      }
    }
  }
}

/*
  보안 기능 코드 블록
*/

/*
  waf 및 보안 장비 log 서버

*/
resource "aws_s3_bucket" "waf_log_storage" {
  bucket = "aws-waf-logs-web-service-team-logs-bucket"
  # force_destroy = true
}

resource "aws_s3_bucket" "cloudtrail_backup_storage" {
  bucket = "cloudtrail-backup-log"
  # force_destroy = true
}
/*
 iam 계정생성 
*/

resource "aws_iam_role" "waf_log_role" {
  name = "waf-log-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Effect": "Allow",
      "Principal": {
        "Service": "wafv2.amazonaws.com"
      }
    }
  ]
}
POLICY
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
        Action   = "s3:PutObject",
        Effect   = "Allow",
        Resource = "${aws_s3_bucket.waf_log_storage.arn}/*"
      }
    ]
  })
}

/*
  정책 연결
*/

resource "aws_iam_role_policy_attachment" "waf_log_role_policy_attachment" {
  policy_arn = aws_iam_policy.waf_s3_log_policy.arn
  role       = aws_iam_role.waf_log_role.name

  depends_on = [aws_iam_policy.waf_s3_log_policy , aws_iam_role.waf_log_role]
}

/*
 보안장비 instance code block

*/


resource "aws_cloudwatch_log_group" "web_service_loadbalancer" {
  name = "web-loadbalancer-watch"
  tags = {
    Application = "Web"
    Location = "alb"
  }
}

/*
  cloudtrail 설정
*/







/*
  guard duty 옵션
*/

resource "aws_guardduty_detector" "web_service_guardduty_config" {
  enable =  true  
  finding_publishing_frequency = "ONE_HOUR"
}

resource "aws_wafv2_web_acl" "web_acl" {
  name  = "web-acl-for-alb"
  scope = "REGIONAL"
  default_action {
    allow {

    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "AWSManagedRulesCommonRuleSet"
    sampled_requests_enabled   = true
  }
}

/*
  log backup 정책 설정
*/

resource "aws_wafv2_web_acl_logging_configuration" "waf_logging_acl_configure" {
  log_destination_configs = [aws_s3_bucket.waf_log_storage.arn]
  resource_arn            = aws_wafv2_web_acl.web_acl.arn
  redacted_fields {
    single_header {
      name = "user-agent"
    }
  }

  depends_on = [ aws_s3_bucket.waf_log_storage ]
}


/*
  auto scaling config

*/

resource "aws_launch_template" "web_service_launch_config" {
  image_id = "ami-0b793e03812de20d6"
  instance_type = "t3.small"
  key_name = "public-ec2-key"

  network_interfaces {
    security_groups = [
    aws_security_group.icmpopen.id, 
    aws_security_group.public_bastion_host_sg.id, 
    aws_security_group.http_open.id, 
    aws_security_group.https_open.id
    ]
  }

  tags ={
    "Name" = "autoscaling-webservice-ec2-tg"
  }
}


# /*
#   auto scaling
# */
resource "aws_autoscaling_group" "web_service_autoscaling_group" {
  name = "web-service-asg"
  max_size = 4
  min_size = 2
  vpc_zone_identifier = [ for subnet in aws_subnet.private_web_subnet : subnet.id]
  

  launch_template {
    id = aws_launch_template.web_service_launch_config.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 60
    }
  }

  tag {
      key                 = "Name"
      value               = "web-service-instance-autoscaling"
      propagate_at_launch = true
    }
  

}

/*

  route 53

*/

data "aws_route53_zone" "web_service_domain" {
  name = "atev22.click"
  
}

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.web_service_domain.id 
  name = "www"
  type ="A"
  
  alias {
    name = aws_lb.web_servcer_loadbalancer.dns_name
    zone_id = aws_lb.web_servcer_loadbalancer.zone_id
    evaluate_target_health = true
  } 
}




output "aws_bastion_public_ip" {
  value = aws_instance.bastion_host.public_ip
}

