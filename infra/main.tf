terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "5.74.0"
    }
  }
}

provider "aws" {
  profile = "nocomplaint"
}

resource "aws_vpc" "LAN_vpc" {
  cidr_block = "192.168.0.0/16"
  enable_dns_hostnames = true
  tags = {
    "Name" = "LAN-vpc"
  }
}

resource "aws_subnet" "WAN_public_subnet" {
  vpc_id = aws_vpc.LAN_vpc.id
  cidr_block = "192.168.10.0/24"
  availability_zone = "ap-northeast-2a"
  map_public_ip_on_launch = true
  tags = {
    "Name" = "WAN-public-subnet"
  }
}

resource "aws_subnet" "LAN_private_user_subnet" {
  vpc_id = aws_vpc.LAN_vpc.id
  cidr_block = "192.168.20.0/24"
  availability_zone = "ap-northeast-2a"
  tags = {
    "Name" = "LAN-private-user-subnet"
  }
}

resource "aws_subnet" "LAN_private_server_subnet" {
  vpc_id = aws_vpc.LAN_vpc.id
  cidr_block = "192.168.30.0/24"
  availability_zone = "ap-northeast-2a"
  tags = {
    "Name" = "LAN-private-server-subnet"
  }
}

resource "aws_internet_gateway" "WAN_igw" {
  vpc_id = aws_vpc.LAN_vpc.id
  tags = {
    Name = "WAN-igw"
  }
  
}

resource "aws_route_table" "WAN_public_route_table" {
  vpc_id = aws_vpc.LAN_vpc.id
  tags = {
    "Name" = "WAN-public-rt"
  }
}

resource "aws_route" "tf_public_route" {
  route_table_id         = aws_route_table.WAN_public_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.WAN_igw.id
}

resource "aws_route_table_association" "WAN_public_association" {
  route_table_id = aws_route_table.WAN_public_route_table.id
  subnet_id = aws_subnet.WAN_public_subnet.id
}

resource "aws_security_group" "WAN_USER_public_sg" {
  name = "WAN-USER-public-sg"
    description = "USER-allow-rule"
    vpc_id = aws_vpc.LAN_vpc.id
    ingress {
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = [ "0.0.0.0/0" ]
      
    }
    ingress {
      from_port = -1
      to_port = -1
      protocol = "icmp"
      cidr_blocks = [ "0.0.0.0/0" ]
      
    }
    egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }

  tags = {
    "Name" = "WAN-USER-public-sg"
  }
  
}

resource "aws_security_group" "LAN_USER_private_sg" {
  name = "LAN-USER-private-sg"
    description = "USER-allow-rule"
    vpc_id = aws_vpc.LAN_vpc.id
    ingress {
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = [ "0.0.0.0/0" ]
      
    }
    ingress {
      from_port = -1
      to_port = -1
      protocol = "icmp"
      cidr_blocks = [ "0.0.0.0/0" ]
      
    }
    egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }

  tags = {
    "Name" = "LAN-USER-private-sg"
  }
  
}

resource "aws_security_group" "LAN_server_private_sg" {
  name = "LAN-server-private-sg"
    description = "server-allow-rule"
    vpc_id = aws_vpc.LAN_vpc.id
    ingress {
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = [ "0.0.0.0/0" ]
      
    }
    ingress {
      from_port = -1
      to_port = -1
      protocol = "icmp"
      cidr_blocks = [ "0.0.0.0/0" ]
      
    }
    egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }

  tags = {
    "Name" = "LAN-server-private-sg"
  }
  
}

resource "aws_security_group" "LAN_eni_public_sg" {
  name = "LAN-eni-public-sg"
    description = "USER-allow-rule"
    vpc_id = aws_vpc.LAN_vpc.id
    ingress {
      from_port = 22
      to_port = 22
      protocol = "tcp"
      cidr_blocks = [ "0.0.0.0/0" ]
      
    }
    ingress {
      from_port = -1
      to_port = -1
      protocol = "icmp"
      cidr_blocks = [ "0.0.0.0/0" ]
      
    }
    egress {
      from_port = 0
      to_port = 0
      protocol = "-1"
      cidr_blocks = ["0.0.0.0/0"]
    }

  tags = {
    "Name" = "LAN-eni-public-sg"
  }
  
}


resource "aws_instance" "WAN_public_USER" {
  ami                    = "ami-040c33c6a51fd5d96" #ubuntu
  instance_type          = "t2.micro"
  key_name               = "nokey"
  subnet_id              = aws_subnet.WAN_public_subnet.id
  vpc_security_group_ids = [aws_security_group.WAN_USER_public_sg.id]
  
  tags = {
    Name = "WAN-public_USER"
  }
}


resource "aws_route_table" "WAN_public_USER_route_table" {
  vpc_id = aws_vpc.LAN_vpc.id
  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_instance.WAN_public_USER.primary_network_interface_id
  }
  tags = {
    Name = "WAN-public-USER-rt"
  }
}

resource "aws_network_interface" "LAN_eni" {
    subnet_id = aws_subnet.LAN_private_server_subnet.id
    private_ip = "192.168.30.1"
    security_groups = [aws_security_group.LAN_eni_public_sg.id]
    
    tags = {
      Name = "LAN-eni"
    }
}

resource "aws_instance" "LAN_private_user" {
  ami                    = "ami-040c33c6a51fd5d96" #ubuntu
  instance_type          = "t2.micro"
  key_name               = "nokey"
  subnet_id              = aws_subnet.LAN_private_user_subnet.id
  vpc_security_group_ids = [aws_security_group.LAN_USER_private_sg.id]
  
  tags = {
    Name = "LAN-private-USER"
  }
}

resource "aws_instance" "LAN_private_server" {
  ami                    = "ami-040c33c6a51fd5d96" #ubuntu
  instance_type          = "t2.micro"
  key_name               = "nokey"
  subnet_id              = aws_subnet.LAN_private_server_subnet.id
  vpc_security_group_ids = [aws_security_group.LAN_server_private_sg.id]
  
  network_interface {
    network_interface_id = aws_network_interface.LAN_eni.id
    device_index = 0
  }


  tags = {
    Name = "LAN-private-server"
  }
}
