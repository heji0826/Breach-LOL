#!/bin/bash


ACCESS_KEY="${ACCESS_KEY}"
SECRET_KEY="${SECRET_KEY}"

# AWS CLI configure
sudo -u ec2-user aws configure set aws_access_key_id "${ACCESS_KEY}" --profile nocomplaint
sudo -u ec2-user aws configure set aws_secret_access_key "${SECRET_KEY}" --profile nocomplaint
sudo -u ec2-user aws configure set region ap-northeast-2 --profile nocomplaint

# Create bin directory and move kubectl there
sudo -u ec2-user mkdir -p /home/ec2-user/bin

# Download kubectl
sudo curl -O curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.30.4/2024-09-11/bin/linux/amd64/kubectl


# File Move
sudo mv /kubectl /home/ec2-user/bin/kubectl 

# Make kubectl executable
sudo chown ec2-user:ec2-user /home/ec2-user/bin/kubectl
sudo chmod +x /home/ec2-user/bin/kubectl

# Update kubeconfig for EKS
sudo -u ec2-user aws eks update-kubeconfig --region ap-northeast-2 --name my-eks --profile nocomplaint


