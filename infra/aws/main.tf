terraform {
  required_version = ">= 1.5, < 2"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
provider "aws" {
  region  = "us-east-1"
  profile = var.aws_profile
  default_tags { tags = { Project = "FleetDoctor", ManagedBy = "Terraform" } }
}
variable "aws_profile" {
  type    = string
  default = "fleetdoctor"
}
variable "owner_cidr" {
  type = string
  validation {
    condition     = can(cidrnetmask(var.owner_cidr)) && can(regex("/32$", var.owner_cidr))
    error_message = "Provide the owner's IPv4 /32, never a broad SSH ingress range."
  }
}
variable "ssh_public_key" {
  type = string
  validation {
    condition     = startswith(var.ssh_public_key, "ssh-ed25519 ") || startswith(var.ssh_public_key, "ssh-rsa ")
    error_message = "Provide an OpenSSH public key, never a private key."
  }
}
data "aws_ssm_parameter" "ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}
data "aws_ec2_instance_type_offerings" "small" {
  filter {
    name   = "instance-type"
    values = ["t3.small"]
  }
  location_type = "availability-zone"
}
data "aws_ec2_instance_type_offerings" "medium" {
  filter {
    name   = "instance-type"
    values = ["t3.medium"]
  }
  location_type = "availability-zone"
}
locals {
  common_azs = sort(tolist(setintersection(data.aws_ec2_instance_type_offerings.small.locations, data.aws_ec2_instance_type_offerings.medium.locations)))
  roles      = { monitor = "t3.medium", node-a = "t3.small", node-b = "t3.small" }
}
resource "aws_vpc" "lab" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
}
resource "aws_subnet" "lab" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.42.1.0/24"
  availability_zone       = local.common_azs[0]
  map_public_ip_on_launch = true
}
resource "aws_internet_gateway" "lab" { vpc_id = aws_vpc.lab.id }
resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
}
resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab.id
}
resource "aws_security_group" "monitor" {
  name_prefix = "fleetdoctor-monitor-"
  vpc_id      = aws_vpc.lab.id
}
resource "aws_security_group" "nodes" {
  name_prefix = "fleetdoctor-nodes-"
  vpc_id      = aws_vpc.lab.id
}
resource "aws_vpc_security_group_ingress_rule" "ssh" {
  for_each          = { monitor = aws_security_group.monitor.id, nodes = aws_security_group.nodes.id }
  security_group_id = each.value
  cidr_ipv4         = var.owner_cidr
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}
resource "aws_vpc_security_group_ingress_rule" "ingest" {
  security_group_id            = aws_security_group.monitor.id
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
}
resource "aws_vpc_security_group_ingress_rule" "probe" {
  security_group_id            = aws_security_group.monitor.id
  referenced_security_group_id = aws_security_group.nodes.id
  ip_protocol                  = "icmp"
  from_port                    = 8
  to_port                      = -1
}
resource "aws_vpc_security_group_egress_rule" "outbound" {
  for_each          = { monitor = aws_security_group.monitor.id, nodes = aws_security_group.nodes.id }
  security_group_id = each.value
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}
resource "aws_key_pair" "lab" {
  key_name_prefix = "fleetdoctor-"
  public_key      = var.ssh_public_key
}
resource "aws_instance" "lab" {
  for_each = local.roles
  ami      = data.aws_ssm_parameter.ami.value
  # Retain the existing root stores when AWS publishes a newer bootstrap image.
  lifecycle { ignore_changes = [ami] }
  instance_type               = each.value
  subnet_id                   = aws_subnet.lab.id
  associate_public_ip_address = true
  vpc_security_group_ids      = [each.key == "monitor" ? aws_security_group.monitor.id : aws_security_group.nodes.id]
  key_name                    = aws_key_pair.lab.key_name
  credit_specification { cpu_credits = "standard" }
  metadata_options { http_tokens = "required" }
  root_block_device {
    volume_type           = "gp3"
    volume_size           = 20
    encrypted             = true
    delete_on_termination = true
  }
  user_data  = file(each.key == "monitor" ? "${path.module}/monitor-bootstrap.sh" : "${path.module}/node-bootstrap.sh")
  tags       = { Name = "fleetdoctor-${each.key}", Role = each.key }
  depends_on = [aws_route_table_association.lab]
}
output "instances" {
  description = "Stable IDs and private addresses. Describe IDs to obtain current public IPs after every start."
  value       = { for role, instance in aws_instance.lab : role => { id = instance.id, private_ip = instance.private_ip } }
}
