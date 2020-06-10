provider "aws" {
  profile = "${var.profile}"
  region  = "${var.region}"
}
variable "region" {
  type    = "string"
  default = "us-east-1"
}

variable "name" {
  type = "string"
}
variable "profile" {
  type    = "string"
  default = "dev"
}

variable "VPC_cidrBlock" {
  type    = "string"
  default = "198.0.0.0/16"
}

variable "subnet_1_cidrBlock" {
  type    = "string"
  default = "10.0.1.0/24"
}

variable "subnet_2_cidrBlock" {
  type    = "string"
  default = "10.0.2.0/24"
}

variable "subnet_3_cidrBlock" {
  type    = "string"
  default = "10.0.3.0/24"
}

variable "public_route_cidrBlock" {
  type    = "string"
  default = "0.0.0.0/0"
}

variable "vpc_name" {
  type    = "string"
  default = "vpc_csye6225_f"
}

variable "ig_name" {
  type    = "string"
  default = "ig_csye6225_e"

}

resource "aws_vpc" "vpc_csye6225_f" {
  cidr_block                       = "${var.VPC_cidrBlock}"
  enable_dns_support               = true
  enable_dns_hostnames             = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
  tags = {
    Name = "${var.vpc_name}"
  }
}
variable "subnet-name" {
  type    = "string"
  default = "subnet_csye6225_e"
}

resource "aws_subnet" "subnet_csye6225_e_1" {
  # cidr_block = "10.0.1.0/24"
  cidr_block = "${var.subnet_1_cidrBlock}"
  vpc_id     = "${aws_vpc.vpc_csye6225_f.id}"

  # count = 3
  availability_zone       = "${var.region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.subnet-name}1"
  }
}
resource "aws_subnet" "subnet_csye6225_e_2" {
  # cidr_block = "10.0.2.0/24"
  cidr_block = "${var.subnet_2_cidrBlock}"
  vpc_id     = "${aws_vpc.vpc_csye6225_f.id}"

  # count = 3
  availability_zone       = "${var.region}b"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.subnet-name}2"
  }
}
resource "aws_subnet" "subnet_csye6225_e_3" {
  # cidr_block = "10.0.3.0/24"
  cidr_block = "${var.subnet_3_cidrBlock}"
  vpc_id     = "${aws_vpc.vpc_csye6225_f.id}"

  availability_zone       = "${var.region}c"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.subnet-name}3"
  }
}

resource "aws_internet_gateway" "ig_csye6225_e" {
  vpc_id = "${aws_vpc.vpc_csye6225_f.id}"
  tags = {
    Name = "${var.ig_name}"
  }
}

resource "aws_route_table" "route_table_csye6225_e" {
  vpc_id = "${aws_vpc.vpc_csye6225_f.id}"
  route {
    # cidr_block = "0.0.0.0/0"
    cidr_block = "${var.public_route_cidrBlock}"
    gateway_id = "${aws_internet_gateway.ig_csye6225_e.id}"
  }
}
resource "aws_route_table_association" "route_association_csye6225_1" {
  subnet_id      = "${aws_subnet.subnet_csye6225_e_1.id}"
  route_table_id = "${aws_route_table.route_table_csye6225_e.id}"
}
resource "aws_route_table_association" "route_association_csye6225_2" {
  subnet_id      = "${aws_subnet.subnet_csye6225_e_2.id}"
  route_table_id = "${aws_route_table.route_table_csye6225_e.id}"
}
resource "aws_route_table_association" "route_association_csye6225_3" {
  subnet_id      = "${aws_subnet.subnet_csye6225_e_3.id}"
  route_table_id = "${aws_route_table.route_table_csye6225_e.id}"
}
