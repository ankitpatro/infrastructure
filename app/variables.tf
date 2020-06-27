variable "vpcop_id" {}

variable "VPC_cidrBlock" {
  type    = "string"
  default = "0.0.0.0/0"
}

variable "subnets" {}

variable "ami_id" {
  description = "AMI Name to be used for EC2 Security group creation"
  type        = "string"
  # default = "ami-0c2744aad3dd08570" 
  default = "ami-07bfa5a8e5f3af0f3"
}

variable "instance_type" {
  description = "Instance Type to be used for EC2 Instance creation"
  type        = "string"
  default     = "t2.micro"
}

variable "volume_size" {
  description = "Instance Volume Size to be used for EC2 Instance creation"
  type        = "string"
  default     = "20"
}

variable "volume_type" {
  description = "Instance Volume Type to be used for EC2 Instance creation"
  type        = "string"
  default     = "gp2"

}

variable "region" {
  type    = "string"
  default = "us-east-1"
}
variable "profile" {
  type    = "string"
  default = "dev"
}

variable "public_key_value" {
  default = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDi7AuDRkNWVFtsXbIH2wO3vg72xvyM3s2O8SzNODvy3BrvLp0531SqGsPwOUNTKo4IqTqjzcK1gz5LQ2HueoJGmmDniFBi+FkWNmaVl49PIvQRFeXN4pNeWEMLV+WNPeOIfY9+QDJOHviekuEbO/j4cEUO/TWTwj0b4DgWYK3AhkIrftEhnpg+qmRPm1TVLwd5JAWRsneof9bE5cNrLdYhUyus4pmwIAPd25BKgZe/MHNqRrNjm+5IxXxi9S2AvDOxZ/jwrDTov4ECLmu37TTbWE5rvuMTE99+V2jt5iiZlXx4cZ+0td2DVbKSZSvTgkuvXovK6Piu7+4/+9AvQQq49BxDeRitoY4ov1kW8JoPV/n5NnBcpBaugEJ7OhP4yuksX26H1WVbrW57fnXcfpHSxZZfevvxvHk2uue7NUXH31c+4kyykxEDuTAPobMIpSEZmPk1YfHzrtBOL0vBpQRvOp2ncSchb+0ok6cdg6JUEER0JJaBKRHagdz82Wt4i9c= ankit@Ankit-Dell-Laptop"

}

variable "domain_name" {
  description = "Domain Name to be used for S3 bucket creation"
  type        = "string"
  default     = "ankitpatro.me"
}
variable "user_account_id" {
  description = "User Account Id"
  type        = "string"
  default     = "787647769598"
}
