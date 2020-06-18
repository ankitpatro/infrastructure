
provider "aws" {
  profile = "${var.profile}"
  region  = "${var.region}"
}

variable "VPC_cidrBlock" {
  default = "10.0.0.0/16"

}

variable "region" {
  default = "us-east-1"

}

variable "profile" {
  default = "dev"

}

module "network_mod" {
  source        = "../infrastructure/net"
  VPC_cidrBlock = "${var.VPC_cidrBlock}"
  region        = "${var.region}"
  profile       = "${var.profile}"
  name          = "network1"
  vpcop_id      = "${module.network_mod.vpcop_id}"
  subnets       = "${module.network_mod.subnets}"
}

# module "network_mod1" {
#   source        = "../infrastructure/net"
#   VPC_cidrBlock = "${var.VPC_cidrBlock}"
#   region        = "us-east-1"
#   profile       = "dev"
#   name          = "network1"
# }


module "application_mod" {
  source = "../infrastructure/app"
  # domain-name   = ""
  ami_id = "ami-0c2744aad3dd08570"
  # ami_name  = "csye6225_1573741914"
  # ami_key_pair_name =  "csye6225_ssh"
  instance_type = "t2.micro"
  volume_size   = "20"
  volume_type   = "gp2"
  region        = "${var.region}"
  profile       = "${var.profile}"
  VPC_cidrBlock = "10.0.0.0/16"
  # account_id  = ""
  vpcop_id = "${module.network_mod.vpcop_id}"
  subnets  = "${module.network_mod.subnets}"

}





# resource "aws_iam_policy" "circleci-ec2-ami" {
#   name        = "circleci-ec2-ami"
#   path        = "/"
#   description = "Allows CircleCI to launch and access EC2 instances"
#   policy      = <<EOF
# {
#     "Version": "2012-10-17",
#     "Statement": [
#         {
#             "Effect": "Allow",
#             "Action": [
#         "ec2:AttachVolume",
#         "ec2:AuthorizeSecurityGroupIngress",
#         "ec2:CopyImage",
#         "ec2:CreateImage",
#         "ec2:CreateKeypair",
#         "ec2:CreateSecurityGroup",
#         "ec2:CreateSnapshot",
#         "ec2:CreateTags",
#         "ec2:CreateVolume",
#         "ec2:DeleteKeyPair",
#         "ec2:DeleteSecurityGroup",
#         "ec2:DeleteSnapshot",
#         "ec2:DeleteVolume",
#         "ec2:DeregisterImage",
#         "ec2:DescribeImageAttribute",
#         "ec2:DescribeImages",
#         "ec2:DescribeInstances",
#         "ec2:DescribeInstanceStatus",
#         "ec2:DescribeRegions",
#         "ec2:DescribeSecurityGroups",
#         "ec2:DescribeSnapshots",
#         "ec2:DescribeSubnets",
#         "ec2:DescribeTags",
#         "ec2:DescribeVolumes",
#         "ec2:DetachVolume",
#         "ec2:GetPasswordData",
#         "ec2:ModifyImageAttribute",
#         "ec2:ModifyInstanceAttribute",
#         "ec2:ModifySnapshotAttribute",
#         "ec2:RegisterImage",
#         "ec2:RunInstances",
#         "ec2:StopInstances",
#         "ec2:TerminateInstances"
#             ],
#             "Resource": "*" 
#         }
#     ]
# }
# EOF
# }

# resource "aws_iam_user_policy_attachment" "attach-policy" {
#   user       = "circleci"
#   policy_arn = "${aws_iam_policy.circleci-ec2-ami.arn}"

# }
