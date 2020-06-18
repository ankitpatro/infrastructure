#----------Application security Group ---------------------

resource "aws_security_group" "application" {
  name        = "WebApp Application Security Group"
  description = "Allow traffic for Webapp"
  vpc_id      = "${var.vpcop_id}"
  ingress {
    description = "TLS from VPC"
    cidr_blocks = ["0.0.0.0/0"]
    # cidr_blocks = "${var.VPC_cidrBlock}"
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
  }
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    # cidr_blocks = "${var.VPC_cidrBlock}"
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
  }

  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    # cidr_blocks = "${var.VPC_cidrBlock}"
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
  }

  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    # cidr_blocks = "${var.VPC_cidrBlock}"
    from_port = 8080
    to_port   = 8080
    protocol  = "tcp"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

}

#----------DB security Group ---------------------

resource "aws_security_group" "database" {
  name        = "Database Security Group"
  description = "Allow TLS inbound traffic"
  vpc_id      = "${var.vpcop_id}"
}

resource "aws_security_group_rule" "ingress-database-rule" {
  type = "ingress"
  # TLS (change to whatever ports you need)
  from_port = 5432
  to_port   = 5432
  protocol  = "tcp"
  # cidr_blocks = "${var.VPC_cidrBlock}"
  # cidr_blocks = ["0.0.0.0/0"]
  security_group_id        = "${aws_security_group.database.id}"
  source_security_group_id = "${aws_security_group.application.id}"
}



#----------RDS DB subnet group resource ---------------------
resource "aws_db_subnet_group" "webapp_rds_subgroup" {
  name       = "subnet_for_rds_instances"
  subnet_ids = "${var.subnets}"

  tags = {
    Name = "Webapp DB subnet group"
  }
}

#====================== S3 Bucket ======================

resource "aws_s3_bucket" "bucket" {
  bucket        = "webapp.ankit.patro"
  acl           = "private"
  force_destroy = "true"

  tags = {
    Name        = "webapp.ankit.patro"
    Environment = "Dev"
  }

  lifecycle_rule {
    id      = "log"
    enabled = true

    tags = {
      "rule"      = "log"
      "autoclean" = "true"
    }

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {

        sse_algorithm = "AES256"
      }
    }
  }
}

#----------RDS Instance ---------------------

resource "aws_db_instance" "WebAppRDS" {
  name                   = "csye6225"
  allocated_storage      = 20
  instance_class         = "db.t3.micro"
  storage_type           = "gp2"
  engine                 = "postgres"
  port                   = "5432"
  multi_az               = "false"
  identifier             = "csye6225-su2020"
  username               = "csye6225su2020"
  password               = "Ankit#1992"
  engine_version         = "12.2"
  publicly_accessible    = "true"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  db_subnet_group_name   = "${aws_db_subnet_group.webapp_rds_subgroup.name}"
  skip_final_snapshot    = true


  #   parameter_group_name = "default.postgres12.2"
}

#----------EC2 Instance ---------------------

resource "aws_instance" "ec2-instance" {
  ami = var.ami_id
  # security_groups = ["${aws_security_group.application.id}"]
  key_name                = "${aws_key_pair.publicKey.key_name}"
  vpc_security_group_ids  = ["${aws_security_group.application.id}"]
  depends_on              = [aws_db_instance.WebAppRDS]
  iam_instance_profile    = "${aws_iam_instance_profile.instance_profile1.name}"
  instance_type           = "${var.instance_type}"
  subnet_id               = var.subnets[0]
  disable_api_termination = "false"
  root_block_device {
    volume_size = "${var.volume_size}"
    volume_type = "${var.volume_type}"
  }
  tags = {
    Name = "WebApp EC2 Instance"
  }

  user_data = "${templatefile("userdata.sh",
    {
      s3_bucket_name  = "${aws_s3_bucket.bucket.bucket}",
      aws_db_endpoint = "${aws_db_instance.WebAppRDS.endpoint}",
      aws_db_name     = "${aws_db_instance.WebAppRDS.name}",
      aws_db_username = "${aws_db_instance.WebAppRDS.username}",
      aws_db_password = "${aws_db_instance.WebAppRDS.password}",
      aws_region      = "${var.region}",
      aws_profile     = "${var.profile}"
  })}"
}

# ====================== DynamoDB table ===========================

resource "aws_dynamodb_table" "dynamodb-table" {
  name           = "csye6225"
  hash_key       = "id"
  read_capacity  = 20
  write_capacity = 20
  attribute {
    name = "id"
    type = "S"
  }
}

#========================IAM Policy=================================
resource "aws_iam_policy" "WebAppS3" {
  name = "WebAppS3"
  #   role = aws_iam_role.test_role.id

  policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
       "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:GetObjectAcl",
        "s3:DeleteObject"
	  ],
        "Effect": "Allow",
        "Resource": ["arn:aws:s3:::${aws_s3_bucket.bucket.bucket}","arn:aws:s3:::${aws_s3_bucket.bucket.bucket}/*"]
      }
    ]
  }
  EOF
}

resource "aws_iam_instance_profile" "instance_profile1" {
  name = "instance_profile1"
  role = "${aws_iam_role.EC2-CSYE6225.name}"
}

#======================IAM ROLE========================
resource "aws_iam_role" "EC2-CSYE6225" {
  name = "EC2-CSYE6225"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  tags = {
    tag-key = "tag-value"
  }
}



#=================Attaches a Managed IAM Policy to an IAM role========================
resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = "${aws_iam_role.EC2-CSYE6225.name}"
  policy_arn = "${aws_iam_policy.WebAppS3.arn}"
}

resource "aws_key_pair" "publicKey" {
  key_name   = "aws_dev"
  public_key = var.public_key_value
}