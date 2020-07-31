#============IAM ROLEs===============================
resource "aws_iam_role" "codedeploysrv" {
  name                  = "CodeDeployServiceRole"
  path                  = "/"
  force_detach_policies = "true"
  assume_role_policy    = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal":
        {"Service": "codedeploy.amazonaws.com"},
      "Effect": "Allow",
	  "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role" "EC2-CSYE6225" {
  name = "CodeDeployEC2ServiceRole"

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


resource "aws_iam_instance_profile" "instance_profile1" {
  name = "instance_profile1"
  role = "${aws_iam_role.EC2-CSYE6225.name}"
}


#================CodeDeploy-EC2-S3 Policy for the Server (EC2)=================

resource "aws_iam_policy" "CodeDeploy-EC2-S3" {
  name        = "CodeDeploy-EC2-S3"
  description = "Allows EC2 instances to read data from S3 buckets"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
          "Action": [
                "s3:Get*",
                "s3:List*"
            ],
			"Effect": "Allow",
            "Resource": ["${aws_s3_bucket.codedeploy_bucket.arn}", "${aws_s3_bucket.codedeploy_bucket.arn}/*"]
			}
    ]
}
EOF
}


#======================CircleCI-Upload-To-S3 Policy for CircleCI to Upload to AWS S3=========================

resource "aws_iam_policy" "CircleCI-Upload-To-S3" {
  name        = "CircleCI-Upload-To-S3"
  description = "Allows CircleCI to upload artifacts from latest successful build to dedicated S3 bucket used by code deploy"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
       {
      "Action": [
        "s3:PutObject",
        "s3:Get*",
        "s3:List*"
      ],
      "Effect": "Allow",
      "Resource": [
          "arn:aws:s3:::codedeploy.ankitpatro.me",
          "arn:aws:s3:::codedeploy.ankitpatro.me/*"
      ]
    }
    ]
}
EOF

}


#======================CircleCI-Code-Deploy Policy for CircleCI to Call CodeDeploy=====================

resource "aws_iam_policy" "CircleCI-Code-Deploy" {
  name        = "CircleCI-Code-Deploy"
  description = "CircleCI-Code-Deploy policy allows CircleCI to call CodeDeploy APIs to initiate application deployment on EC2 instances"
  policy      = <<EOF
{
"Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource":
        "arn:aws:codedeploy:${var.region}:${var.user_account_id}:application:${aws_codedeploy_app.csye6225-webapp.name}"
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
        "*"
      ]
  },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${var.user_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${var.user_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${var.user_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
  }
EOF
}


resource "aws_iam_policy" "circleci-ec2-ami" {
  name        = "circleci-ec2-ami"
  path        = "/"
  description = "Allows CircleCI to upload artifacts from latest successful build to dedicated S3 bucket used by code deploy"
  policy      = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:AttachVolume",
				"ec2:AuthorizeSecurityGroupIngress",
				"ec2:CopyImage",
				"ec2:CreateImage",
				"ec2:CreateKeypair",
				"ec2:CreateSecurityGroup",
				"ec2:CreateSnapshot",
				"ec2:CreateTags",
				"ec2:CreateVolume",
				"ec2:DeleteKeyPair",
				"ec2:DeleteSecurityGroup",
				"ec2:DeleteSnapshot",
				"ec2:DeleteVolume",
				"ec2:DeregisterImage",
				"ec2:DescribeImageAttribute",
				"ec2:DescribeImages",
				"ec2:DescribeInstances",
				"ec2:DescribeInstanceStatus",
				"ec2:DescribeRegions",
				"ec2:DescribeSecurityGroups",
				"ec2:DescribeSnapshots",
				"ec2:DescribeSubnets",
				"ec2:DescribeTags",
				"ec2:DescribeVolumes",
				"ec2:DetachVolume",
				"ec2:GetPasswordData",
				"ec2:ModifyImageAttribute",
				"ec2:ModifyInstanceAttribute",
				"ec2:ModifySnapshotAttribute",
				"ec2:RegisterImage",
				"ec2:RunInstances",
				"ec2:StopInstances",
				"ec2:TerminateInstances"
            ],
            "Resource": "${aws_s3_bucket.codedeploy_bucket.arn}" 
        }
    ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "test-attach-codedeploysrv-policy" {
  role       = "${aws_iam_role.codedeploysrv.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
}


resource "aws_iam_role_policy_attachment" "ec2CodedeployRolePolicyAttach" {
  role       = "${aws_iam_role.EC2-CSYE6225.name}"
  policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"

}

resource "aws_iam_role_policy_attachment" "ec2CloudWatchRolePolicyAttach" {
  role       = "${aws_iam_role.EC2-CSYE6225.name}"
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_user_policy_attachment" "test-attach1" {
  user       = "cicd"
  policy_arn = "${aws_iam_policy.circleci-ec2-ami.arn}"
}

resource "aws_iam_user_policy_attachment" "test-attach2" {
  user       = "cicd"
  policy_arn = "${aws_iam_policy.CircleCI-Code-Deploy.arn}"
}


resource "aws_iam_user_policy_attachment" "test-attach3" {
  user       = "cicd"
  policy_arn = "${aws_iam_policy.CircleCI-Upload-To-S3.arn}"
}


resource "aws_iam_user_policy_attachment" "test-attach4" {
  user       = "cicd"
  policy_arn = "${aws_iam_policy.CodeDeploy-EC2-S3.arn}"

}

#----------------------- Create IAM Lambda Role ------------------

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# ============================== SNS Topic ===================================

resource "aws_sns_topic" "email_request" {
  name = "email_request"
  delivery_policy = <<EOF
{
  "http": {
    "defaultHealthyRetryPolicy": {
      "minDelayTarget": 20,
      "maxDelayTarget": 20,
      "numRetries": 3,
      "numMaxDelayRetries": 0,
      "numNoDelayRetries": 0,
      "numMinDelayRetries": 0,
      "backoffFunction": "linear"
    },
    "disableSubscriptionOverrides": false,
    "defaultThrottlePolicy": {
      "maxReceivesPerSecond": 1
    } }}
EOF
} 

#======================SNS_POLICY==========================

resource "aws_iam_policy" "sns_policy" {
  name        = "test_policy"
  path        = "/"
  description = "My test policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "SNS:Publish"
      ],
      "Resource": "${aws_sns_topic.email_request.arn}"
    }
  ]
}
EOF
}
#====Attaching sns policy with code deploy role================
resource "aws_iam_role_policy_attachment" "snspolicy_role_attach2" {
  role       = "${aws_iam_role.EC2-CSYE6225.name}"
  policy_arn = "${aws_iam_policy.sns_policy.arn}"
}

#===========Attaching sns policy with lambda role===========
resource "aws_iam_role_policy_attachment" "snspolicy_role_attach1" {
  role       = "${aws_iam_role.iam_for_lambda.name}"
  policy_arn = "${aws_iam_policy.sns_policy.arn}"
}

#----------------S3 Bucket for lambda --------------
# resource "aws_s3_bucket" "lambda_bucket" {
# 	bucket = "lambda1.${var.domain_name}"
# 	acl    = "private"
# 	force_destroy = "true"
# 	tags = "${
#       		map(
#      		"Name", "${var.domain_name}",
#     		)
#   	}"
# 	lifecycle_rule {
# 	    id      = "log/"
# 	    enabled = true
# 		transition{
# 			days = 30
# 			storage_class = "STANDARD_IA"
# 		}
# 		expiration{
# 			days = 60
# 		}
# 	}
# }


resource "aws_lambda_function" "func_lambda" {
  # filename      = "csye6225_lambda0.0.1-SNAPSHOT"
  function_name = "func_lambda"
  role          = "${aws_iam_role.iam_for_lambda.arn}"
  handler       = "LogEvent::handleRequest"
  runtime	    = "java8"
  # s3_bucket 	= "${aws_s3_bucket.lambda_bucket.bucket}"
  s3_bucket = "lambda.ankitpatro.me"
  s3_key      = "faas-1.0-SNAPSHOT.jar"
  timeout        = 900
  reserved_concurrent_executions = 1
  memory_size = 256
  depends_on     = ["aws_sns_topic.email_request"]
   # Pass the SNS topic ARN and DynamoDB table name in the environment.
  environment {
      variables = "${
      		map(
     		"sns_arn", "${aws_sns_topic.email_request.arn}",
            "dynamo_table_name", "${aws_dynamodb_table.snslambda_table.name}",
            "ttlInMin",15
    		)
  	}"
  }
}



#--------------------- Attach IAM Lambda Role with lambda Log Policies ------------
resource "aws_iam_role_policy_attachment" "lambda_role_attach1" {
  role = "${aws_iam_role.iam_for_lambda.name}"
  policy_arn = "${aws_iam_policy.lambda_logging.arn}"
}

#===============Attach EC2 Code Deploy Role with lambda Log Policies
resource "aws_iam_role_policy_attachment" "lambda_role_attach2" {
  role       = "${aws_iam_role.EC2-CSYE6225.name}"
  policy_arn = "${aws_iam_policy.lambda_logging.arn}"
}

#--------------------------- Create Lambda Policy -------------------

resource "aws_iam_policy" "lambda_logging" {
  name = "lambda_logging"
  path = "/"
  description = "IAM policy for logging from a lambda"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogStreams"
      ],
      "Resource": "arn:aws:logs:*:*:*",
      "Effect": "Allow"
    },
    {
      "Action": [
        "ses:*"
      ],
      "Resource": "*",
      "Effect": "Allow"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:DescribeStream",
        "dynamodb:GetRecords",
        "dynamodb:GetShardIterator",
        "dynamodb:ListStreams","dynamodb:GetItem",
        "dynamodb:DeleteItem",
        "dynamodb:PutItem",
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:UpdateItem",
        "dynamodb:BatchWriteItem",
        "dynamodb:BatchGetItem",
        "dynamodb:DescribeTable"
      ],
      "Resource": "${aws_dynamodb_table.snslambda_table.arn}"
  }
 
  ]
}
EOF
}

# ----------------------- Lambda SNS DynamoDB table ---------------------------------

resource "aws_dynamodb_table" "snslambda_table" {
	 name           = "snslambda"
	 hash_key       = "username"
	 read_capacity = "20"
	 write_capacity = "20"
     stream_enabled = true
     stream_view_type = "KEYS_ONLY"
	 attribute {
		name = "username"
		type = "S"
  	}
     ttl {
      enabled = true
      attribute_name = "ttl"
    }
  }

    #-------------SNS permissions to invoke lambda function ---------------

resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowExecutionFromSNSToLambda"
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.func_lambda.function_name}"
  principal     = "sns.amazonaws.com"
  source_arn = "${aws_sns_topic.email_request.arn}"
} 

#---------------- Subscribe Lambda function to SNS topic ---------------

resource "aws_sns_topic_subscription" "sns_subscription" {
  # depends_on = ["aws_lambda_function.func_lambda"]
  topic_arn = "${aws_sns_topic.email_request.arn}"
  protocol = "lambda"
  endpoint = "${aws_lambda_function.func_lambda.arn}"
}


# not sure, if we need this or not

# resource "aws_lb_target_group_attachment" "test" {
#   target_group_arn = "${aws_lb_target_group.lb_tg.arn}"
#   target_id        = "${aws_lambda_function.func_lambda.id}"
#   port             = 80
# }

resource "aws_iam_policy" "CircleCI-Lambda" {
  name = "circleci_s3_policy_lambda"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:*"
        ],
        
      
      "Resource": "arn:aws:lambda:${var.region}:${var.user_account_id}:function:${aws_lambda_function.func_lambda.function_name}"
    },
    
      

    {
      "Effect": "Allow",
      "Action": [
        
        "s3:PutObject",
        "s3:Get*",
        "s3:List*"
        ],

      "Resource": "arn:aws:s3:::lambda.ankitpatro.me"
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "circleci_lambda_policy_attach" {
  user = "cicd"
  policy_arn = "${aws_iam_policy.CircleCI-Lambda.arn}"
}

#----------Application security Group ---------------------

resource "aws_security_group" "application" {
  name        = "WebApp Application Security Group"
  description = "Allow traffic for Webapp"
  vpc_id      = "${var.vpcop_id}"
  ingress {
    description = "TLS from VPC"
    # cidr_blocks = ["0.0.0.0/0"]
    # cidr_blocks = "${var.VPC_cidrBlock}"
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    security_groups = ["${aws_security_group.loadbalancer.id}"]
  }
  ingress {
    # cidr_blocks = ["0.0.0.0/0"]
    # cidr_blocks = "${var.VPC_cidrBlock}"
    from_port = 80
    to_port   = 80
    protocol  = "tcp"
    security_groups = ["${aws_security_group.loadbalancer.id}"]
  }

  ingress {
    # cidr_blocks = ["0.0.0.0/0"]
    # cidr_blocks = "${var.VPC_cidrBlock}"
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    security_groups = ["${aws_security_group.loadbalancer.id}"]
  }

  ingress {
    # cidr_blocks = ["0.0.0.0/0"]
    # cidr_blocks = "${var.VPC_cidrBlock}"
    from_port = 8080
    to_port   = 8080
    protocol  = "tcp"
    security_groups = ["${aws_security_group.loadbalancer.id}"]
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

##LOAD BALANCER SECURITY GROUP
resource "aws_security_group" "loadbalancer" {
  name          = "loadbalancer_security_group"
  vpc_id        = "${var.vpcop_id}"
  ingress{
    from_port   = 80
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks  = ["0.0.0.0/0"]
  }
  # Egress is used here to communicate anywhere with any given protocol
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags          = {
    Name        = "LoadBalancer Security Group"
    
  }
}

# ====================== EC2 Launch Configuration ===========================
resource "aws_launch_configuration" "asg_launch_config" {
  name   = "asg_launch_config"
  image_id      = "${var.ami_id}"
  instance_type = "${var.instance_type}"
  key_name      = "${aws_key_pair.publicKey.key_name}"
  associate_public_ip_address = true
  security_groups = ["${aws_security_group.application.id}"]
  
  user_data = "${templatefile("userdata.sh",
		{
			s3_bucket_name = "${aws_s3_bucket.bucket.bucket}",
			aws_db_endpoint = "${aws_db_instance.WebAppRDS.endpoint}",
			aws_db_name = "${aws_db_instance.WebAppRDS.name}",
			aws_db_username = "${aws_db_instance.WebAppRDS.username}",
			aws_db_password = "${aws_db_instance.WebAppRDS.password}",
			aws_region = "${var.region}",
			aws_profile = "${var.profile}",
      sns_topic_arn = "${aws_sns_topic.email_request.arn}"
		})}"

  iam_instance_profile = "${aws_iam_instance_profile.instance_profile1.name}"
  
  root_block_device {
		volume_size = "${var.volume_size}"
		volume_type = "${var.volume_type}"
	}
  lifecycle {
    create_before_destroy = true
  }
  depends_on = [
    "aws_security_group.application"
  ]
}

# ============================ Autoscaling group =========================
resource "aws_autoscaling_group" "ec2_asg" {
  name                 = "ec2_asg"
  launch_configuration = "${aws_launch_configuration.asg_launch_config.name}"
  min_size             = 2
  max_size             = 5
  desired_capacity     = 2
  default_cooldown     = 60
  health_check_type    = "ELB"
  vpc_zone_identifier  = var.subnets
  lifecycle {
    create_before_destroy = true
  }
  tag {
    key                 = "Name"
    value               = "WebApp EC2 Instance"
    # Name = "WebApp EC2 Instance"
    propagate_at_launch = true
  }
  depends_on = [
    "aws_launch_configuration.asg_launch_config",
    "var.subnets",
    "aws_lb_target_group.lb_tg"
  ]
}

#---------------------------- Autoscaling Policies ---------------------------
# SCALE - UP Policy
resource "aws_autoscaling_policy" "asg_scaleUp" {
  name                   = "WebServerScaleUpPolicy"
  scaling_adjustment     = "1"
  adjustment_type        = "ChangeInCapacity"
  cooldown               = "60"
  autoscaling_group_name = "${aws_autoscaling_group.ec2_asg.name}"
  policy_type = "SimpleScaling"
}

# SCALE - DOWN Policy
resource "aws_autoscaling_policy" "asg_scaleDwn" {
  name                   = "WebServerScaleDownPolicy"
  scaling_adjustment     = "-1"
  adjustment_type        = "ChangeInCapacity"
  cooldown               = "60"
  autoscaling_group_name = "${aws_autoscaling_group.ec2_asg.name}"
  policy_type = "SimpleScaling"
}
#SCALE - UP Policy: CPU
resource "aws_cloudwatch_metric_alarm" "up-cpu-alarm" {
  alarm_name = "up-cpu-alarm"
  alarm_description = "Scale-up if CPU > 90% for 10 minutes"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods = "1"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "60"
  statistic = "Average"
  threshold = "40"
  alarm_actions = ["${aws_autoscaling_policy.asg_scaleUp.arn}"]
  # comparison_operator = "GreaterThanThreshold"
  dimensions = "${
      		map(
     		"AutoScalingGroupName", "${aws_autoscaling_group.ec2_asg.name}",
    		)
  	}"
}

#SCALE - DOWN Policy: CPU
resource "aws_cloudwatch_metric_alarm" "down-cpu-alarm" {
  alarm_name = "down-cpu-alarm"
  alarm_description = "Scale-down if CPU < 70% for 10 minutes"
  comparison_operator = "LessThanThreshold"
  evaluation_periods = "1"
  metric_name = "CPUUtilization"
  namespace = "AWS/EC2"
  period = "60"
  statistic = "Average"
  threshold = "30"
  alarm_actions = ["${aws_autoscaling_policy.asg_scaleDwn.arn}"]
  # comparison_operator = "LessThanThreshold"
  dimensions = "${
      		map(
     		"AutoScalingGroupName", "${aws_autoscaling_group.ec2_asg.name}",
    		)
  	}"
}

#=================LOAD BALANCER=================================

resource "aws_lb" "alb" {
  name = "alb"
  subnets = "${var.subnets}"
  load_balancer_type = "application"
  # security_groups = ["${aws_security_group.application.id}"]
  security_groups    = ["${aws_security_group.loadbalancer.id}"]
  internal = false
  # enable_deletion_protection = true
  tags = {
    Name = "terraform-alb"
  }
  #target_group
}

resource "aws_lb_listener" "lb_listener1" {
  load_balancer_arn = "${aws_lb.alb.arn}"
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn = "arn:aws:acm:us-east-1:684177922449:certificate/a8d3d7d0-6327-49c2-880d-7c5b055b3f25"
  default_action {
    type             = "forward"
    target_group_arn = "${aws_lb_target_group.lb_tg.arn}"
  }
}



resource "aws_lb_target_group" "lb_tg" {
  name        = "tf-lb-tg"
  port        = "8080"
  protocol    = "HTTP"
  # target_type = "ip"
  vpc_id      = "${var.vpcop_id}"
  tags        = {
      name    = "tf-lb-tg"
  }
  # health_check {
  #     healthy_threshold = 3
  #     unhealthy_threshold = 5
  #     timeout = 5
  #     interval = 30
  #     path = "/apphealthstatus"
  #     port = "8080"
  #     matcher = "200"
  # }

  stickiness {
    type = "lb_cookie"
   
  }

}

resource "aws_alb_listener_rule" "listener_rule" {
  listener_arn = "${aws_lb_listener.lb_listener1.arn}"  
  priority     = 100   
  action {    
    type             = "forward"    
    target_group_arn = "${aws_lb_target_group.lb_tg.arn}"  
  }   
  condition {    
    field  = "path-pattern"    
    values = ["/*"]  
  }
}


#Autoscaling Attachment
resource "aws_autoscaling_attachment" "asg_targetgroup" {
  alb_target_group_arn   = "${aws_lb_target_group.lb_tg.arn}"
  autoscaling_group_name = "${aws_autoscaling_group.ec2_asg.id}"
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

#====================== S3 Bucket for codedeploy======================

resource "aws_s3_bucket" "codedeploy_bucket" {
  bucket        = "codedeploy.${var.domain_name}"
  acl           = "private"
  force_destroy = "true"
  tags = "${
    map(
      "Name", "${var.domain_name}",
    )
  }"
  lifecycle_rule {
    id      = "log/"
    enabled = true
    # transition {
    #   days          = 30
    #   storage_class = "STANDARD_IA"
    # }
    expiration {
      days = 30
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
  publicly_accessible    = "false"
  vpc_security_group_ids = ["${aws_security_group.database.id}"]
  db_subnet_group_name   = "${aws_db_subnet_group.webapp_rds_subgroup.name}"
  skip_final_snapshot    = true
  parameter_group_name = "${aws_db_parameter_group.sslgroup.name}"
  storage_encrypted = "true"
}

 resource "aws_db_parameter_group" "sslgroup" {
  name   = "sslgroup"
  family = "postgres12"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
    }
 }

#----------EC2 Instance ---------------------

# resource "aws_instance" "ec2-instance" {
#   ami = var.ami_id
#   # security_groups = ["${aws_security_group.application.id}"]
#   key_name                = "${aws_key_pair.publicKey.key_name}"
#   vpc_security_group_ids  = ["${aws_security_group.application.id}"]
#   depends_on              = [aws_db_instance.WebAppRDS]
#   iam_instance_profile    = "${aws_iam_instance_profile.instance_profile1.name}"
#   instance_type           = "${var.instance_type}"
#   subnet_id               = var.subnets[0]
#   disable_api_termination = "false"
#   root_block_device {
#     volume_size = "${var.volume_size}"
#     volume_type = "${var.volume_type}"
#   }
#   tags = {
#     Name = "WebApp EC2 Instance"
#   }

#   user_data = "${templatefile("userdata.sh",
#     {
#       s3_bucket_name  = "${aws_s3_bucket.bucket.bucket}",
#       aws_db_endpoint = "${aws_db_instance.WebAppRDS.endpoint}",
#       aws_db_name     = "${aws_db_instance.WebAppRDS.name}",
#       aws_db_username = "${aws_db_instance.WebAppRDS.username}",
#       aws_db_password = "${aws_db_instance.WebAppRDS.password}",
#       aws_region      = "${var.region}",
#       aws_profile     = "${var.profile}",
#       host_name       = "${var.domain_name}"
#   })}"
# }

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



#======================IAM ROLE========================




#=================Attaches a Managed IAM Policy to an IAM role========================
resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = "${aws_iam_role.EC2-CSYE6225.name}"
  policy_arn = "${aws_iam_policy.WebAppS3.arn}"
}

resource "aws_key_pair" "publicKey" {
  key_name   = "aws_dev"
  public_key = var.public_key_value
}






# # =================== Codedeploy App and Group ==============================

resource "aws_codedeploy_app" "csye6225-webapp" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "csye6225-webapp-deployment" {
  app_name               = "${aws_codedeploy_app.csye6225-webapp.name}"
  deployment_group_name  = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn       = "${aws_iam_role.codedeploysrv.arn}"
  autoscaling_groups = ["${aws_autoscaling_group.ec2_asg.name}"]
  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "WebApp EC2 Instance"
  }
  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }
  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }
  # alarm_configuration {
  #   alarms  = ["Deployment-Alarm"]
  #   enabled = true
  # }
    load_balancer_info{
	  target_group_info{
		  name = "${aws_lb_target_group.lb_tg.name}"
	  }
  }
}

# ================================ ROUTE 53 =========================================
# resource "aws_route53_zone" "routezone" {
#   # name = "${var.domain_name}"
#   name = "prod.ankitpatro.me"
  
# }

resource "aws_route53_record" "route" {
  zone_id = "Z0089045TSHQ6TRWHLJC"
  name    = "prod.ankitpatro.me"
  type    = "A"

  alias {
    name                   = "${aws_lb.alb.dns_name}"
    zone_id                = "${aws_lb.alb.zone_id}"
    evaluate_target_health = true
  }
}
