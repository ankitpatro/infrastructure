#!/bin/bash
sudo echo export "Bucketname='${s3_bucket_name}'" >> /etc/environment
sudo echo export "DBendpoint='${aws_db_endpoint}'" >> /etc/environment
sudo echo export "DB_USERNAME='${aws_db_username}'" >> /etc/environment
sudo echo export "DB_PASSWORD='${aws_db_password}'" >> /etc/environment
sudo echo export "S3_BUCKET_NAME='${s3_bucket_name}'" >> /etc/environment
sudo echo export "REGION='${aws_region}'" >> /etc/environment
sudo echo export "PROFILE='${aws_profile}'" >> /etc/environment


              
