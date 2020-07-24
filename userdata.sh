#!/bin/bash
sudo echo export "Bucketname='${s3_bucket_name}'" >> /etc/environment
sudo echo export "DBendpoint='${aws_db_endpoint}'" >> /etc/environment
sudo echo export "DB_USERNAME='${aws_db_username}'" >> /etc/environment
sudo echo export "DB_PASSWORD='${aws_db_password}'" >> /etc/environment
sudo echo export "S3_BUCKET_NAME='${s3_bucket_name}'" >> /etc/environment
sudo echo export "REGION='${aws_region}'" >> /etc/environment
sudo echo export "PROFILE='${aws_profile}'" >> /etc/environment
sudo echo export "SNS_TOPIC_ARN='${sns_topic_arn}'" >> /etc/environment



# cd /etc/systemd/system
# sudo touch webapp-reboot.service
# sudo chown -R ubuntu:ubuntu webapp-reboot.service
# sudo echo "[Unit]" >> webapp-reboot.service
# sudo echo "Description=Run Web Application" >> webapp-reboot.service
# sudo echo "[Service]" >> webapp-reboot.service
# sudo echo "User=ubuntu" >> webapp-reboot.service
# sudo echo "WorkingDirectory=/home/ubuntu" >> webapp-reboot.service
# sudo echo "EnvironmentFile=/etc/environment" >> webapp-reboot.service
# # sudo echo "ExecStart=/home/ubuntu/java -DDB_PASSWORD=Ankit#1992 -jar webapp-0.0.1-SNAPSHOT.jar > /home/ubuntu/output 2> /home/ubuntu/output < /home/ubuntu/output &" >> webapp-reboot.service
# sudo echo "ExecStart=/home/ubuntu/webapp.sh"
# sudo echo "[Install]" >> webapp-reboot.service
# sudo echo "WantedBy=multi-user.target" >> webapp-reboot.service
# sudo systemctl daemon-reload
# sudo systemctl enable webapp-reboot.service
# source /etc/environment