#!/bin/bash

echo SAWS_HOSTNAME >/etc/hostname
hostname SAWS_HOSTNAME

# setup NAT immediately if we are salt 
if [[ "SAWS_HOSTNAME" == "salt" ]]; then
	echo "1" >/proc/sys/net/ipv4/ip_forward
	iptables -t nat -I POSTROUTING -s SAWS_VPC -d 0.0.0.0/0 -j MASQUERADE
fi

# sleep 30 seconds to give everything some time to settle...
sleep 30


echo "deb http://debian.saltstack.com/debian wheezy-saltstack main" >>/etc/apt/sources.list
sudo apt-get update
sudo apt-get -y install curl unzip libjson-perl
curl -O https://bootstrap.pypa.io/get-pip.py
sudo python get-pip.py
sudo pip install awscli

export AWS_SECRET_ACCESS_KEY=SAWS_SECRET_KEY
export AWS_REGION=us-east-1
export AWS_ACCESS_KEY_ID=SAWS_ACCESS_KEY

/usr/local/bin/aws s3 cp s3://SAWS_S3BUCKET/package.zip /root/package.zip
mkdir /root/saws-package
cd /root/saws-package
unzip /root/package.zip

INFOEXISTS="$(/usr/local/bin/aws s3 cp s3://SAWS_S3BUCKET/saws-info.json /root/saws-info.json 2>&1 > /dev/null)"
while [[ "$INFOEXISTS" == *"404"* ]]; do
        echo "Waiting for info file to exist..."
        INFOEXISTS="$(/usr/local/bin/aws s3 cp s3://SAWS_S3BUCKET/saws-info.json /root/saws-info.json 2>&1 > /dev/null)"
        sleep 5
done

perl /root/saws-package/gen-hosts.pl

## install salt
if [[ "SAWS_HOSTNAME" == "salt" ]]; then
	echo "iptables -t nat -I POSTROUTING -s SAWS_VPC -d 0.0.0.0/0 -j MASQUERADE" >>/etc/rc.local
	echo "echo \"1\" >/proc/sys/net/ipv4/ip_forward" >>/etc/rc.local
        apt-get -y --force-yes install salt-master
else
	apt-get update
        apt-get -y --force-yes install salt-minion
	sudo apt-get -y install nginx
	sudo service nginx start
fi

