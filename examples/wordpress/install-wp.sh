#!/bin/bash

apt-get install -y nginx php5-cli php5-cgi spawn-fcgi php5-cgi php5-mysql php5-curl php5-gd php5-idn php-pear php5-imagick php5-imap php5-mcrypt php5-memcache php5-ming php5-pspell php5-recode php5-snmp php5-sqlite php5-tidy php5-xmlrpc php5-xsl

cd /usr/share/nginx/www
wget http://wordpress.org/latest.tar.gz
tar xvf latest.tar.gz

cd wordpress
cp wp-config-sample.php wp-config.php

rdsendpoint=$(cat /root/saws-info.json | json_pp | grep '"Address"' | cut -d ':' -f 2 | tr -d '"' | tr -d ',' | tr -d ' ')

echo $rdsendpoint
sed -ri 's/database_name_here/wp/' wp-config.php
sed -ri 's/username_here/mysqlroot/' wp-config.php
sed -ri 's/password_here/ibai3ah85/' wp-config.php
sed -ri "s/localhost/$rdsendpoint/" wp-config.php
sed -ri "s/put your unique phrase here/not very unique phrase/" wp-config.php


/usr/bin/spawn-fcgi -a 127.0.0.1 -p 9000 -u www-data -g www-data -f /usr/bin/php5-cgi -P /var/run/fastcgi-php.pid
sed -ri "s/exit 0//" /etc/rc.local
echo -e "/usr/bin/spawn-fcgi -a 127.0.0.1 -p 9000 -u www-data -g www-data -f /usr/bin/php5-cgi -P /var/run/fastcgi-php.pid" >>/etc/rc.local

cp /root/saws-package/nginx-site-config.txt  /etc/nginx/sites-enabled/default
service nginx restart
