Simple AWS tool
---------------

This tool provides a simple way to bootstrap AWS environments. It supports
simple commands to create, destroy or package system configuration (user
defined scripts). S3 is used to store configuration data which is referenced by
the initial configuration script using the UserData feature of AWS.

The primary motivation for a tool like this is the ability to easily hack up
test environments or maintain repeatable and easy to boostrap virtual
environments.

NOTE: This is a very, very early WIP. I wouldn't use it for anything. :)

Motivation
----------

I needed a simple AWS bootstrap tool that meets the following criteria:

1. All CM materials housed in a git/hg/svn repo, pushed to and deployed from S3.
2. Facilitate immutable infrastructure without relying on AMIs or baked images.
3. Simple configuration file that controls destruction/creation of AWS resources.
4. Cross platform (windows/linux).
5. Less configuration is more, specify only what you need. Assume sane defaults for as much as possible. Further configuration should be handled downstream in scripts, anyway.


Synopsis
--------

A JSON config file provides EC2 and other service information.

Commands available:

1. saws -a create
2. saws -a destroy
3. saws -a pack
4. saws -a push
5. saws -a stop
6. saws -a start

Create creates any services (e.g., EC2 nodes) defined in JSON.

Destroy terminates all ec2 services.

Pack creates a zip of configuration data to prep for upload to S3, which the intial-config scripts reference.

Push publishes the package.zip to the configured S3 repo.

Stop/Start start and stop all EC2 nodes.

saws.json
---------

The saws.json file defines the VPC and associated AWS services and is the only configuration input for <code>saws</code>. Saws expects to find the saws.json (or specifically overloaded via -c) file in the current directory along with the associated scripts and data used to initialize the nodes.

The configuration file is designed to contain the minimum amount of information necessary to determinately recreate an environment. Important JSON configuration params:

* initialconfig: file to use for initial UserData. This file will be templated with key AWS information: SAWS_ACCESSKEY, SAWS_SECRETKEY, SAWS_S3BUCKET, SAWS_HOSTNAME, SAWS_VPC
* s3bucket: the S3 bucket to store central configuration data. This will be automatically created if it does not exist
* vpc: the CIDR range of the VPC. This should encompass any private/public subnet CIDR range.
* privatenet: the CIDR range of the private subnet in the VPC
* publicnet: the CIDR range of the public subnet in the VPC
* allsecuritygroups: defines specific security groups. The only options are 'name' and 'tcpport' which affect ingress security group filters.
* ec2: an array of ec2 definitions
	* instancetype: AWS instance type
	* name: name of the EC2 instance, which will be tagged with a Name tag
	* ami: AMI to use when creating the instance
	* keyname: the SSH key/value pair used to access the instance
	* securitygroups: a list of strings to map into security groups. 'default' is always available but others must match the 'allsecuritygroups' setting
	* hasexternalip: if set to true, the instance will be given an external ip (optional)
	* isnat: if set to true, the instance will have traffic routed to it in order to NAT for other instances (optional)
	* initialconfig: an overload to use a specific initialconfig template rather than the global one (optional)
* rds: an array of rds definitions
	* dbinstanceidentifier: the name of the RDS instance
	* dbname: the default DB name, if applicable
	* engine: string representing the engine, see AWS docs. e.g., "MySQL"
	* dbinstanceclass: instance class of the RDS instance, e.g., "db.t1.micro"
	* masterusername: admin DB user
	* masteruserpassword: admin user password
* elb: an array of elb definition
	* name: name of elb
	* instanceport: port the instance is listening on, assumed to be the LB port
	* protocol: "HTTP" or "HTTPS"
	* securitygroups: array of security groups for the LB that must match the name of the 'allsecuritygroups' array
	* instances: array of instance names to be included in the LB



Example Usage
-------

The demo saws.json creates three Debian GNU/Linux instances and a Windows 2012 instance. It also create a basic load balancer and a MySQL RDS DB. The base scripts provided will bootstrap salt on each node and expose nginx to test the LB on the two Debian hosts.

First, set the following vars in your shell for the AWS lib to work: AWS_SECRET_ACCESS_KEY, AWS_REGION, AWS_DEFAULT_REGION, AWS_ACCESS_KEY_ID.

<pre>
$ ./saws -a create
Created keypair: dummykey
Key saved to file: dummykey.key
Created new VPC: vpc-89b953ed
Created MySQL RDS instance:  someid
Created instance salt: i-24bd088f
Created instance debiantest1: i-d1bc097a
Created instance debiantest2: i-4cbc09e7
Created instance wintest1: i-3122bae3
Created elb: testlb-1869659592.us-east-1.elb.amazonaws.com
Waiting for remaining 5 creation steps to complete...
1: External IP for salt assigned: 52.21.104.223
2: Configured for NAT: salt
3: External IP for debiantest2 assigned: 52.7.38.215
4: External IP for debiantest1 assigned: 52.21.105.3
5: Endpoint for RDS instance someid: someid.cqxtcggij89r.us-east-1.rds.amazonaws.com
</pre>

Now we can login to the salt host and verify Salt is working and accept the minion keys.

<pre>
$ ssh -i dummykey.key admin@52.21.104.223
The authenticity of host '52.21.104.223 (52.21.104.223)' can't be established.
ECDSA key fingerprint is 4f:e8:b5:17:29:2d:ae:66:10:2f:b3:da:94:ee:33:6f.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '52.21.104.223' (ECDSA) to the list of known hosts.
Linux ip-192-168-98-201 3.2.0-4-amd64 #1 SMP Debian 3.2.65-1+deb7u1 x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
admin@salt:~$ sudo salt-key -A -y                                                       
The following keys are going to be accepted:
Unaccepted Keys:
debiantest1
debiantest2
wintest1
Key for minion debiantest1 accepted.
Key for minion debiantest2 accepted.
Key for minion wintest1 accepted.
admin@salt:~$ sudo salt '*' grains.item os
wintest1:
    ----------
    os:
        Windows
debiantest1:
    ----------
    os:
        Debian
debiantest2:
    ----------
    os:
        Debian
admin@salt:~$ 
</pre>

And lets verify the LB is up and running.

<pre>
$ curl testlb-1869659592.us-east-1.elb.amazonaws.com
&lt;html&gt;
&lt;head&gt;
&lt;title&gt;Welcome to nginx!&lt;/title&gt;&gt;
&lt;/head&gt;
&lt;body bgcolor="white" text="black"&gt;
&lt;center>&lt;h1&gt;Welcome to nginx!&lt;/h1&gt;&lt;/center&gt;
&lt;/body>
&lt;/html>
</pre>




