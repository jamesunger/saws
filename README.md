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

A JSON config file provides EC2 and other service information.

Commands available:

1. saws -a create
2. saws -a destroy
3. saws -a package
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


Example
-------
<pre>
$ ./saws -a create
Created new VPC: vpc-35b7a950
Creating EC2 instance: salt
Created i-70586aa3
External IP:  52.3.204.96
Configured for NAT:  i-70586aa3
Creating EC2 instance: debiantest1
Created i-b6586a65
Creating EC2 instance: debiantest2
Created i-b0586a63
Creating EC2 instance: wintest1
Created i-6f596bbc
External IP:  52.7.101.142
$ ssh -i ../tor-cloud-servers.pem admin@52.3.204.96
The authenticity of host '52.3.204.96 (52.3.204.96)' can't be established.
ECDSA key fingerprint is 66:44:c6:60:cb:b8:c1:29:0e:a6:45:3c:26:41:f4:a4.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '52.3.204.96' (ECDSA) to the list of known hosts.
Linux ip-192-168-98-198 3.2.0-4-amd64 #1 SMP Debian 3.2.65-1+deb7u1 x86_64
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
admin@salt:~$ sudo su
root@salt:/home/admin# salt-key -L
Accepted Keys:
Denied Keys:
Unaccepted Keys:
debiantest1
debiantest2
wintest1
Rejected Keys:
root@salt:/home/admin# salt-key -A -y
The following keys are going to be accepted:
Unaccepted Keys:
debiantest1
debiantest2
wintest1
Key for minion debiantest1 accepted.
Key for minion debiantest2 accepted.
Key for minion wintest1 accepted.
root@salt:/home/admin# salt '*' grains.item os
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
</pre>



