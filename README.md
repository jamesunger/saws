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
Created new VPC: vpc-d5fde3b0
Creating EC2 instance: salt
Created i-013202d2
External IP:  52.2.198.199
Configured for NAT:  i-013202d2
Creating EC2 instance: debiantest1
Created i-ed33033e
Creating EC2 instance: debiantest2
Created i-183303cb
Creating EC2 instance: wintest1
Created i-1c3303cf
External IP:  52.7.11.206
</pre>

Now you can login to the 'salt' demo node which has an external ip:
<pre>
ssh -i /path/to/sshkey admin@52.2.198.199
</pre>

We can start using salt right away since the hosts should know about each other:
<pre>
root@salt:/home/admin# salt-key -L
Accepted Keys:
Denied Keys:
Unaccepted Keys:
debiantest1
debiantest2
wintest1
Rejected Keys:
</pre>

Which we can add with <code>salt-key -A -y</code> and now we can control our test cluster:

<pre>
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
