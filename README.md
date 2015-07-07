# saws
Simple AWS tool
---------------

This tool provides a simple way to bootstrap AWS environments. It supports
simple commands to create, destroy or package system configuration. S3 is used
to store configuration data which is referenced by the initial configuration
script using the UserData feature of AWS.

NOTE: This is a very, very early WIP.

A JSON config file provides EC2 and other service information.

Four simple commands exist now:
  saws -a create
  saws -a destroy
  saws -a package
  saws -a push

Create creates any services (e.g., EC2 nodes) defined in JSON.

Destroy terminates all ec2 services.

Package creates a zip of configuration data to prep for upload to S3

Pack publishes the package.zip to the configured S3 repo
