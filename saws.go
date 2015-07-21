package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"encoding/base64"
	"regexp"
	"time"
	"errors"
	"strings"
	"bytes"
)

type Config struct {
	S3Bucket string `json:s3bucket`
	EC2      []EC2  `json:ec2`
	InitialConfig     string  `json:initialconfig`
	VPC string `json:vpc`
	PrivateNet string `json:privatenet`
	PublicNet string `json:publicnet`
	VPCID string `json:vpcid`
	PrivateSubnetID string `json:privatesubnetid`
	PublicSubnetID string `json:publicsubnetid`
	AllSecurityGroups []SecurityGroup `json:allsecuritygroups`
	AvailZone1 string `json:availzone1`
	AvailZone2 string `json:availzone2`
	RDS []RDS `json:rds`
}

type RDS struct {
	AllocatedStorage int64 `json:allocatedstorage`
	BackupRetentionPeriod int64 `json:backuprentationperiod`
	DBInstanceClass string `json:dbinstanceclass`
	DBInstanceIdentifier string `json:dbinstanceidentifier`
	DBName string `json:dbname`
	DBSubnetGroupName string `json:dbsubnetgroupname`
	Engine string `json:engine`
	EngineVersion string `json:engineversion`
	MasterUserPassword string `json:masteruserpassword`
	MasterUsername string `json:MasterUsername`
}

type SecurityGroup struct {
	Name string `json:name`
	TcpPort int64 `json:tcpport`
}

type EC2 struct {
	Name         string `json:string`
	InitialConfig     string  `json:initialconfig`
	InstanceType string `json:instancetype`
	AMI string `json:ami`
	KeyName string `json:keyname`
	SubnetID string `json:subnetid`
	SecurityGroupIDs []*string `json:securitygroupids`
	SecurityGroups []string `json:securitygroups`
	HasExternalIP bool `json:hasexternalip`
	IsNat bool `json:isnat`
}

type SawsInfo struct {
	EC2 []*ec2.Instance `json:ec2`
	RDS []*rds.DBInstance `json:rds`
}

func getUserData(initialconfig string, s3bucket string, hostname string, vpc string) string {
	ic, err := ioutil.ReadFile(initialconfig)
	if err != nil {
		panic(err)
	}



	accid := os.Getenv("AWS_ACCESS_KEY_ID")
	seck := os.Getenv("AWS_SECRET_ACCESS_KEY")

	if accid == "" {
		panic("Error: need to set env var AWS_ACCESS_KEY_ID")
	}

	if seck == "" {
		panic("Error: need to set env var AWS_SECRET_ACCESS_KEY")
	}


	rxpid := regexp.MustCompile("SAWS_ACCESS_KEY")
	rxpkey := regexp.MustCompile("SAWS_SECRET_KEY")
	rxp3 := regexp.MustCompile("SAWS_S3BUCKET")
	rxphostname := regexp.MustCompile("SAWS_HOSTNAME")
	rxpvpc := regexp.MustCompile("SAWS_VPC")
	ic1 := rxpid.ReplaceAll(ic, []byte(accid))
	ic2 := rxpkey.ReplaceAll(ic1, []byte(seck))
	ic3 := rxp3.ReplaceAll(ic2, []byte(s3bucket))
	ic4 := rxphostname.ReplaceAll(ic3, []byte(hostname))
	ic5 := rxpvpc.ReplaceAll(ic4, []byte(vpc))


	return base64.StdEncoding.EncodeToString([]byte(ic5))
}

func parseConfig(configfile string) *Config {
	config := &Config{}
	fc, err := ioutil.ReadFile(configfile)
	if err != nil {
		panic(err)
	}

	err = json.Unmarshal(fc, config)
	if err != nil {
		panic(err)
	}

	return config
}

func uploadPackage(config *Config) error {
	key := "package.zip"
	uploadfile, err := os.Open(key)
	if err != nil {
		return err
	}

	fmt.Println("Uploading package.zip to", config.S3Bucket, "bucket...")
	uploader := s3manager.NewUploader(nil)
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: &config.S3Bucket,
		Key:    &key,
		Body:   uploadfile,
	})

	if err != nil {
		panic(err)
	}

	fmt.Println("Uploaded package.zip to", config.S3Bucket, "bucket.")

	return nil
}

func deleteSawsInfo(config *Config) error {
	key := "saws-info.json"
	doi := &s3.DeleteObjectInput{ Bucket: &config.S3Bucket, Key: &key }

	svc := s3.New(nil)
	_,err := svc.DeleteObject(doi)
	//fmt.Println(doo)
	if err != nil {
		fmt.Println("Failed to delete saws-info.json")
		return err
	}

	return nil

}

func sendSawsInfo(config *Config) error {
	jsonBytes := getJsonSawsInfo(config)
	jsonBytesReader := bytes.NewReader(jsonBytes)

	key := "saws-info.json"
	uploader := s3manager.NewUploader(nil)
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: &config.S3Bucket,
		Key:    &key,
		Body:   jsonBytesReader,
	})

	if err != nil {
		fmt.Println("Failed to upload saws-info.json.")
		return err
	}


	return nil
}

func Push(config *Config) {
	uploadPackage(config)
}

func waitForNonXState(svc *ec2.EC2, instanceid *string, state string) error {
	iids := []*string{ instanceid }
	dii := &ec2.DescribeInstancesInput {
		InstanceIDs: iids,
	}

	dio,err := svc.DescribeInstances(dii)
	if err != nil {
		panic(err)
	}


	//fmt.Println("waiting for instance to leave state", state)
	//fmt.Println(dio)
	count := 0
	for {
		dio,err = svc.DescribeInstances(dii)
		if err != nil {
			panic(err)
		}

		if *dio.Reservations[0].Instances[0].State.Name != state {
			return nil
		}

		if count > 20 {
			break
		}

		time.Sleep(2*time.Second)
		count++
		//fmt.Println(dio)
		//fmt.Println("waiting for instance to leave state ", state)
	}


	return errors.New(fmt.Sprintf("Waited too long for EC2 to leave %s state",state))


}

func waitForNonPendingState(svc *ec2.EC2, instanceid *string) error {
	iids := []*string{ instanceid }
	dii := &ec2.DescribeInstancesInput {
		InstanceIDs: iids,
	}

	dio,err := svc.DescribeInstances(dii)
	if err != nil {
		panic(err)
	}


	//fmt.Println("waiting for non pending state...")
	//fmt.Println(dio)
	count := 0
	for {
		dio,err = svc.DescribeInstances(dii)
		if err != nil {
			panic(err)
		}

		if *dio.Reservations[0].Instances[0].State.Name != "pending" {
			return nil
		}

		if count > 20 {
			break
		}

		time.Sleep(2*time.Second)
		count++
		//fmt.Println(dio)
		//fmt.Println("waiting for non pending state...")
	}


	return errors.New("Waited too long for EC2 to leave pending state.")

}

func createInstance(svc *ec2.EC2, config *Config, ec2config EC2, userdata string) {
	var min int64
	var max int64
	min = 1
	max = 1



	var subnet string
	if ec2config.HasExternalIP {
		subnet = config.PublicSubnetID
	} else {
		subnet = config.PrivateSubnetID
	}

	ec2config.SecurityGroupIDs = getSecurityGroupIDs(svc, config, &ec2config)
	params := &ec2.RunInstancesInput{
		ImageID:      &ec2config.AMI,
		InstanceType: &ec2config.InstanceType,
		MaxCount: &max,
		MinCount: &min,
		KeyName: &ec2config.KeyName,
		UserData: &userdata,
		SubnetID: &subnet,
		SecurityGroupIDs: ec2config.SecurityGroupIDs,
	}
	//fmt.Println("Create instance params:", params)

	rres, err := svc.RunInstances(params)
	if err != nil {
		fmt.Println("Failed to create instance",err)
		fmt.Println(rres)
	} else {
		fmt.Println("Created", *rres.Instances[0].InstanceID)
		//fmt.Println(rres)

		//fmt.Println("Sleeping for a sec to give AWS some time ...")


	time.Sleep(1*time.Second)

		keyname := "Name"
		_, err := svc.CreateTags(&ec2.CreateTagsInput{
			Resources: []*string{rres.Instances[0].InstanceID},
			Tags:      []*ec2.Tag{
				&ec2.Tag{
					Key:   &keyname,
					Value:   &ec2config.Name,
				},
			},
		})
		//fmt.Println(tres)


		if err != nil {
			fmt.Println("Could not create tags for instance ", rres.Instances[0].InstanceID)
			fmt.Println(err)
		} //else {
			//fmt.Println("Created tag Name with value", ec2config.Name)
		//}


		//fmt.Println("hasexternalip ", ec2config.HasExternalIP)
		if ec2config.HasExternalIP {
			vpcs := "vpc"
			aao,err := svc.AllocateAddress(&ec2.AllocateAddressInput{ Domain: &vpcs })
			if err != nil {
				fmt.Println("Could not allocate addr:", err)
			}

			//fmt.Println(aao)


			err = waitForNonPendingState(svc, rres.Instances[0].InstanceID)
			if err != nil {
				fmt.Println(err)
			} else {
				//aai,err := svc.AssociateAddress(&ec2.AssociateAddressInput{ PublicIP: aao.PublicIP, InstanceID: rres.Instances[0].InstanceID })
				_,err := svc.AssociateAddress(&ec2.AssociateAddressInput{ AllocationID: aao.AllocationID, InstanceID: rres.Instances[0].InstanceID })
				if err != nil {
					fmt.Println("Could not assign addr:", err)
				}

				//fmt.Println(aai)
			}

			fmt.Println("External IP: ", *aao.PublicIP)

		}

		//fmt.Println("isnat", ec2config.IsNat)
		if ec2config.IsNat {
			bv := false
			abv := &ec2.AttributeBooleanValue{ Value: &bv }
			miai := &ec2.ModifyInstanceAttributeInput{ InstanceID: rres.Instances[0].InstanceID, SourceDestCheck: abv }
			_,err := svc.ModifyInstanceAttribute(miai)
			if err != nil {
				fmt.Println("Failed to change sourcedestcheck", err)
			}

			routeid,err := getPrivateRouteTable(svc, &config.PrivateSubnetID, config.VPCID)
			if err != nil {
				routeid,err = createPrivateRouteTable(svc, config)
			} else {
				_ = deleteDefaultRoute(svc,routeid)
				/*if err != nil {
					fmt.Println("Error deleting default route or default route existed", err)
				}*/
			}

			defr := "0.0.0.0/0"
			cri := &ec2.CreateRouteInput{ DestinationCIDRBlock: &defr, InstanceID: rres.Instances[0].InstanceID, RouteTableID: routeid }
			_,err = svc.CreateRoute(cri)
			if err != nil {
				fmt.Println("Error adding new default route to NAT node", err)
			}

			fmt.Println("Configured for NAT: ", *rres.Instances[0].InstanceID)
		}

	}

}

func getNonTerminatedInstance(instances []*ec2.Instance) *ec2.Instance {
	for i := range instances {
		fmt.Println(instances[i])
		if instances[i].InstanceID != nil && *instances[i].State.Name != "terminated" {
			fmt.Println("Found instance!")
			return instances[i]
		}
	}

	return &ec2.Instance{}
}

func getInstancesByName(svc *ec2.EC2, tag string) []*ec2.Instance {
	keyname := "tag:Name"
	keyvalue := tag

	filter := ec2.Filter{
		Name: &keyname, Values: []*string{ &keyvalue } }
	filters := []*ec2.Filter{
		&filter,
	}

	dii := &ec2.DescribeInstancesInput {
		Filters: filters,
	}

	dio,err := svc.DescribeInstances(dii)
	if err != nil {
		panic(err)
	}


	//if len(dio.Reservations) == 0 {
	//	return &ec2.Instance{}
	//} else if len(dio.Reservations) >= 2 {
	//	fmt.Println("More than on instance found...")
	//	return getNonTerminatedInstance(dio.Reservations[0].Instances)
	//} else {
	//	return dio.Reservations[0].Instances[0]
	//}

	instances := make([]*ec2.Instance,0)
	//instances := []*ec2.Instance
	for i := range dio.Reservations {
		for k := range dio.Reservations[i].Instances {
			instances = append(instances, dio.Reservations[i].Instances[k])
		}
	}

	//fmt.Println(instances)
	return instances

}

func getRDSInstanceById(rdsc *rds.RDS, rdsconf *RDS) (*rds.DBInstance,error) {
	ddbii := &rds.DescribeDBInstancesInput{ DBInstanceIdentifier: &rdsconf.DBInstanceIdentifier }
	ddbo, err := rdsc.DescribeDBInstances(ddbii)
	if err != nil {
		return nil,err
	}

	return ddbo.DBInstances[0],nil

}

func getJsonSawsInfo(config *Config) []byte {
	svc := ec2.New(nil)
	rdsc := rds.New(nil)
	instancelist := make([]*ec2.Instance,0)
	for i := range config.EC2 {
		//fmt.Println(config.EC2[i].Name)
		instances := getInstancesByName(svc,config.EC2[i].Name)
		for k := range instances {
			instancelist = append(instancelist,instances[k])
		}
	}

	rdslist := make([]*rds.DBInstance,0)
	for i := range config.RDS {
		//fmt.Println(config.RDS[i].DBInstanceIdentifier)
		dbinstance,err := getRDSInstanceById(rdsc,&config.RDS[i])
		if err != nil {
			//fmt.Println("Failed to find db instance", config.RDS[i].DBInstanceIdentifier)
		} else {
			rdslist = append(rdslist,dbinstance)
		}
	}

	sawsinfo := SawsInfo{}
	sawsinfo.EC2 = instancelist
	sawsinfo.RDS = rdslist

	marsh,err := json.Marshal(&sawsinfo)
	if err != nil {
		fmt.Println("Failed to unmarshal", err)
		panic(err)
	}


	return marsh

}

func Stat(config *Config) {
	//svc := ec2.New(nil)


	instanceinfo := getJsonSawsInfo(config)
	fmt.Println(string(instanceinfo))

	/*

	for i := range config.EC2 {
		fmt.Println(config.EC2[i].Name)
		fmt.Println(config.EC2[i].InstanceType)

		instances := getInstancesByName(svc,config.EC2[i].Name)


		//exists := false
		for k := range instances {
			fmt.Println(*instances[k].InstanceID)
			fmt.Println(instances[k])


			userd := "userData"
			diai := &ec2.DescribeInstanceAttributeInput{
					Attribute: &userd,
					InstanceID: instances[k].InstanceID,
			}
			dao,err := svc.DescribeInstanceAttribute(diai)
			if err != nil {
				fmt.Println(err)
			}
			data,_ := base64.StdEncoding.DecodeString(*dao.UserData.Value)
			fmt.Println(string(data))
			//fmt.Println(dao.UserData.Value)
		}
	}
	*/


}

func getMainRouteTableFromVPC(svc *ec2.EC2, VPCID *string) (*string, error) {

	keyname := "association.main"
	asbool := "true"
	filters := make([]*ec2.Filter,0)
	filter := ec2.Filter{
		Name: &keyname, Values: []*string{ &asbool } }
	filters = append(filters,&filter)

	//fmt.Println("Filters ", filters)


	drti := &ec2.DescribeRouteTablesInput{ Filters: filters}
	drto,err := svc.DescribeRouteTables(drti)
	if err != nil {
		panic(err)
	}

	for i := range drto.RouteTables {
		if *drto.RouteTables[i].VPCID == *VPCID {
			//fmt.Println("Route table is", *drto.RouteTables[i].RouteTableID)
			return drto.RouteTables[i].RouteTableID,nil
		}
	}

	return nil,errors.New(fmt.Sprintf("No main route table found for vpc", *VPCID))

}



func getPrivateRouteTable(svc *ec2.EC2, subnetid *string, VPCID string) (*string, error) {
	keyname := "association.subnet-id"
	filters := make([]*ec2.Filter,0)
	filter := ec2.Filter{
		Name: &keyname, Values: []*string{ subnetid } }
	filters = append(filters,&filter)

	//fmt.Println("Filters ", filters)

	drti := &ec2.DescribeRouteTablesInput{Filters: filters}
	drto,err := svc.DescribeRouteTables(drti)
	if err != nil {
		panic(err)
	}

	for i := range drto.RouteTables {
		if *drto.RouteTables[i].VPCID == VPCID {
			//fmt.Println("Route table is", *drto.RouteTables[i].RouteTableID)
			return drto.RouteTables[i].RouteTableID,nil
		}
	}

	return nil,errors.New(fmt.Sprintf("No route table found for subnet", *subnetid))

}




func deleteDefaultRoute(svc *ec2.EC2, rtid *string) error {
	defr := "0.0.0.0/0"
	dri := &ec2.DeleteRouteInput{ DestinationCIDRBlock: &defr, RouteTableID: rtid}
	_,err := svc.DeleteRoute(dri)
	if err != nil {
		return err
	}

	return nil
}

func createGateway(svc *ec2.EC2, vpc *ec2.VPC, subid *string) error {
	cigi := &ec2.CreateInternetGatewayInput{}
	cigo,err := svc.CreateInternetGateway(cigi)
	if err != nil {
		fmt.Println("Failed to create gateway.")
		return err
	}

	//fmt.Println("We have vpcid: " + *vpc.VPCID)
	_,err = svc.AttachInternetGateway(&ec2.AttachInternetGatewayInput{InternetGatewayID: cigo.InternetGateway.InternetGatewayID, VPCID: vpc.VPCID})
	if err != nil {
		fmt.Println("Failed to attach gateway.")
		return err
	}

	defr := "0.0.0.0/0"
	rtid,err := getMainRouteTableFromVPC(svc, vpc.VPCID)
	if err != nil {
		fmt.Println("Failed to get route table from VPC id.")
		panic(err)
	}
	cri := &ec2.CreateRouteInput{ DestinationCIDRBlock: &defr, GatewayID: cigo.InternetGateway.InternetGatewayID, RouteTableID: rtid }
	_,err = svc.CreateRoute(cri)
	//fmt.Println(cro)
	if err != nil {
		fmt.Println("Failed to create default route.")
		return err
	}

	arti := &ec2.AssociateRouteTableInput{ RouteTableID: rtid, SubnetID: subid }
	_, err = svc.AssociateRouteTable(arti)
	//fmt.Println(arto)
	if err != nil {
		fmt.Println("Failed to associate subnet with route table.")
		return err
	}

	return nil

}

func createSecurityGroups(c *ec2.EC2, config *Config) error {
		for j := range config.AllSecurityGroups {
			csgi := &ec2.CreateSecurityGroupInput{ GroupName: &config.AllSecurityGroups[j].Name, VPCID: &config.VPCID, Description: &config.AllSecurityGroups[j].Name }
			csgo,err := c.CreateSecurityGroup(csgi)
			//fmt.Println(err)
			if err != nil {
				fmt.Println("Failed to create security group.")
				fmt.Println(err)
				if !strings.Contains(fmt.Sprintf("%s",err),"InvalidGroup.Duplicate") {
					return err
				}
				continue
			}

			everywhere := "0.0.0.0/0"
			proto := "tcp"
			//var fromPort int64
			//fromPort = -1
			asgii := &ec2.AuthorizeSecurityGroupIngressInput{ CIDRIP: &everywhere, FromPort: &config.AllSecurityGroups[j].TcpPort, ToPort: &config.AllSecurityGroups[j].TcpPort, GroupID: csgo.GroupID, IPProtocol: &proto }
			_,err = c.AuthorizeSecurityGroupIngress(asgii)
			//fmt.Println("Adding security group", asgii)
			if err != nil {
				fmt.Println("Failed to add rule to security group: ", err)
				return err
			}
		}

	return nil

}

func createSubnets(svc *ec2.EC2, config *Config) (*ec2.CreateSubnetOutput, *ec2.CreateSubnetOutput, error) {


	var csi *ec2.CreateSubnetInput
	if config.AvailZone1 != "" {
		csi = &ec2.CreateSubnetInput{ CIDRBlock: &config.PublicNet, VPCID: &config.VPCID, AvailabilityZone: &config.AvailZone1 }
	} else {
		csi = &ec2.CreateSubnetInput{ CIDRBlock: &config.PublicNet, VPCID: &config.VPCID }
	}
	//csi := &ec2.CreateSubnetInput{ CIDRBlock: &config.PublicNet, VPCID: &config.VPCID }
	cso1,err := svc.CreateSubnet(csi)
	if err != nil {
		fmt.Println("Create public subnet failed")
		return nil,nil,err
	}
	//fmt.Println(cso1)
	config.PublicSubnetID = *cso1.Subnet.SubnetID

	if config.AvailZone2 != "" {
		csi = &ec2.CreateSubnetInput{ CIDRBlock: &config.PrivateNet, VPCID: &config.VPCID, AvailabilityZone: &config.AvailZone2 }
	} else {
		csi = &ec2.CreateSubnetInput{ CIDRBlock: &config.PrivateNet, VPCID: &config.VPCID }
	}
	//csi := &ec2.CreateSubnetInput{ CIDRBlock: &config.PublicNet, VPCID: &config.VPCID }
	//csi = &ec2.CreateSubnetInput{ CIDRBlock: &config.PrivateNet, VPCID: &config.VPCID}
	cso2,err := svc.CreateSubnet(csi)
	if err != nil {
		fmt.Println("Create private subnet failed")
		return nil,nil,err
	}
	//fmt.Println(cso2)
	config.PrivateSubnetID = *cso2.Subnet.SubnetID


	return cso1,cso2,nil

}

func createPrivateRouteTable(svc *ec2.EC2, config *Config) (*string, error) {
	crt := &ec2.CreateRouteTableInput{ VPCID: &config.VPCID }
	crto,err := svc.CreateRouteTable(crt)
	if err != nil {
		fmt.Println("Failed to create private route table.")
		return nil,err
	}


	arti := &ec2.AssociateRouteTableInput{ RouteTableID: crto.RouteTable.RouteTableID, SubnetID: &config.PrivateSubnetID }
	_, err = svc.AssociateRouteTable(arti)
	//fmt.Println(arto)
	if err != nil {
		fmt.Println("Failed to associate private subnet with route table.")
		return nil,err
	}


	return crto.RouteTable.RouteTableID,nil

}

func getSecurityGroupIDs(c *ec2.EC2, config *Config, inst *EC2) ([]*string) {


	//secgroups := make([]*string,0)
	secgroupids := make([]*string,0)
	for i := range inst.SecurityGroups {
		filters := make([]*ec2.Filter,0)
		//secgroups = append(secgroups,&inst.SecurityGroups[i])

		keyname := "group-name"
		keyname2 := "vpc-id"
		filter := ec2.Filter{
			Name: &keyname, Values: []*string{ &inst.SecurityGroups[i] } }
		filter2 := ec2.Filter{
			Name: &keyname2, Values: []*string{ &config.VPCID } }
		filters = append(filters,&filter)
		filters = append(filters,&filter2)

		//fmt.Println("Filters ", filters)

		dsgi := &ec2.DescribeSecurityGroupsInput{ Filters: filters }
		dsgo,err := c.DescribeSecurityGroups(dsgi)
		if err != nil {
			fmt.Println("Describe security groups failed.")
			panic(err)
		}

		for i := range dsgo.SecurityGroups {
			secgroupids = append(secgroupids,dsgo.SecurityGroups[i].GroupID)
		}

	}


	//fmt.Println("Security Groups!", secgroupids)
	return secgroupids

}

func verifyAndCreateVPC(c *ec2.EC2, config *Config) error {

	dvi := &ec2.DescribeVPCsInput{}
	dvo,err := c.DescribeVPCs(dvi)
	if err != nil {
		return err
	}


	vpc := &ec2.VPC{}
	vpcexists := false
	for i := range dvo.VPCs {
		if *dvo.VPCs[i].CIDRBlock == config.VPC {
			vpc = dvo.VPCs[i]
			vpcexists = true
			config.VPCID = *dvo.VPCs[i].VPCID
			fmt.Println("VPC already exists.")
		}
	}




	if vpcexists {

		err = createSecurityGroups(c, config)
		if err != nil {
			fmt.Println("Failed to create security groups.")
			panic(err)
		}

		/*
		sgids := getSecurityGroupIDs(c,config, BOOK
		err = applySecurityGroups(c, config)
		if err != nil {
			fmt.Println("Failed to apply security groups.")
			panic(err)
		}
		*/

		dsi := &ec2.DescribeSubnetsInput{}
		dso,err := c.DescribeSubnets(dsi)
		if err != nil {
			panic(err)
		}


		haspriv := false
		haspub := false
		for i := range dso.Subnets {
			if *dso.Subnets[i].CIDRBlock == config.PublicNet {
				fmt.Println("Subnet for public VPC already exists.")
				config.PublicSubnetID = *dso.Subnets[i].SubnetID
				haspub = true
				continue
			}

			if *dso.Subnets[i].CIDRBlock == config.PrivateNet {
				fmt.Println("Subnet for private VPC already exists.")
				config.PrivateSubnetID = *dso.Subnets[i].SubnetID
				haspriv = true
				continue
			}
		}

		if haspub && haspriv {
			return nil
		}

		cso1,cso2,err := createSubnets(c, config)
		if err != nil {
			panic(err)
		}
		config.PublicSubnetID = *cso1.Subnet.SubnetID
		config.PrivateSubnetID = *cso2.Subnet.SubnetID

		_,err = createPrivateRouteTable(c,config)
		if err != nil {
			panic(err)
		}


		return createGateway(c, vpc, cso1.Subnet.SubnetID)

	}

	cvi := &ec2.CreateVPCInput{ CIDRBlock: &config.VPC }
	cvo, err := c.CreateVPC(cvi)

	if err != nil {
		return err
	}
	config.VPCID = *cvo.VPC.VPCID
	fmt.Println("Created new VPC: " + config.VPCID)

	//fmt.Println(cvo)
	err = createSecurityGroups(c, config)
	if err != nil {
		fmt.Println("Failed to create security groups.")
		panic(err)
	}

	/*
	err = applySecurityGroups(c, config)
	if err != nil {
		fmt.Println("Failed to apply security groups.")
		panic(err)
	}
	*/


	cso1,cso2,err := createSubnets(c, config)
	config.PublicSubnetID = *cso1.Subnet.SubnetID
	config.PrivateSubnetID = *cso2.Subnet.SubnetID

	_,err = createPrivateRouteTable(c,config)
	if err != nil {
		panic(err)
	}

	return createGateway(c, cvo.VPC, cso1.Subnet.SubnetID)

}

func Create(config *Config) {
	//fmt.Println("Create not implemented")

	svc := ec2.New(nil)
	rdsc := rds.New(nil)

	err := verifyAndCreateVPC(svc,config)
	if err != nil {
		panic(err)
	}



	err = deleteSawsInfo(config)
	if err != nil {
		panic(err)
	}

	for i := range config.RDS {
		// setup RDS instances

		groupname := "sawsdbprivate"
		cdbsgi := &rds.CreateDBSubnetGroupInput{ DBSubnetGroupName: &groupname, SubnetIDs: []*string { &config.PrivateSubnetID, &config.PublicSubnetID }, DBSubnetGroupDescription: &groupname }
		cdsgo,err := rdsc.CreateDBSubnetGroup(cdbsgi)
		if err != nil {
			fmt.Println("Failed to create db subnetgroup:", err)
			//FIXME: search for subnet gorup if already created
			panic(err)
		}
		//fmt.Println(cdsgo)

		/*
		fmt.Println("Creating with:", config.RDS[i])
		fmt.Println("DBSubnetGroupName: ", cdsgo.DBSubnetGroup.DBSubnetGroupName)
		fmt.Println("Engine: ", config.RDS[i].Engine)
		fmt.Println("DBName: ", config.RDS[i].DBName)
		fmt.Println("DBInstanceIdentifier: ", config.RDS[i].DBInstanceIdentifier)
		fmt.Println("AllocatedStorage: ", config.RDS[i].AllocatedStorage)
		fmt.Println("DBInstanceClass: ", config.RDS[i].DBInstanceClass)
		fmt.Println("MasterUsername: ", config.RDS[i].MasterUsername)
		fmt.Println("MasterUserPassword: ", config.RDS[i].MasterUserPassword)
		*/

		cdbi := &rds.CreateDBInstanceInput{
				DBSubnetGroupName: cdsgo.DBSubnetGroup.DBSubnetGroupName,
				Engine: &config.RDS[i].Engine,
				DBName: &config.RDS[i].DBName,
				DBInstanceIdentifier: &config.RDS[i].DBInstanceIdentifier,
				AllocatedStorage: &config.RDS[i].AllocatedStorage,
				DBInstanceClass: &config.RDS[i].DBInstanceClass,
				MasterUsername: &config.RDS[i].MasterUsername,
				MasterUserPassword: &config.RDS[i].MasterUserPassword,
		}
		_, err = rdsc.CreateDBInstance(cdbi)
		if err != nil {
			fmt.Println("Error creating db instance:",err)
			panic(err)
		}
		//fmt.Println(cdbo)
		fmt.Println("Created", config.RDS[i].Engine, "RDS instance: ", config.RDS[i].DBInstanceIdentifier)
	}

	//fmt.Println("Creating with", config)
	for i := range config.EC2 {
		fmt.Println("Creating EC2 instance:", config.EC2[i].Name)
		//fmt.Println(config.EC2[i].InstanceType)

		instances := getInstancesByName(svc,config.EC2[i].Name)

		exists := false
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				//fmt.Println("Instance is terminated:", *instances[k].InstanceID)
			} else {
				fmt.Println("Instance already exists: ", *instances[k].InstanceID)
				exists = true
			}
		}


		if !exists {
			//fmt.Println("No instance found, creating...")
			var userdata string
			if config.EC2[i].InitialConfig == "" {
				userdata = getUserData(config.InitialConfig,config.S3Bucket,config.EC2[i].Name, config.VPC)
			} else {
				userdata = getUserData(config.EC2[i].InitialConfig,config.S3Bucket,config.EC2[i].Name, config.VPC)
			}
			createInstance(svc, config, config.EC2[i], userdata)
		}

	}



	//if len(config.RDS) > 0 {
	//	fmt.Println("Waiting for 
	//}
	//jsonInstanceInfo := getJsonInstanceInfo(config)
	//fmt.Println(jsonInstanceInfo)
	err = sendSawsInfo(config)
	if err != nil {
		panic(err)
	}

	//fmt.Println("Creating with", config)
}

func releaseExternalIP(svc *ec2.EC2, instanceid string) error {
	keyname := "instance-id"

	filter := ec2.Filter{
		Name: &keyname, Values: []*string{ &instanceid } }
	filters := []*ec2.Filter{
		&filter,
	}
	dai := &ec2.DescribeAddressesInput{ Filters: filters }
	dao,err := svc.DescribeAddresses(dai)
	if err != nil {
		return err
	}

	for i := range dao.Addresses {
		//fmt.Println("Address ",dao.Addresses[i])

		dai := &ec2.DisassociateAddressInput{ AssociationID: dao.Addresses[i].AssociationID }
		_,err := svc.DisassociateAddress(dai)
		//fmt.Println(daio)
		if err != nil {
			return err
		}

		rai := &ec2.ReleaseAddressInput{ AllocationID: dao.Addresses[i].AllocationID }
		_,err = svc.ReleaseAddress(rai)
		//fmt.Println(rao)
		if err != nil {
			return err
		}
	}

	return nil
}

func Destroy(config *Config) {
	//fmt.Println("Destroy not implemented")
	svc := ec2.New(nil)
	rdsc := rds.New(nil)

	for i := range config.EC2 {
		fmt.Println("Destroying EC2 instance: ", config.EC2[i].Name)
		//fmt.Println(config.EC2[i].InstanceType)


		instances := getInstancesByName(svc,config.EC2[i].Name)
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				//fmt.Println("Instance is terminated:", *instances[k].InstanceID)
			} else {
				fmt.Println("Instance will be terminated: ", *instances[k].InstanceID)
				if config.EC2[i].HasExternalIP {
					//fmt.Println("Has external IP")
					//waitForNonXState(svc, instances[k].InstanceID, "shutting-down")
					err := releaseExternalIP(svc, *instances[k].InstanceID)
					if err != nil {
						fmt.Println("Failed to release ip: ", err)
					}
				}

				instanceids := []*string{ instances[k].InstanceID }
				tii := ec2.TerminateInstancesInput { InstanceIDs: instanceids }
				_,err := svc.TerminateInstances(&tii)
				if err != nil {
					panic(err)
				}


				fmt.Println("Terminated instance ", *instances[k].InstanceID)

			}
		}
	}


	for i := range config.RDS {
		abool := true
		ddbi := &rds.DeleteDBInstanceInput{ DBInstanceIdentifier: &config.RDS[i].DBInstanceIdentifier, SkipFinalSnapshot: &abool }
		_,err := rdsc.DeleteDBInstance(ddbi)
		if err != nil {
			fmt.Println("Error deleting instance:", err)
		}
		//fmt.Println(ddbo)
		fmt.Println("Destroyed", config.RDS[i].Engine, "RDS instance: ", config.RDS[i].DBInstanceIdentifier)
	}
	/*
	for i := range config.RDS {
		ddbii := &rds.DescribeDBInstancesInput{ DBInstanceIdentifier: config.RDS[i].DBInstanceIdentifier }
		ddbo,err := rdsc.DescribeDBInstances(ddbii)
		if err != nil {
			panic(err)
		}


	}
	*/

	fmt.Println("Everything but the VPC destroyed.")

	/*
	dvi := &ec2.DescribeVPCsInput{}
	dvo,err := svc.DescribeVPCs(dvi)
	if err != nil {
		panic(err)
	}


	//vpcid := ""
	for i := range dvo.VPCs {
		if *dvo.VPCs[i].CIDRBlock == config.VPC {
			config.VPCID = *dvo.VPCs[i].VPCID
		}
	}





	fmt.Println("All instances destroyed, resting a bit and removing VPC...")
	time.Sleep(5*time.Second)
	devi := &ec2.DeleteVPCInput{ VPCID: &config.VPCID }
	_,err = svc.DeleteVPC(devi)

	if err != nil {
		fmt.Println("Error deleting vpc: ", err)
	}
	*/

}

func Start(config *Config) {
	svc := ec2.New(nil)

	for i := range config.EC2 {
		fmt.Println("Starting ", config.EC2[i].Name)
		//fmt.Println(config.EC2[i].InstanceType)


		instances := getInstancesByName(svc,config.EC2[i].Name)
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				//fmt.Println("Instance is terminated:", *instances[k].InstanceID)
			} else {
				fmt.Println("Instance will be started: ", *instances[k].InstanceID)
				instanceids := []*string{ instances[k].InstanceID }
				sii := ec2.StartInstancesInput { InstanceIDs: instanceids }
				_,err := svc.StartInstances(&sii)
				if err != nil {
					panic(err)
				}
				fmt.Println("Started instance ", *instances[k].InstanceID)

			}
		}
	}

}


func Stop(config *Config) {
	svc := ec2.New(nil)

	for i := range config.EC2 {
		fmt.Println("Stopping ", config.EC2[i].Name)
		//fmt.Println(config.EC2[i].InstanceType)


		instances := getInstancesByName(svc,config.EC2[i].Name)
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				//fmt.Println("Instance is terminated:", *instances[k].InstanceID)
			} else {
				fmt.Println("Instance will be shutdown: ", *instances[k].InstanceID)
				instanceids := []*string{ instances[k].InstanceID }
				sii := ec2.StopInstancesInput { InstanceIDs: instanceids }
				_,err := svc.StopInstances(&sii)
				if err != nil {
					panic(err)
				}
				fmt.Println("Stopped instance ", *instances[k].InstanceID)

			}
		}
	}

}



func copyContents(r io.Reader, w io.Writer) error {
	b := make([]byte, 4096)
	for {
		// read chunk into memory
		length, err := r.Read(b[:cap(b)])
		if err != nil {
			if err != io.EOF {
				return err
			}
			if length == 0 {
				break
			}
		}
		// write chunk to zip file
		_, err = w.Write(b[:length])
		if err != nil {
			return err
		}
	}
	return nil
}

func unwantedFileOrObject(info os.FileInfo) bool {
	//fmt.Println(info.Name())
	unwanted := []string{"src", "pkg", "saws", "saws.json", "package.zip"}
	for i := range unwanted {
		if info.Name() == unwanted[i] {
			fmt.Println("Do not want: ", info.Name())
			return true
		}
	}

	return false
}

func zipEverything() error {
	zipFile, err := os.Create("package.zip")
	if err != nil {
		return err
	}
	defer zipFile.Close()

	writer := zip.NewWriter(zipFile)

	zipItem := func(path string, info os.FileInfo, err error) error {
		//fmt.Println(path)
		if err != nil {
			return err
		}

		if unwantedFileOrObject(info) {
			return nil
		}

		if !info.Mode().IsRegular() || info.Size() == 0 {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return err
		}

		w, err := writer.Create(path)
		if err != nil {
			return err
		}

		err = copyContents(file, w)
		if err != nil {
			return err
		}

		return nil
	}

	err = filepath.Walk(".", zipItem)
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	return nil

}

func Pack() {
	zipEverything()
	fmt.Println("Package created: package.zip")
}

func makeBucket(client *s3.S3, bucket *string) error {
	cbi := &s3.CreateBucketInput{Bucket: bucket}
	_, err := client.CreateBucket(cbi)
	if err != nil {
		return err
	}

	return nil
}

func main() {

	var (
		configfile string
		action     string
	)
	flag.StringVar(&configfile, "c", "saws.json", "Config file to use")
	flag.StringVar(&action, "a", "pack", "Action, create/destroy/start/stop/pack/push/stat")
	flag.Parse()

	config := parseConfig(configfile)


	client := s3.New(nil)
	lb, err := client.ListBuckets(nil)
	if err != nil {
		panic(err)
	}

	// FIXME: no need to loop over buckets
	bucketExists := false
	for i := range lb.Buckets {

		if *lb.Buckets[i].Name == config.S3Bucket {
			bucketExists = true
			break
		}

	}

	if !bucketExists {
		err := makeBucket(client, &config.S3Bucket)
		if err != nil {
			panic(err)
		}
		fmt.Println("Created bucket ", config.S3Bucket)
	}

	switch {
	case action == "pack":
		Pack()
	case action == "create":
		Create(config)
	case action == "destroy":
		Destroy(config)
	case action == "push":
		Push(config)
	case action == "stop":
		Stop(config)
	case action == "start":
		Start(config)
	case action == "stat":
		Stat(config)
	default:
		fmt.Println("Unknown action given", action)
	}

}
