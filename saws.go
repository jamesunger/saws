package main

import (
	"archive/zip"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/service/s3"
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
)

type Config struct {
	S3Bucket string `json:s3bucket`
	EC2      []EC2  `json:ec2`
	InitialConfig     string  `json:initialconfig`
	VPC string `json:vpc`
	VPCID string `json:vpcid`
	SubnetID string `json:subnetid`
	AllSecurityGroups []SecurityGroup `json:allsecuritygroups`
}

type SecurityGroup struct {
	Name string `json:name`
	TcpPort int64 `json:tcpport`
}

type EC2 struct {
	Name         string `json:string`
	InstanceType string `json:instancetype`
	AMI string `json:ami`
	KeyName string `json:keyname`
	SubnetID string `json:subnetid`
	SecurityGroupIDs []*string `json:securitygroupids`
	SecurityGroups []string `json:securitygroups`
	HasExternalIP bool `json:hasexternalip`
}

func getUserData(initialconfig string, s3bucket string) string {
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
	ic1 := rxpid.ReplaceAll(ic, []byte(accid))
	ic2 := rxpkey.ReplaceAll(ic1, []byte(seck))
	ic3 := rxp3.ReplaceAll(ic2, []byte(s3bucket))


	return base64.StdEncoding.EncodeToString([]byte(ic3))
	
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

func Push(config *Config) {
	uploadPackage(config)
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


	fmt.Println(dio)
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
		fmt.Println(dio)
	}


	return errors.New("Waited too long for EC2 to leave pending state.")

}

func createInstance(svc *ec2.EC2, config *Config, ec2config EC2, userdata string) {
	var min int64
	var max int64
	min = 1
	max = 1

	subnet := config.SubnetID
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
	fmt.Println("Create instance params:", params)

	rres, err := svc.RunInstances(params)
	if err != nil {
		fmt.Println("Failed to create instance",err)
		fmt.Println(rres)
	} else {
		fmt.Println("Created instance")
		//fmt.Println(rres)

		fmt.Println("Sleeping for a sec to give AWS some time ...")
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
		} else {
			fmt.Println("Created tag Name with value", ec2config.Name)
		}


		fmt.Println("hasexternalip ", ec2config.HasExternalIP)
		if ec2config.HasExternalIP {
			vpcs := "vpc"
			aao,err := svc.AllocateAddress(&ec2.AllocateAddressInput{ Domain: &vpcs })
			if err != nil {
				fmt.Println("Could not allocate addr:", err)
 			}

			fmt.Println(aao)


			err = waitForNonPendingState(svc, rres.Instances[0].InstanceID)
			if err != nil {
				fmt.Println(err)
			} else {
				//aai,err := svc.AssociateAddress(&ec2.AssociateAddressInput{ PublicIP: aao.PublicIP, InstanceID: rres.Instances[0].InstanceID })
				aai,err := svc.AssociateAddress(&ec2.AssociateAddressInput{ AllocationID: aao.AllocationID, InstanceID: rres.Instances[0].InstanceID })
				if err != nil {
					fmt.Println("Could not assign addr:", err)
 				}

				fmt.Println(aai)
			}

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

func Stat(config *Config) {
	
	svc := ec2.New(nil)

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



}

func getRouteTableFromVPC(svc *ec2.EC2, VPCID *string) (*string, error) {
	drti := &ec2.DescribeRouteTablesInput{}
	drto,err := svc.DescribeRouteTables(drti)
	if err != nil {
		panic(err)
	}

	for i := range drto.RouteTables {
		if *drto.RouteTables[i].VPCID == *VPCID {
			fmt.Println("Route table is", *drto.RouteTables[i].RouteTableID)
			return drto.RouteTables[i].RouteTableID,nil
		}
	}

	return nil,errors.New(fmt.Sprintf("No route table found for vpc", *VPCID))

}

func createGateway(svc *ec2.EC2, vpc *ec2.VPC, subid *string) error {
	cigi := &ec2.CreateInternetGatewayInput{}
	cigo,err := svc.CreateInternetGateway(cigi)
	if err != nil {
		fmt.Println("Failed to create gateway.")
		return err
	}

	fmt.Println("We have vpcid: " + *vpc.VPCID)
	_,err = svc.AttachInternetGateway(&ec2.AttachInternetGatewayInput{InternetGatewayID: cigo.InternetGateway.InternetGatewayID, VPCID: vpc.VPCID})
	if err != nil {
		fmt.Println("Failed to attach gateway.")
		return err
	}
	
	defgtw := "0.0.0.0/0"
	rtid,err := getRouteTableFromVPC(svc, vpc.VPCID)
	if err != nil {
		fmt.Println("Failed to get route table from VPC id.")
		panic(err)
	}
	cri := &ec2.CreateRouteInput{ DestinationCIDRBlock: &defgtw, GatewayID: cigo.InternetGateway.InternetGatewayID, RouteTableID: rtid }
	cro,err := svc.CreateRoute(cri)
	fmt.Println(cro)
	if err != nil {
		fmt.Println("Failed to create default route.")
		return err
	}

	arti := &ec2.AssociateRouteTableInput{ RouteTableID: rtid, SubnetID: subid }
	arto, err := svc.AssociateRouteTable(arti)
	fmt.Println(arto)
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
			fmt.Println(err)
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
			if err != nil {
			}
				fmt.Println("Failed to add rule to security group.")
				return err
		}

	return nil

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

		fmt.Println("Filters ", filters)

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


	fmt.Println("Security Groups!", secgroupids)
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

		for i := range dso.Subnets {
			if *dso.Subnets[i].CIDRBlock == config.VPC {
				fmt.Println("Subnet for VPC already exists.")
				config.SubnetID = *dso.Subnets[i].SubnetID
				return nil
			}
		}

		csi := &ec2.CreateSubnetInput{ CIDRBlock: &config.VPC, VPCID: &config.VPCID}
		cso,err := c.CreateSubnet(csi)
		if err != nil {
			fmt.Println("Create subnet failed")
			return err
		}
		fmt.Println(cso)
		config.SubnetID = *cso.Subnet.SubnetID

		return createGateway(c, vpc, cso.Subnet.SubnetID)

	}

	cvi := &ec2.CreateVPCInput{ CIDRBlock: &config.VPC }
	cvo, err := c.CreateVPC(cvi)
	
	if err != nil {
		return err
	}	
	config.VPCID = *cvo.VPC.VPCID
	fmt.Println("newly created vpid " + config.VPCID)

	fmt.Println(cvo)
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


	csi := &ec2.CreateSubnetInput{ CIDRBlock: &config.VPC, VPCID: &config.VPCID }
	cso,err := c.CreateSubnet(csi)
	if err != nil {
		return err
	}
	fmt.Println(cso)
	config.SubnetID = *cso.Subnet.SubnetID

	return createGateway(c, cvo.VPC, cso.Subnet.SubnetID)

}

func Create(config *Config) {
	//fmt.Println("Create not implemented")

	svc := ec2.New(nil)

	err := verifyAndCreateVPC(svc,config)
	if err != nil {
		panic(err)
	}



	//fmt.Println("Creating with", config)
	for i := range config.EC2 {
		fmt.Println(config.EC2[i].Name)
		fmt.Println(config.EC2[i].InstanceType)

		instances := getInstancesByName(svc,config.EC2[i].Name)

		exists := false
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				fmt.Println("Instance is terminated:", *instances[k].InstanceID)
			} else {
				fmt.Println("Instance already exists: ", *instances[k].InstanceID)
				exists = true
			}
		}


		if !exists {
			fmt.Println("No instance found, creating...")
			userdata := getUserData(config.InitialConfig,config.S3Bucket)
			createInstance(svc, config, config.EC2[i], userdata)
			
		}

	}
}

func Destroy(config *Config) {
	//fmt.Println("Destroy not implemented")
	svc := ec2.New(nil)

	for i := range config.EC2 {
		fmt.Println(config.EC2[i].Name)
		fmt.Println(config.EC2[i].InstanceType)


		instances := getInstancesByName(svc,config.EC2[i].Name)
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				fmt.Println("Instance is terminated:", *instances[k].InstanceID)
			} else {
				fmt.Println("Instance will be terminated: ", *instances[k].InstanceID)
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
	flag.StringVar(&action, "a", "pack", "Action, create/destroy/pack/push/stat")
	flag.Parse()

	config := parseConfig(configfile)

	fmt.Println("S3Bucket ", config.S3Bucket)

	client := s3.New(nil)
	lb, err := client.ListBuckets(nil)
	if err != nil {
		panic(err)
	}
	//fmt.Println(lb.GoString())

	// FIXME: no need to loop over buckets
	bucketExists := false
	for i := range lb.Buckets {

		if *lb.Buckets[i].Name == config.S3Bucket {
			bucketExists = true
			break
		}

		//fmt.Printf("Bucket: %s\n",*lb.Buckets[i].Name)
		//lin := &s3.ListObjectsInput{ Bucket: lb.Buckets[i].Name }
		//lout,_ := client.ListObjects(lin)
		//fmt.Println(lout.GoString())
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
	case action == "stat":
		Stat(config)
	default:
		fmt.Println("Unknown action given", action)
	}

}
