package main

/*
*
* Copyright 2015 James Unger
*
* This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU General Public License for more details.
*
*    You should have received a copy of the GNU General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/s3"
        "github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
        "code.google.com/p/go-uuid/uuid"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"os/exec"
)

type Config struct {
	S3Bucket          string          `json:s3bucket`
	KeyPair           string          `json:keypair`
	EC2               []EC2           `json:ec2`
	InitialConfig     string          `json:initialconfig`
	VPC               string          `json:vpc`
	DestroyPolicy     string          `json:destroypolicy`
	PrivateNet        string          `json:privatenet`
	PublicNet         string          `json:publicnet`
	VpcId             string          `json:vpcid`
	PrivateSubnetId   string          `json:privatesubnetid`
	PublicSubnetId    string          `json:publicsubnetid`
	AllSecurityGroups []SecurityGroup `json:allsecuritygroups`
	AvailZone1        string          `json:availzone1`
	AvailZone2        string          `json:availzone2`
	PushCmd           string          `json:pushcmd`
	InfoCmd           string          `json:infocmd`
	RDS               []RDS           `json:rds`
	ELB               []ELB           `json:elb`
}

type RDS struct {
	AllocatedStorage      int64  `json:allocatedstorage`
	BackupRetentionPeriod int64  `json:backuprentationperiod`
	DBInstanceClass       string `json:dbinstanceclass`
	DBInstanceIdentifier  string `json:dbinstanceidentifier`
	DBName                string `json:dbname`
	DBSubnetGroupName     string `json:dbsubnetgroupname`
	Engine                string `json:engine`
	EngineVersion         string `json:engineversion`
	MasterUserPassword    string `json:masteruserpassword`
	MasterUsername        string `json:masterusername`
}

type SecurityGroup struct {
	Name    string `json:name`
	TcpPort int64  `json:tcpport`
}

type EC2 struct {
	Name             string    `json:string`
	InitialConfig    string    `json:initialconfig`
	InstanceType     string    `json:instancetype`
	AMI              string    `json:ami`
	KeyName          string    `json:keyname`
	SubnetId         string    `json:subnetid`
	InstanceId       string    `json:instanceid`
	SecurityGroupIds []*string `json:securitygroupids`
	SecurityGroups   []string  `json:securitygroups`
	HasExternalIP    bool      `json:hasexternalip`
	IsNat            bool      `json:isnat`
}

type ELB struct {
	Name             string   `json:name`
	InstancePort     int64    `json:instanceport`
	LoadBalancerPort int64    `json:instanceport`
	Instances        []string `json:instances`
	Protocol         string   `json:protocol`
	SecurityGroups   []string `json:securitygroups`
}

type SawsInfo struct {
	EC2 []*ec2.Instance   `json:ec2`
	RDS []*rds.DBInstance `json:rds`
}

func getUserData(initialconfig string, s3bucket string, hostname string, vpc string, uuids string) string {
	ic, err := ioutil.ReadFile(initialconfig)
	if err != nil {
		panic(err)
	}

	accid := os.Getenv("SAWS_S3_ACCESS_KEY")
	seck := os.Getenv("SAWS_S3_SECRET_KEY")

	if accid == "" {
		panic("Error: need to set env var SAWS_S3_ACCESS_KEY")
	}

	if seck == "" {
		panic("Error: need to set env var SAWS_S3_SECRET_KEY")
	}

	rxpid := regexp.MustCompile("SAWS_S3_ACCESS_KEY")
	rxpkey := regexp.MustCompile("SAWS_S3_SECRET_KEY")
	rxp3 := regexp.MustCompile("SAWS_S3BUCKET")
	rxphostname := regexp.MustCompile("SAWS_HOSTNAME")
	rxpvpc := regexp.MustCompile("SAWS_VPC")
	rxpuuid := regexp.MustCompile("SAWS_UUID")
	ic1 := rxpid.ReplaceAll(ic, []byte(accid))
	ic2 := rxpkey.ReplaceAll(ic1, []byte(seck))
	ic3 := rxp3.ReplaceAll(ic2, []byte(s3bucket))
	ic4 := rxphostname.ReplaceAll(ic3, []byte(hostname))
	ic5 := rxpvpc.ReplaceAll(ic4, []byte(vpc))
	ic6 := rxpuuid.ReplaceAll(ic5, []byte(uuids))

	return base64.StdEncoding.EncodeToString([]byte(ic6))
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

type rateLimitUploader struct {
	fh    *os.File
	slice []byte    // Buffer of unread data.
	tmp   [256]byte // Storage for slice.
	count int
}

func (f *rateLimitUploader) Read(p []byte) (int, error) {

	f.count++

	if len(p) == 0 {
		return 0, nil
	}
	if len(f.slice) == 0 {
		mbytes := make([]byte, 1024)
		blockLen, err := f.fh.Read(mbytes)
		if err != nil {
			return 0, err
		}
		if blockLen == 0 {
			return 0, io.EOF
		}
		f.slice = mbytes[0:blockLen]
		/*if _, err = io.ReadFull(f.fh, f.slice); err != nil {
			      fmt.Println("All done")
		              return 0, io.EOF
		          }*/
	}
	n := copy(p, f.slice)
	fmt.Println("Chunk...", f.count)
	time.Sleep(1 * time.Millisecond)
	f.slice = f.slice[n:]
	return n, nil
}

func uploadPackage(config *Config) error {
	key := "package.zip"
	uploadfile, err := os.Open(key)
	if err != nil {
		return err
	}

	//rlu := &rateLimitUploader{ fh: uploadfile }

	fmt.Println("Uploading package.zip to", config.S3Bucket, "bucket...")
	uploader := s3manager.NewUploader(session.New())
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: &config.S3Bucket,
		Key:    &key,
		//Body:   rlu,
		Body: uploadfile,
	})

	if err != nil {
		panic(err)
	}

	fmt.Println("Uploaded package.zip to", config.S3Bucket, "bucket.")

	return nil
}

func deleteSawsInfo(config *Config) error {
	key := "saws-info.json"
	doi := &s3.DeleteObjectInput{Bucket: &config.S3Bucket, Key: &key}

	svc := s3.New(session.New())
	_, err := svc.DeleteObject(doi)
	//fmt.Println(doo)
	if err != nil {
		fmt.Println("Failed to delete saws-info.json")
		return err
	}

	return nil

}

func getCmd(cmdline string, uuids string) (string,[]string) {
	parts := strings.Split(cmdline, " ")
	name := ""
	args := []string{}

	for i := range parts {
		if i == 0 {
			name = parts[0]
			args = append(args,parts[i])
		} else if strings.Contains(parts[i],"SAWS_UUID") {
			narg := strings.Replace(parts[i],"SAWS_UUID",uuids,1)
			args = append(args,narg)
		} else {
			args = append(args,parts[i])
		}
	}

	//fmt.Println("name",name,"args",args)
	return name, args
}

func sendSawsInfo(config *Config, uuids string) error {
	jsonBytes := getJsonSawsInfo(config)
	jsonBytesReader := bytes.NewReader(jsonBytes)

	if config.InfoCmd != "" {
		name,cmdargs := getCmd(config.InfoCmd, uuids)
		cmd := exec.Cmd{Path: name, Args: cmdargs}
		writcl,err := cmd.StdinPipe()
		if err != nil {
			fmt.Println("Error running external infocmd: ", config.InfoCmd);
			panic(err)
		}
		cmd.Start()


		bytesn,err := io.Copy(writcl,jsonBytesReader)
		if err != nil {
			fmt.Println("Failed to read from jsonBytesReader and copy to writcl:",err);
		} else {
			fmt.Println(bytesn,"piped to", cmdargs)
		}
		err = writcl.Close()
		if err != nil {
			fmt.Println("Error failed to close write stream to stdin:",err)
		}

		err = cmd.Wait()
		if err != nil {
			fmt.Println("Subprocess returned error on wait:", err)
		}

	} else {

		key := "saws-info.json"
		uploader := s3manager.NewUploader(session.New())
		_, err := uploader.Upload(&s3manager.UploadInput{
			Bucket: &config.S3Bucket,
			Key:    &key,
			Body:   jsonBytesReader,
		})

		if err != nil {
			fmt.Println("Failed to upload saws-info.json.")
			return err
		}
	}

	return nil
}

func Push(config *Config) {
	if config.PushCmd != "" {
		name,cmdargs := getCmd(config.PushCmd,"")
		cmd := exec.Cmd{Path: name, Args: cmdargs}
		err := cmd.Run()
		if err != nil {
			fmt.Println("Error running external pushcmd:", config.PushCmd);
			panic(err)
		}
	} else {
		uploadPackage(config)
	}
}

func waitForNoUsedIPS(svc *ec2.EC2, vpcid string) error {
	filters := make([]*ec2.Filter, 0)
	keyname := "vpc-id"
	filter := ec2.Filter{
		Name: &keyname, Values: []*string{&vpcid}}
	filters = append(filters, &filter)
	dnii := &ec2.DescribeNetworkInterfacesInput{Filters: filters}
	dnio, err := svc.DescribeNetworkInterfaces(dnii)
	if err != nil {
		fmt.Println("Failed to describe network interfaces:", err)
		return err
	}

	//for i := range dnio.NetworkInterfaces {
	//	fmt.Println(dnio.NetworkInterfaces[i])
	//}

	count := 0
	for {
		dnio, err = svc.DescribeNetworkInterfaces(dnii)
		if len(dnio.NetworkInterfaces) == 0 {
			return nil
		}

		//for i := range dnio.NetworkInterfaces {
		//	fmt.Println(dnio.NetworkInterfaces[i])
		//}

		if count > 60 {
			break
		}

		time.Sleep(2 * time.Second)
		count++

	}

	return errors.New("Waited too long for IPs to disappear...")

}

func waitForDetachedNetwork(svc *ec2.EC2, instanceid *string) error {
	iids := []*string{instanceid}
	dii := &ec2.DescribeInstancesInput{
		InstanceIds: iids,
	}

	dio, err := svc.DescribeInstances(dii)
	if err != nil {
		panic(err)
	}

	//fmt.Println(dio)
	count := 0
	for {
		dio, err = svc.DescribeInstances(dii)
		if err != nil {
			panic(err)
		}

		if len(dio.Reservations[0].Instances[0].NetworkInterfaces) == 0 {
			return nil
		}

		if count > 60 {
			break
		}

		time.Sleep(2 * time.Second)
		count++
	}

	return errors.New(fmt.Sprintf("Waited too long for EC2 to remove networking."))

}

func waitForXState(svc *ec2.EC2, instanceid *string, state string) error {
	iids := []*string{instanceid}
	dii := &ec2.DescribeInstancesInput{
		InstanceIds: iids,
	}

	dio, err := svc.DescribeInstances(dii)
	if err != nil {
		panic(err)
	}

	//fmt.Println("waiting for instance to leave state", state)
	//fmt.Println(dio)
	count := 0
	for {
		dio, err = svc.DescribeInstances(dii)
		if err != nil {
			panic(err)
		}
		//fmt.Println(dio)

		if *dio.Reservations[0].Instances[0].State.Name == state {
			return nil
		}

		if count > 30 {
			break
		}

		time.Sleep(2 * time.Second)
		count++
		//fmt.Println(dio)
		//fmt.Println("waiting for instance to leave state ", state)
	}

	return errors.New(fmt.Sprintf("Waited too long waiting for EC2 to enter %s state", state))

}

func waitForNonXState(svc *ec2.EC2, instanceid *string, state string) error {
	iids := []*string{instanceid}
	dii := &ec2.DescribeInstancesInput{
		InstanceIds: iids,
	}

	dio, err := svc.DescribeInstances(dii)
	if err != nil {
		panic(err)
	}

	//fmt.Println("waiting for instance to leave state", state)
	//fmt.Println(dio)
	count := 0
	for {
		dio, err = svc.DescribeInstances(dii)
		if err != nil {
			panic(err)
		}

		if *dio.Reservations[0].Instances[0].State.Name != state {
			return nil
		}

		if count > 30 {
			break
		}

		time.Sleep(2 * time.Second)
		count++
		//fmt.Println(dio)
		//fmt.Println("waiting for instance to leave state ", state)
	}

	return errors.New(fmt.Sprintf("Waited too long for EC2 to leave %s state", state))

}

func waitForRDSEndpoint(rds *rds.RDS, dbid *string) (*rds.DBInstance, error) {
	count := 0
	rdsinst, err := getRDSInstanceById(rds, dbid)
	if err != nil {
		return nil, err
	}

	for {
		if count > 300 {
			break
		}
		//fmt.Println(rdsinst)
		rdsinst, err = getRDSInstanceById(rds, dbid)

		if err != nil {
			return nil, err
		}

		if rdsinst.Endpoint != nil {
			return rdsinst, nil
		} else {
			//fmt.Println(count)
			count++
		}
		time.Sleep(5 * time.Second)

	}

	return nil, errors.New("Waited too long for RDS endpoint to come online.")
}

func waitForDeleteRDS(rds *rds.RDS, dbid *string) error {
	count := 0
	_, err := getRDSInstanceById(rds, dbid)
	if err != nil {
		return nil
	}

	for {
		if count > 300 {
			break
		}
		//fmt.Println(rdsinst)
		_, err = getRDSInstanceById(rds, dbid)

		if err != nil {
			return nil
		} else {
			count++
		}
		time.Sleep(5 * time.Second)

	}

	return errors.New("Waited too long for RDS endpoint to delete.")
}

func waitForNonPendingState(svc *ec2.EC2, instanceid *string) error {
	iids := []*string{instanceid}
	dii := &ec2.DescribeInstancesInput{
		InstanceIds: iids,
	}

	dio, err := svc.DescribeInstances(dii)
	if err != nil {
		panic(err)
	}

	//fmt.Println("waiting for non pending state...")
	//fmt.Println(dio)
	count := 0
	for {
		dio, err = svc.DescribeInstances(dii)
		if err != nil {
			panic(err)
		}

		if *dio.Reservations[0].Instances[0].State.Name != "pending" {
			return nil
		}

		if count > 20 {
			break
		}

		time.Sleep(2 * time.Second)
		count++
		//fmt.Println(dio)
		//fmt.Println("waiting for non pending state...")
	}

	return errors.New("Waited too long for EC2 to leave pending state.")

}

func isEc2PartofLb(config *Config, ec2 EC2) bool {
	for i := range config.ELB {
		for k := range config.ELB[i].Instances {
			if config.ELB[i].Instances[k] == ec2.Name {
				return true
			}
		}
	}
	return false
}

func createInstance(svc *ec2.EC2, config *Config, ec2config EC2, userdata string, doneChan chan string) int {
	var min int64
	var max int64
	min = 1
	max = 1

	remainingSteps := 0

	var subnet string
	if ec2config.HasExternalIP {
		subnet = config.PublicSubnetId
	} else {
		subnet = config.PrivateSubnetId
	}

	//fmt.Println("Public: ", config.PublicSubnetId)
	//fmt.Println("Private: ", config.PrivateSubnetId)
	//fmt.Println("Using: ", subnet)
	//if isEc2PartofLb(config, ec2config) {
	//	subnet = config.PrivateSubnetId
	//}

	ec2config.SecurityGroupIds = getSecurityGroupIds(svc, config, ec2config.SecurityGroups)
	keyname := ec2config.KeyName
	if keyname == "" {
		keyname = config.KeyPair
	}
	params := &ec2.RunInstancesInput{
		ImageId:          &ec2config.AMI,
		InstanceType:     &ec2config.InstanceType,
		MaxCount:         &max,
		MinCount:         &min,
		KeyName:          &keyname,
		UserData:         &userdata,
		SubnetId:         &subnet,
		SecurityGroupIds: ec2config.SecurityGroupIds,
	}
	//fmt.Println("Create instance params:", params)

	rres, err := svc.RunInstances(params)
	if err != nil {
		fmt.Println("Failed to create instance", err)
		fmt.Println(rres)
	} else {
		fmt.Printf("Created instance %s: %s\n", ec2config.Name, *rres.Instances[0].InstanceId)
		ec2config.InstanceId = *rres.Instances[0].InstanceId
		//fmt.Println(rres)

		//fmt.Println("Sleeping for a sec to give AWS some time ...")

		time.Sleep(1 * time.Second)

		keyname := "Name"
		_, err := svc.CreateTags(&ec2.CreateTagsInput{
			Resources: []*string{rres.Instances[0].InstanceId},
			Tags: []*ec2.Tag{
				&ec2.Tag{
					Key:   &keyname,
					Value: &ec2config.Name,
				},
			},
		})
		//fmt.Println(tres)

		if err != nil {
			fmt.Println("Could not create tags for instance ", rres.Instances[0].InstanceId)
			fmt.Println(err)
		} //else {
		//fmt.Println("Created tag Name with value", ec2config.Name)
		//fmt.Println("isnat", ec2config.IsNat)
		if ec2config.IsNat {
			remainingSteps++

			go func() {

				err = waitForNonPendingState(svc, rres.Instances[0].InstanceId)
				if err != nil {
					fmt.Println(err)
					doneChan <- "Gave up waiting on ec2 to leave pending state."
					return
				}

				bv := false
				abv := &ec2.AttributeBooleanValue{Value: &bv}
				miai := &ec2.ModifyInstanceAttributeInput{InstanceId: rres.Instances[0].InstanceId, SourceDestCheck: abv}
				_, err := svc.ModifyInstanceAttribute(miai)
				if err != nil {
					fmt.Println("Failed to change sourcedestcheck", err)
				}

				routeid, err := getPrivateRouteTable(svc, &config.PrivateSubnetId, config.VpcId)
				if err != nil {
					routeid, err = createPrivateRouteTable(svc, config)
				} else {
					_ = deleteDefaultRoute(svc, routeid)
					/*if err != nil {
						fmt.Println("Error deleting default route or default route existed", err)
					}*/
				}

				defr := "0.0.0.0/0"
				cri := &ec2.CreateRouteInput{DestinationCidrBlock: &defr, InstanceId: rres.Instances[0].InstanceId, RouteTableId: routeid}
				_, err = svc.CreateRoute(cri)
				if err != nil {
					fmt.Println("Error adding new default route to NAT node", err)
				}
				doneChan <- fmt.Sprintf("Configured for NAT: %s", ec2config.Name)
			}()

		}
		//}

		//fmt.Println("hasexternalip ", ec2config.HasExternalIP)
		if ec2config.HasExternalIP {
			remainingSteps++

			go func() {
				vpcs := "vpc"
				aao, err := svc.AllocateAddress(&ec2.AllocateAddressInput{Domain: &vpcs})
				if err != nil {
					fmt.Println("Could not allocate addr:", err)
				}

				err = waitForNonPendingState(svc, rres.Instances[0].InstanceId)
				if err != nil {
					fmt.Println(err)
				} else {
					//aai,err := svc.AssociateAddress(&ec2.AssociateAddressInput{ PublicIp: aao.PublicIp, InstanceId: rres.Instances[0].InstanceId })
					_, err := svc.AssociateAddress(&ec2.AssociateAddressInput{AllocationId: aao.AllocationId, InstanceId: rres.Instances[0].InstanceId})
					if err != nil {
						fmt.Println("Could not assign addr:", err)
					}
				}

				//fmt.Println("External IP: ", *aao.PublicIp)
				doneChan <- fmt.Sprintf("External IP for %s assigned: %s", ec2config.Name, *aao.PublicIp)
			}()

		}

	}

	return remainingSteps

}

func getNonTerminatedInstance(instances []*ec2.Instance) *ec2.Instance {
	for i := range instances {
		fmt.Println(instances[i])
		if instances[i].InstanceId != nil && *instances[i].State.Name != "terminated" {
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
		Name: &keyname, Values: []*string{&keyvalue}}
	filters := []*ec2.Filter{
		&filter,
	}

	dii := &ec2.DescribeInstancesInput{
		Filters: filters,
	}

	dio, err := svc.DescribeInstances(dii)
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

	instances := make([]*ec2.Instance, 0)
	//instances := []*ec2.Instance
	for i := range dio.Reservations {
		for k := range dio.Reservations[i].Instances {
			instances = append(instances, dio.Reservations[i].Instances[k])
		}
	}

	//fmt.Println(instances)
	return instances

}

func getRDSInstanceById(rdsc *rds.RDS, rdsid *string) (*rds.DBInstance, error) {
	ddbii := &rds.DescribeDBInstancesInput{DBInstanceIdentifier: rdsid}
	ddbo, err := rdsc.DescribeDBInstances(ddbii)
	if err != nil {
		return nil, err
	}

	return ddbo.DBInstances[0], nil

}

func getJsonSawsInfo(config *Config) []byte {
	svc := ec2.New(session.New())
	rdsc := rds.New(session.New())
	instancelist := make([]*ec2.Instance, 0)
	for i := range config.EC2 {
		//fmt.Println(config.EC2[i].Name)
		instances := getInstancesByName(svc, config.EC2[i].Name)
		for k := range instances {
			instancelist = append(instancelist, instances[k])
		}
	}

	rdslist := make([]*rds.DBInstance, 0)
	for i := range config.RDS {
		//fmt.Println(config.RDS[i].DBInstanceIdentifier)
		dbinstance, err := getRDSInstanceById(rdsc, &config.RDS[i].DBInstanceIdentifier)
		if err != nil {
			//fmt.Println("Failed to find db instance", config.RDS[i].DBInstanceIdentifier)
		} else {
			rdslist = append(rdslist, dbinstance)
		}
	}

	sawsinfo := SawsInfo{}
	sawsinfo.EC2 = instancelist
	sawsinfo.RDS = rdslist

	marsh, err := json.Marshal(&sawsinfo)
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
				fmt.Println(*instances[k].InstanceId)
				fmt.Println(instances[k])


				userd := "userData"
				diai := &ec2.DescribeInstanceAttributeInput{
						Attribute: &userd,
						InstanceId: instances[k].InstanceId,
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

func getMainRouteTableFromVPC(svc *ec2.EC2, VpcId *string) (*string, error) {

	keyname := "association.main"
	asbool := "true"
	filters := make([]*ec2.Filter, 0)
	filter := ec2.Filter{
		Name: &keyname, Values: []*string{&asbool}}
	filters = append(filters, &filter)

	//fmt.Println("Filters ", filters)

	drti := &ec2.DescribeRouteTablesInput{Filters: filters}
	drto, err := svc.DescribeRouteTables(drti)
	if err != nil {
		panic(err)
	}

	for i := range drto.RouteTables {
		if *drto.RouteTables[i].VpcId == *VpcId {
			//fmt.Println("Route table is", *drto.RouteTables[i].RouteTableId)
			return drto.RouteTables[i].RouteTableId, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("No main route table found for vpc", *VpcId))

}

func getPrivateRouteTable(svc *ec2.EC2, subnetid *string, VpcId string) (*string, error) {
	keyname := "association.subnet-id"
	filters := make([]*ec2.Filter, 0)
	filter := ec2.Filter{
		Name: &keyname, Values: []*string{subnetid}}
	filters = append(filters, &filter)

	//fmt.Println("Filters ", filters)

	drti := &ec2.DescribeRouteTablesInput{Filters: filters}
	drto, err := svc.DescribeRouteTables(drti)
	if err != nil {
		panic(err)
	}

	for i := range drto.RouteTables {
		if *drto.RouteTables[i].VpcId == VpcId {
			//fmt.Println("Route table is", *drto.RouteTables[i].RouteTableId)
			return drto.RouteTables[i].RouteTableId, nil
		}
	}

	return nil, errors.New(fmt.Sprintf("No route table found for subnet", *subnetid))

}

func deleteDefaultRoute(svc *ec2.EC2, rtid *string) error {
	defr := "0.0.0.0/0"
	dri := &ec2.DeleteRouteInput{DestinationCidrBlock: &defr, RouteTableId: rtid}
	_, err := svc.DeleteRoute(dri)
	if err != nil {
		return err
	}

	return nil
}

func createGateway(svc *ec2.EC2, vpc *ec2.Vpc, subid *string) error {
	cigi := &ec2.CreateInternetGatewayInput{}
	cigo, err := svc.CreateInternetGateway(cigi)
	if err != nil {
		fmt.Println("Failed to create gateway.")
		return err
	}

	//fmt.Println("We have vpcid: " + *vpc.VpcId)
	_, err = svc.AttachInternetGateway(&ec2.AttachInternetGatewayInput{InternetGatewayId: cigo.InternetGateway.InternetGatewayId, VpcId: vpc.VpcId})
	if err != nil {
		fmt.Println("Failed to attach gateway.")
		return err
	}

	defr := "0.0.0.0/0"
	rtid, err := getMainRouteTableFromVPC(svc, vpc.VpcId)
	if err != nil {
		fmt.Println("Failed to get route table from VPC id.")
		panic(err)
	}
	cri := &ec2.CreateRouteInput{DestinationCidrBlock: &defr, GatewayId: cigo.InternetGateway.InternetGatewayId, RouteTableId: rtid}
	_, err = svc.CreateRoute(cri)
	//fmt.Println(cro)
	if err != nil {
		fmt.Println("Failed to create default route.")
		return err
	}

	arti := &ec2.AssociateRouteTableInput{RouteTableId: rtid, SubnetId: subid}
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
		csgi := &ec2.CreateSecurityGroupInput{GroupName: &config.AllSecurityGroups[j].Name, VpcId: &config.VpcId, Description: &config.AllSecurityGroups[j].Name}
		csgo, err := c.CreateSecurityGroup(csgi)
		//fmt.Println(err)
		if err != nil {
			if !strings.Contains(fmt.Sprintf("%s", err), "InvalidGroup.Duplicate") {
				fmt.Println("Failed to create security group.")
				return err
			}
			continue
		}

		everywhere := "0.0.0.0/0"
		proto := "tcp"
		//var fromPort int64
		//fromPort = -1
		asgii := &ec2.AuthorizeSecurityGroupIngressInput{CidrIp: &everywhere, FromPort: &config.AllSecurityGroups[j].TcpPort, ToPort: &config.AllSecurityGroups[j].TcpPort, GroupId: csgo.GroupId, IpProtocol: &proto}
		_, err = c.AuthorizeSecurityGroupIngress(asgii)
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
		csi = &ec2.CreateSubnetInput{CidrBlock: &config.PublicNet, VpcId: &config.VpcId, AvailabilityZone: &config.AvailZone1}
	} else {
		csi = &ec2.CreateSubnetInput{CidrBlock: &config.PublicNet, VpcId: &config.VpcId}
	}
	//csi := &ec2.CreateSubnetInput{ CidrBlock: &config.PublicNet, VpcId: &config.VpcId }
	cso1, err := svc.CreateSubnet(csi)
	if err != nil {
		fmt.Println("Create public subnet failed")
		return nil, nil, err
	}
	//fmt.Println(cso1)
	config.PublicSubnetId = *cso1.Subnet.SubnetId

	if config.AvailZone2 != "" {
		csi = &ec2.CreateSubnetInput{CidrBlock: &config.PrivateNet, VpcId: &config.VpcId, AvailabilityZone: &config.AvailZone2}
	} else {
		csi = &ec2.CreateSubnetInput{CidrBlock: &config.PrivateNet, VpcId: &config.VpcId}
	}
	//csi := &ec2.CreateSubnetInput{ CidrBlock: &config.PublicNet, VpcId: &config.VpcId }
	//csi = &ec2.CreateSubnetInput{ CidrBlock: &config.PrivateNet, VpcId: &config.VpcId}
	cso2, err := svc.CreateSubnet(csi)
	if err != nil {
		fmt.Println("Create private subnet failed")
		return nil, nil, err
	}
	//fmt.Println(cso2)
	config.PrivateSubnetId = *cso2.Subnet.SubnetId

	return cso1, cso2, nil

}

func createPrivateRouteTable(svc *ec2.EC2, config *Config) (*string, error) {
	crt := &ec2.CreateRouteTableInput{VpcId: &config.VpcId}
	crto, err := svc.CreateRouteTable(crt)
	if err != nil {
		fmt.Println("Failed to create private route table.")
		return nil, err
	}

	arti := &ec2.AssociateRouteTableInput{RouteTableId: crto.RouteTable.RouteTableId, SubnetId: &config.PrivateSubnetId}
	_, err = svc.AssociateRouteTable(arti)
	//fmt.Println(arto)
	if err != nil {
		fmt.Println("Failed to associate private subnet with route table.")
		return nil, err
	}

	return crto.RouteTable.RouteTableId, nil

}

func getGatewayIds(c *ec2.EC2, vpcid string) ([]string, error) {
	gatewayids := []string{}

	filters := make([]*ec2.Filter, 0)
	keyname := "attachment.vpc-id"
	filter := ec2.Filter{
		Name: &keyname, Values: []*string{&vpcid}}
	filters = append(filters, &filter)

	digi := &ec2.DescribeInternetGatewaysInput{Filters: filters}
	digo, err := c.DescribeInternetGateways(digi)
	if err != nil {
		return gatewayids, err
	}

	for i := range digo.InternetGateways {
		gatewayids = append(gatewayids, *digo.InternetGateways[i].InternetGatewayId)
	}
	return gatewayids, nil
}

func getSecurityGroupIdsByVPC(c *ec2.EC2, vpcid string) []*string {
	secgroupids := make([]*string, 0)
	filters := make([]*ec2.Filter, 0)
	keyname := "vpc-id"
	filter := ec2.Filter{
		Name: &keyname, Values: []*string{&vpcid}}
	filters = append(filters, &filter)

	dsgi := &ec2.DescribeSecurityGroupsInput{Filters: filters}
	dsgo, err := c.DescribeSecurityGroups(dsgi)
	if err != nil {
		fmt.Println("Describe security groups failed.")
		panic(err)
	}

	for i := range dsgo.SecurityGroups {
		if *dsgo.SecurityGroups[i].GroupName == "default" {
			continue
		} else {
			secgroupids = append(secgroupids, dsgo.SecurityGroups[i].GroupId)
		}
	}

	return secgroupids

}

func getSecurityGroupIds(c *ec2.EC2, config *Config, secgroups []string) []*string {

	//secgroups := make([]*string,0)
	secgroupids := make([]*string, 0)
	for i := range secgroups {
		filters := make([]*ec2.Filter, 0)

		keyname := "group-name"
		keyname2 := "vpc-id"
		filter := ec2.Filter{
			Name: &keyname, Values: []*string{&secgroups[i]}}
		filter2 := ec2.Filter{
			Name: &keyname2, Values: []*string{&config.VpcId}}
		filters = append(filters, &filter)
		filters = append(filters, &filter2)

		//fmt.Println("Filters ", filters)

		dsgi := &ec2.DescribeSecurityGroupsInput{Filters: filters}
		dsgo, err := c.DescribeSecurityGroups(dsgi)
		if err != nil {
			fmt.Println("Describe security groups failed.")
			panic(err)
		}

		for i := range dsgo.SecurityGroups {
			secgroupids = append(secgroupids, dsgo.SecurityGroups[i].GroupId)
		}

	}

	//fmt.Println("Security Groups!", secgroupids)
	return secgroupids

}

func verifyAndCreateVPC(c *ec2.EC2, config *Config) error {

	dvi := &ec2.DescribeVpcsInput{}
	dvo, err := c.DescribeVpcs(dvi)
	if err != nil {
		return err
	}

	vpc := &ec2.Vpc{}
	vpcexists := false
	for i := range dvo.Vpcs {
		if *dvo.Vpcs[i].CidrBlock == config.VPC {
			vpc = dvo.Vpcs[i]
			vpcexists = true
			config.VpcId = *dvo.Vpcs[i].VpcId
			//fmt.Println("VPC already exists.")
		}
	}

	if vpcexists {

		err = createSecurityGroups(c, config)
		if err != nil {
			fmt.Println("Failed to create security groups.")
			panic(err)
		}

		/*
			sgids := getSecurityGroupIds(c,config,
			err = applySecurityGroups(c, config)
			if err != nil {
				fmt.Println("Failed to apply security groups.")
				panic(err)
			}
		*/

		dsi := &ec2.DescribeSubnetsInput{}
		dso, err := c.DescribeSubnets(dsi)
		if err != nil {
			panic(err)
		}

		haspriv := false
		haspub := false
		for i := range dso.Subnets {
			if *dso.Subnets[i].CidrBlock == config.PublicNet {
				//fmt.Println("Subnet for public VPC already exists.")
				config.PublicSubnetId = *dso.Subnets[i].SubnetId
				haspub = true
				continue
			}

			if *dso.Subnets[i].CidrBlock == config.PrivateNet {
				//fmt.Println("Subnet for private VPC already exists.")
				config.PrivateSubnetId = *dso.Subnets[i].SubnetId
				haspriv = true
				continue
			}
		}

		if haspub && haspriv {
			return nil
		}

		cso1, cso2, err := createSubnets(c, config)
		if err != nil {
			panic(err)
		}
		config.PublicSubnetId = *cso1.Subnet.SubnetId
		config.PrivateSubnetId = *cso2.Subnet.SubnetId

		_, err = createPrivateRouteTable(c, config)
		if err != nil {
			panic(err)
		}

		return createGateway(c, vpc, cso1.Subnet.SubnetId)

	}

	cvi := &ec2.CreateVpcInput{CidrBlock: &config.VPC}
	cvo, err := c.CreateVpc(cvi)

	if err != nil {
		return err
	}
	config.VpcId = *cvo.Vpc.VpcId
	fmt.Println("Created new VPC: " + config.VpcId)

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

	cso1, cso2, err := createSubnets(c, config)
	config.PublicSubnetId = *cso1.Subnet.SubnetId
	config.PrivateSubnetId = *cso2.Subnet.SubnetId

	_, err = createPrivateRouteTable(c, config)
	if err != nil {
		panic(err)
	}

	return createGateway(c, cvo.Vpc, cso1.Subnet.SubnetId)

}

func Create(config *Config) {
	//fmt.Println("Create not implemented")

	uuids := uuid.New()
	svc := ec2.New(session.New())
	rdsc := rds.New(session.New())
	elbc := elb.New(session.New())

	if config.KeyPair != "" {

		dkpi := &ec2.DescribeKeyPairsInput{KeyNames: []*string{&config.KeyPair}}
		dkpo, err := svc.DescribeKeyPairs(dkpi)
		if err != nil {
			// almost certainly due to keypair already existing
			//fmt.Println("Failed to describe key pairs:", err)
		}

		if len(dkpo.KeyPairs) == 0 {
			ckpi := &ec2.CreateKeyPairInput{KeyName: &config.KeyPair}
			ckpo, err := svc.CreateKeyPair(ckpi)
			if err != nil {
				fmt.Println("Failed to create keypair:")
				panic(err)
			}

			fmt.Println("Created keypair:", config.KeyPair)
			err = ioutil.WriteFile(config.KeyPair+".key", []byte(*ckpo.KeyMaterial), 0600)
			if err != nil {
				fmt.Println("Failed to write to", config.KeyPair+".key:", err)
				fmt.Println(*ckpo.KeyMaterial)
			} else {
				fmt.Println("Key saved to file:", config.KeyPair+".key")
			}

		}

	}

	err := verifyAndCreateVPC(svc, config)
	if err != nil {
		panic(err)
	}

	err = deleteSawsInfo(config)
	if err != nil {
		panic(err)
	}

	doneChan := make(chan string)
	numStepsDeferred := 0

	// Creat RDS
	for i := range config.RDS {
		// setup RDS instances

		_, err = getRDSInstanceById(rdsc, &config.RDS[i].DBInstanceIdentifier)
		if err == nil {
			fmt.Println("RDS instance", config.RDS[i].DBInstanceIdentifier, "exists.")
			continue
		}

		groupname := "sawsdbprivate"
		cdbsgi := &rds.CreateDBSubnetGroupInput{DBSubnetGroupName: &groupname, SubnetIds: []*string{&config.PrivateSubnetId, &config.PublicSubnetId}, DBSubnetGroupDescription: &groupname}
		_, err := rdsc.CreateDBSubnetGroup(cdbsgi)
		if err != nil {

			//fmt.Println("Failed to create db subnetgroup:", err)
			//FIXME: search for subnet gorup if already created
			//panic(err)
		}

		//fmt.Println("Creating with:", config.RDS[i])
		//fmt.Println("DBSubnetGroupName: ", cdsgo.DBSubnetGroup.DBSubnetGroupName)
		//fmt.Println("Engine: ", config.RDS[i].Engine)
		//fmt.Println("DBName: ", config.RDS[i].DBName)
		//fmt.Println("DBInstanceIdentifier: ", config.RDS[i].DBInstanceIdentifier)
		//fmt.Println("AllocatedStorage: ", config.RDS[i].AllocatedStorage)
		//fmt.Println("DBInstanceClass: ", config.RDS[i].DBInstanceClass)
		//fmt.Println("MasterUsername: ", config.RDS[i].MasterUsername)
		//fmt.Println("MasterUserPassword: ", config.RDS[i].MasterUserPassword)

		cdbi := &rds.CreateDBInstanceInput{
			DBSubnetGroupName:    &groupname,
			Engine:               &config.RDS[i].Engine,
			DBName:               &config.RDS[i].DBName,
			DBInstanceIdentifier: &config.RDS[i].DBInstanceIdentifier,
			AllocatedStorage:     &config.RDS[i].AllocatedStorage,
			DBInstanceClass:      &config.RDS[i].DBInstanceClass,
			MasterUsername:       &config.RDS[i].MasterUsername,
			MasterUserPassword:   &config.RDS[i].MasterUserPassword,
		}
		_, err = rdsc.CreateDBInstance(cdbi)
		if err != nil {
			fmt.Println("Error creating db instance.")
			panic(err)
		}
		//fmt.Println(cdbo)
		fmt.Println("Created", config.RDS[i].Engine, "RDS instance: ", config.RDS[i].DBInstanceIdentifier)

		numStepsDeferred++
		go func() {
			rdsinst, err := waitForRDSEndpoint(rdsc, &config.RDS[i].DBInstanceIdentifier)
			if err != nil {
				fmt.Println(err)
				doneChan <- fmt.Sprint(err)
			} else {
				doneChan <- fmt.Sprintf("Endpoint for RDS instance %s: %s", config.RDS[i].DBInstanceIdentifier, *rdsinst.Endpoint.Address)
			}
		}()

	}

	// Creat EC2
	for i := range config.EC2 {
		//fmt.Println("Creating EC2 instance:", config.EC2[i].Name)
		//fmt.Println(config.EC2[i].InstanceType)

		instances := getInstancesByName(svc, config.EC2[i].Name)

		exists := false
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				//fmt.Println("Instance is terminated:", *instances[k].InstanceId)
			} else {
				fmt.Println("Instance", config.EC2[i].Name, "already exists:", *instances[k].InstanceId)
				exists = true
			}
		}

		if !exists {
			//fmt.Println("No instance found, creating...")
			var userdata string
			if config.EC2[i].InitialConfig == "" {
				userdata = getUserData(config.InitialConfig, config.S3Bucket, config.EC2[i].Name, config.VPC, uuids)
			} else {
				userdata = getUserData(config.EC2[i].InitialConfig, config.S3Bucket, config.EC2[i].Name, config.VPC, uuids)
			}
			numsteps := createInstance(svc, config, config.EC2[i], userdata, doneChan)
			numStepsDeferred += numsteps
		}

	}

	// Create ELB
	for i := range config.ELB {
		//fmt.Println("elbport ", config.ELB[i].InstancePort)
		//fmt.Println("instanceport ", config.ELB[i].InstancePort)
		secgroupids := getSecurityGroupIds(svc, config, config.ELB[i].SecurityGroups)
		listn := &elb.Listener{InstancePort: &config.ELB[i].InstancePort, InstanceProtocol: &config.ELB[i].Protocol, Protocol: &config.ELB[i].Protocol, LoadBalancerPort: &config.ELB[i].InstancePort}
		//clbi := &elb.CreateLoadBalancerInput{Listeners: []*elb.Listener{ listn }, LoadBalancerName: &config.ELB[i].Name, Subnets: []*string{ &config.PublicSubnetId, &config.PrivateSubnetId }, SecurityGroups: secgroupids }
		clbi := &elb.CreateLoadBalancerInput{Listeners: []*elb.Listener{listn}, LoadBalancerName: &config.ELB[i].Name, Subnets: []*string{&config.PublicSubnetId}, SecurityGroups: secgroupids}
		clbo, err := elbc.CreateLoadBalancer(clbi)
		if err != nil {
			fmt.Println("Failed to create elb:", err)
		}
		fmt.Println("Created elb:", *clbo.DNSName)

		instances := []*elb.Instance{}
		for k := range config.ELB[i].Instances {
			validInstances := getInstancesByName(svc, config.ELB[i].Instances[k])
			//fmt.Println(validInstances)
			for j := range validInstances {
				if *validInstances[j].State.Name != "terminated" {
					instance := &elb.Instance{InstanceId: validInstances[j].InstanceId}
					instances = append(instances, instance)
				}
			}
		}

		riwlbi := &elb.RegisterInstancesWithLoadBalancerInput{LoadBalancerName: &config.ELB[i].Name, Instances: instances}
		_, err = elbc.RegisterInstancesWithLoadBalancer(riwlbi)
		if err != nil {
			fmt.Println("Failed to register instances with elb:", err)
		}

	}

	if numStepsDeferred != 0 {
		fmt.Println("Waiting for remaining", numStepsDeferred, "creation steps to complete...")
		for i := 0; i < numStepsDeferred; i++ {
			msg := <-doneChan
			next := i + 1
			fmt.Printf("%d: %s\n", next, msg)
		}
	}


	err = sendSawsInfo(config,uuids)
	if err != nil {
		panic(err)
	}

	//fmt.Println("Creating with", config)
}

func releaseExternalIP(svc *ec2.EC2, instanceid string) error {
	keyname := "instance-id"

	filter := ec2.Filter{
		Name: &keyname, Values: []*string{&instanceid}}
	filters := []*ec2.Filter{
		&filter,
	}
	dai := &ec2.DescribeAddressesInput{Filters: filters}
	dao, err := svc.DescribeAddresses(dai)
	if err != nil {
		return err
	}

	for i := range dao.Addresses {
		//fmt.Println("Address ",dao.Addresses[i])

		dai := &ec2.DisassociateAddressInput{AssociationId: dao.Addresses[i].AssociationId}
		_, err := svc.DisassociateAddress(dai)
		//fmt.Println(daio)
		if err != nil {
			return err
		}

		rai := &ec2.ReleaseAddressInput{AllocationId: dao.Addresses[i].AllocationId}
		_, err = svc.ReleaseAddress(rai)
		//fmt.Println(rao)
		if err != nil {
			return err
		}
	}

	return nil
}

func Destroy(config *Config) {
	//fmt.Println("Destroy not implemented")
	svc := ec2.New(session.New())
	elbc := elb.New(session.New())
	rdsc := rds.New(session.New())

	doneChan := make(chan string)
	numStepsDeferred := 0

	for i := range config.EC2 {
		fmt.Println("Destroying EC2 instance:", config.EC2[i].Name)
		//fmt.Println(config.EC2[i].InstanceType)

		instances := getInstancesByName(svc, config.EC2[i].Name)
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				//fmt.Println("Instance is terminated:", *instances[k].InstanceId)
			} else {
				//fmt.Println("Instance will be terminated:", *instances[k].InstanceId)
				if config.EC2[i].HasExternalIP {
					//fmt.Println("Has external IP")
					//waitForNonXState(svc, instances[k].InstanceId, "shutting-down")
					err := releaseExternalIP(svc, *instances[k].InstanceId)
					if err != nil {
						fmt.Println("Failed to release ip: ", err)
					}
				}

				instanceids := []*string{instances[k].InstanceId}
				tii := ec2.TerminateInstancesInput{InstanceIds: instanceids}
				_, err := svc.TerminateInstances(&tii)
				if err != nil {
					panic(err)
				}

				numStepsDeferred++
				go func() {
					//err := waitForDetachedNetwork(svc,instances[k].InstanceId)
					err := waitForXState(svc, instances[k].InstanceId, "terminated")
					if err != nil {
						fmt.Println(err)
						doneChan <- fmt.Sprint(err)
					} else {
						//time.Sleep(20*time.Second)
						doneChan <- fmt.Sprintf("Terminated instance: %s", *instances[k].InstanceId)
					}
				}()

			}
		}
	}

	if config.DestroyPolicy == "nuke" {
		for i := range config.RDS {
			abool := true
			ddbi := &rds.DeleteDBInstanceInput{DBInstanceIdentifier: &config.RDS[i].DBInstanceIdentifier, SkipFinalSnapshot: &abool}
			_, err := rdsc.DeleteDBInstance(ddbi)
			if err != nil {
				fmt.Println("Error deleting instance:", err)
			}
			//fmt.Println(ddbo)

			numStepsDeferred++
			go func() {
				err := waitForDeleteRDS(rdsc, &config.RDS[i].DBInstanceIdentifier)
				if err != nil {
					fmt.Println(err)
					doneChan <- fmt.Sprint(err)
				} else {

					groupname := "sawsdbprivate"
					ddbsgi := &rds.DeleteDBSubnetGroupInput{DBSubnetGroupName: &groupname}
					_, err = rdsc.DeleteDBSubnetGroup(ddbsgi)
					if err != nil {
						fmt.Println("Failed to delete db subnetgroup:", err)
					}

					doneChan <- fmt.Sprintf("Destroyed %s RDS instance: %s", config.RDS[i].Engine, config.RDS[i].DBInstanceIdentifier)
				}
			}()

		}

	}

	for i := range config.ELB {
		dlbi := &elb.DeleteLoadBalancerInput{LoadBalancerName: &config.ELB[i].Name}
		_, err := elbc.DeleteLoadBalancer(dlbi)
		if err != nil {
			fmt.Println("Failed to delete load balancer:", err)
		} else {
			fmt.Println("Destroyed load balancer:", config.ELB[i].Name)
		}
	}

	if numStepsDeferred != 0 {
		fmt.Println("Waiting for remaining", numStepsDeferred, "destroy steps to complete...")
		for i := 0; i < numStepsDeferred; i++ {
			msg := <-doneChan
			next := i + 1
			fmt.Printf("%d: %s\n", next, msg)
		}
	}

	if config.DestroyPolicy == "nuke" {
		dvi := &ec2.DescribeVpcsInput{}
		dvo, err := svc.DescribeVpcs(dvi)
		if err != nil {
			panic(err)
		}

		for i := range dvo.Vpcs {
			if *dvo.Vpcs[i].CidrBlock == config.VPC {
				config.VpcId = *dvo.Vpcs[i].VpcId
			}
		}

		if config.VpcId == "" {
			fmt.Println("No VPC found, so not removing VPC or dependencies.")
			return
		}

		// before we mess with gateways and security groups, lets make sure all attached addresses are gone. they should really all be gone at this point, but it takes a bit sometimes...
		fmt.Println("Waiting for IPs to be free from Vpcs/Subnets...")
		err = waitForNoUsedIPS(svc, config.VpcId)
		if err != nil {
			fmt.Println(err)
		}

		// destroy security groups associated with VPC
		secgroups := getSecurityGroupIdsByVPC(svc, config.VpcId)
		for i := range secgroups {
			dsgi := &ec2.DeleteSecurityGroupInput{GroupId: secgroups[i]}
			_, err := svc.DeleteSecurityGroup(dsgi)
			if err != nil {
				fmt.Println("Error deleting security group:", err)
			} else {
				fmt.Println("Delete security group:", *secgroups[i])
			}
		}

		// deactivate and destroy gateways associated with VPC
		gatewayids, err := getGatewayIds(svc, config.VpcId)
		if err != nil {
			fmt.Println("Error fetching gateway list:", err)
		}
		for i := range gatewayids {
			digi := &ec2.DetachInternetGatewayInput{InternetGatewayId: &gatewayids[i], VpcId: &config.VpcId}
			_, err := svc.DetachInternetGateway(digi)
			if err != nil {
				fmt.Println("Failed to detach internet gateway:", err)
			}

			deigi := &ec2.DeleteInternetGatewayInput{InternetGatewayId: &gatewayids[i]}
			_, err = svc.DeleteInternetGateway(deigi)
			if err != nil {
				fmt.Println("Failed to delete internet gateway:", gatewayids[i])
			}

		}
		// wait a bit for aws to settle...
		//fmt.Println("All instances, security groups, gateways destroyed, resting a bit and removing route tables, subnets and VPC...")
		//time.Sleep(60*time.Second)

		// destroy subnets associated with VPC
		filters := make([]*ec2.Filter, 0)
		keyname := "vpc-id"
		filter := ec2.Filter{
			Name: &keyname, Values: []*string{&config.VpcId}}
		filters = append(filters, &filter)
		dsi := &ec2.DescribeSubnetsInput{Filters: filters}
		subnets, err := svc.DescribeSubnets(dsi)
		if err != nil {
			fmt.Println("Error describing subnets associated with VPC:", err)
		}

		for i := range subnets.Subnets {
			desi := &ec2.DeleteSubnetInput{SubnetId: subnets.Subnets[i].SubnetId}
			_, err = svc.DeleteSubnet(desi)
			if err != nil {
				fmt.Println("Failed to delete subnet:", err)
			}
		}

		// destroy route tables associated with VPC
		filters = make([]*ec2.Filter, 0)
		keyname = "vpc-id"
		filter = ec2.Filter{
			Name: &keyname, Values: []*string{&config.VpcId}}
		filters = append(filters, &filter)

		rti := &ec2.DescribeRouteTablesInput{Filters: filters}
		rttables, err := svc.DescribeRouteTables(rti)
		if err != nil {
			fmt.Println("Error describing route table associated with VPC:", err)
		}

		for i := range rttables.RouteTables {
			drti := &ec2.DeleteRouteTableInput{RouteTableId: rttables.RouteTables[i].RouteTableId}
			_, err = svc.DeleteRouteTable(drti)
			if err != nil {
				//fmt.Println("Failed to delete route table:", err)
			}
		}

		devi := &ec2.DeleteVpcInput{VpcId: &config.VpcId}
		_, err = svc.DeleteVpc(devi)

		if err != nil {
			fmt.Println("Error deleting vpc: ", err)
		}
		fmt.Println("Destroyed VPC:", config.VpcId)
	} else {
		fmt.Println("Everything but RDS and VPC destroyed.")
	}

}

func Start(config *Config) {
	svc := ec2.New(session.New())

	for i := range config.EC2 {
		fmt.Println("Starting ", config.EC2[i].Name)
		//fmt.Println(config.EC2[i].InstanceType)

		instances := getInstancesByName(svc, config.EC2[i].Name)
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				//fmt.Println("Instance is terminated:", *instances[k].InstanceId)
			} else {
				fmt.Println("Instance will be started: ", *instances[k].InstanceId)
				instanceids := []*string{instances[k].InstanceId}
				sii := ec2.StartInstancesInput{InstanceIds: instanceids}
				_, err := svc.StartInstances(&sii)
				if err != nil {
					panic(err)
				}
				fmt.Println("Started instance ", *instances[k].InstanceId)

			}
		}
	}

}

func Stop(config *Config) {
	svc := ec2.New(session.New())

	for i := range config.EC2 {
		fmt.Println("Stopping ", config.EC2[i].Name)
		//fmt.Println(config.EC2[i].InstanceType)

		instances := getInstancesByName(svc, config.EC2[i].Name)
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				//fmt.Println("Instance is terminated:", *instances[k].InstanceId)
			} else {
				fmt.Println("Instance will be shutdown: ", *instances[k].InstanceId)
				instanceids := []*string{instances[k].InstanceId}
				sii := ec2.StopInstancesInput{InstanceIds: instanceids}
				_, err := svc.StopInstances(&sii)
				if err != nil {
					panic(err)
				}
				fmt.Println("Stopped instance ", *instances[k].InstanceId)

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

func unwantedFileOrObject(path string, info os.FileInfo) bool {
	//fmt.Println(info.Name())
	unwanted := []string{".git.*", "src.*", "pkg.*", ".*?\\.key", "saws", "saws.json", "package.zip"}
	for i := range unwanted {
		//fmt.Println(path)
		match, err := regexp.MatchString(unwanted[i], path)
		if err != nil {
			panic(err)
		}
		if match {
			//fmt.Println("Do not want: ", path)
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

		if unwantedFileOrObject(path, info) {
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

	client := s3.New(session.New())
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
		fmt.Println("Created bucket", config.S3Bucket)
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
