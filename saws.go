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
)

type Config struct {
	S3Bucket string `json:s3bucket`
	EC2      []EC2  `json:ec2`
	InitialConfig     string  `json:initialconfig`
}

type EC2 struct {
	Name         string `json:string`
	InstanceType string `json:instancetype`
	AMI string `json:ami`
	KeyName string `json:keyname`
	SubnetID string `json:subnetid`
	SecurityGroupIDs []*string `json:securitygroupids`
}

func getUserData(initialconfig string, s3bucket string) string {
	ic, err := ioutil.ReadFile(initialconfig)
	if err != nil {
		panic(err)
	}


	rxpid := regexp.MustCompile("SAWS_ACCESS_KEY")
	rxpkey := regexp.MustCompile("SAWS_SECRET_KEY")
	rxp3 := regexp.MustCompile("SAWS_S3BUCKET")
	ic1 := rxpid.ReplaceAll(ic, []byte(os.Getenv("AWS_ACCESS_KEY_ID")))
	ic2 := rxpkey.ReplaceAll(ic1, []byte(os.Getenv("AWS_SECRET_ACCESS_KEY")))
	ic3 := rxp3.ReplaceAll(ic2, []byte(s3bucket))


	fmt.Println("ic3")
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

func uploadPackage(config Config) error {
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

func Push(config Config) {
	uploadPackage(config)
}

func createInstance(svc *ec2.EC2, ec2config EC2, userdata string) {
	var min int64
	var max int64
	min = 1
	max = 1

	subnet := ec2config.SubnetID	
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

	rres, err := svc.RunInstances(params)
	if err != nil {
		fmt.Println("Failed to create instance",err)
		fmt.Println(rres)
	} else {
		fmt.Println("Created instance")
		//fmt.Println(rres)
		
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
		} else {
			fmt.Println("Created tag Name with value", ec2config.Name)
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

func Create(config Config) {
	//fmt.Println("Create not implemented")

	svc := ec2.New(nil)

	for i := range config.EC2 {
		fmt.Println(config.EC2[i].Name)
		fmt.Println(config.EC2[i].InstanceType)

		instances := getInstancesByName(svc,config.EC2[i].Name)

		exists := false
		for k := range instances {
			if *instances[k].State.Name == "terminated" {
				fmt.Println("Instance is terminated:", *instances[k].InstanceID)
			} else {
				fmt.Println("Instance already exists: ", *instances[k].PublicIPAddress)
				exists = true
			}
		}


		if !exists {
			fmt.Println("No instance found, creating...")
			userdata := getUserData(config.InitialConfig,config.S3Bucket)
			createInstance(svc, config.EC2[i], userdata)
			
		}

	}
}

func Destroy(config Config) {
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
	flag.StringVar(&action, "a", "pack", "Action, create/destroy/pack/push")
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
		Create(*config)
	case action == "destroy":
		Destroy(*config)
	case action == "push":
		Push(*config)
	default:
		fmt.Println("Unknown action given", action)
	}

}
