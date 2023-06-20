package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// SSHConfig represents the structure of an SSH configuration entry
type SSHConfig struct {
	Host           string
	HostName       string
	User           string
	Port           int
	IdentityFile   string
	IdentitiesOnly bool
	ProxyJump      string
}

func expandTilde(path string) (string, error) {
	if strings.HasPrefix(path, "~/") || path == "~" {
		currentUser, err := user.Current()
		if err != nil {
			return "", err
		}
		return strings.Replace(path, "~", currentUser.HomeDir, 1), nil
	}
	return path, nil
}

func createSSHConfigFile(configFilePath string) error {
	sshConfigPath, err := expandTilde("~/.ssh/config")
	if err != nil {
		panic(err)
	}

	// Check if the ~/.ssh/config file exists
	_, err = os.Stat(sshConfigPath)
	if os.IsNotExist(err) {
		// Create the ~/.ssh directory if it doesn't exist
		err = os.MkdirAll(filepath.Dir(sshConfigPath), 0700)
		if err != nil {
			return err
		}

		// Create the ~/.ssh/config file
		file, err := os.Create(sshConfigPath)
		if err != nil {
			return err
		}
		file.Close()
	}

	// Append the absolute path of the new config file to the end of ~/.ssh/config
	file, err := os.OpenFile(sshConfigPath, os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	configFileEntry := fmt.Sprintf("Include %s\n", configFilePath)

	// Check if the entry already exists in the ~/.ssh/config file
	exists, err := checkEntryExists(file, configFileEntry)
	if err != nil {
		return err
	}

	// Append the entry only if it doesn't already exist
	if !exists {
		_, err = file.WriteString(configFileEntry)
		if err != nil {
			return err
		}
	}

	fmt.Printf("updated %s\n", sshConfigPath)

	return nil
}

// Function to check if an entry already exists in the file
func checkEntryExists(file *os.File, entry string) (bool, error) {
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		if line == strings.ReplaceAll(entry, "\n", "") {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, err
	}
	return false, nil
}


func main() {
	// Define the prefix, region, and PEM file path flags
	prefix := flag.String("prefix", "my-cluster", "Prefix for filtering instances")
	region := flag.String("region", "", "AWS region")
	pemPath := flag.String("pem", "", "Path to the PEM file")
	flag.Parse()

	if *region == "" {
		fmt.Println("Region is required.")
		return
	}

	if *pemPath == "" {
		fmt.Println("Path to the PEM file is required.")
		return
	}

	// Create a new AWS SDK configuration
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*region))
	if err != nil {
		fmt.Println("Failed to load AWS SDK configuration:", err)
		return
	}

	// Create a new EC2 client
	client := ec2.NewFromConfig(cfg)

	// Set the input parameters
	filterName := "tag:Name"
	filterValues := []string{
		fmt.Sprintf("%s-md-0-*", *prefix),
		fmt.Sprintf("%s-bastion", *prefix),
		fmt.Sprintf("%s-control-plane-*", *prefix),
	}
	input := &ec2.DescribeInstancesInput{
		Filters: []types.Filter{
			{
				Name:   &filterName,
				Values: filterValues,
			},
		},
	}

	// Send the DescribeInstances API request
	resp, err := client.DescribeInstances(context.TODO(), input)
	if err != nil {
		fmt.Println("Failed to describe instances:", err)
		return
	}

	// Create a channel to control the maximum number of goroutines running simultaneously
	maxConcurrency := 10
	semaphore := make(chan struct{}, maxConcurrency)

	// Create a mutex for thread-safe access to sshConfigs
	var mutex sync.Mutex

	// Create a wait group to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Extract the required information and format as SSHConfig objects
	var sshConfigs []SSHConfig
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			// Skip instances that are not in the "running" or "pending" state
			if instance.State.Name != "running" && instance.State.Name != "pending" {
				continue
			}
			// Acquire a token from the semaphore to control concurrency
			semaphore <- struct{}{}

			wg.Add(1)
			go func(instance types.Instance) {
				defer wg.Done()

				hostname := ""
				privateIP := ""
				publicIP := ""
				var proxyJump string

				for _, tag := range instance.Tags {
					if *tag.Key == "Name" {
						hostname = *tag.Value
						break
					}
				}

				if instance.PrivateIpAddress != nil {
					privateIP = *instance.PrivateIpAddress
				}

				if instance.PublicIpAddress != nil {
					publicIP = *instance.PublicIpAddress
				}

				if strings.Contains(hostname, "bastion") {
					proxyJump = ""
				} else {
					proxyJump = fmt.Sprintf("%s-bastion", *prefix)
				}

				sshConfig := SSHConfig{
					Host:           hostname,
					HostName:       privateIP,
					User:           "ubuntu",
					Port:           22,
					IdentityFile:   *pemPath,
					IdentitiesOnly: true,
					ProxyJump:      proxyJump,
				}

				if strings.Contains(hostname, "bastion") {
					sshConfig.HostName = publicIP
				}

				// Lock the mutex before writing to sshConfigs
				mutex.Lock()
				sshConfigs = append(sshConfigs, sshConfig)
				mutex.Unlock()

				// Release the token back to the semaphore
				<-semaphore
			}(instance)
		}
	}

	// Wait for all goroutines to finish
	wg.Wait()

	// Generate the SSH configuration file using a template
	tmpl := template.Must(template.New("sshConfig").Parse(`
{{- range .}}
Host {{.Host}}
 HostName {{.HostName}}
 User {{.User}}
 Port {{.Port}}
 IdentityFile {{.IdentityFile}}
 IdentitiesOnly {{.IdentitiesOnly}}
 StrictHostKeyChecking no
 {{if .ProxyJump}}ProxyJump {{.ProxyJump}}{{end}}
{{- end}}`))

	// Generate a unique file name based on the current timestamp
	configFileName, err := expandTilde(filepath.Join("~/.ssh", fmt.Sprintf("%s-cluster-api-test.config", *prefix)))
	if err != nil {
		panic(err)
	}

	// Write the SSH configuration to a file
	file, err := os.OpenFile(configFileName, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Failed to create SSH configuration file:", err)
		return
	}
	defer file.Close()

	err = tmpl.Execute(file, sshConfigs)
	if err != nil {
		fmt.Println("Failed to generate SSH configuration:", err)
		return
	}

	// Write the SSH configuration to the ~/.ssh/config file
	configFilePath, err := filepath.Abs(configFileName)
	if err != nil {
		panic(err)
	}

	err = createSSHConfigFile(configFilePath)
	if err != nil {
		fmt.Println("Failed to update SSH configuration file:", err)
		return
	}

	fmt.Printf("updated %s\n", configFileName)
}

