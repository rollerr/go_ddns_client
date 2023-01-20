package main

import (
	"context"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"strings"

	cloudfare "github.com/cloudflare/cloudflare-go"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

type Config struct {
	Email          string `yaml:"email"`
	ZoneRecordID   string `yaml:"zone_record_id"`
	ZoneID         string `yaml:"zone_id"`
	SSHKeyPath     string `yaml:"ssh_key_path"`
	SSHUser        string `yaml:"ssh_user"`
	Domain         string `yaml:"domain"`
	cloudFareToken string `yaml:"api_file_path"`
	DestinationIP  string `yaml:"destination_ip"`
}

func getKeyFromPath(apiFilePath string) string {
	if apiFilePath == "" {
		log.Fatal("No API key file specified")
		return ""
	}

	log.Printf("Reading key from %s", apiFilePath)
	file, err := os.ReadFile(apiFilePath)
	if err != nil {
		log.Fatal("Could not open key file: ", err)
	}
	return string(file)
}

func getConfigFromYaml() Config {
	var ConfigPath string
	flag.StringVar(&ConfigPath, "config", "config.yaml", "Path to config file")
	flag.Parse()

	f, err := os.Open(ConfigPath)
	if err != nil {
		log.Fatal("Could not open config file: ", err)
	}
	defer f.Close()
	configFile, err := io.ReadAll(f)
	if err != nil {
		log.Fatal(err)
	}
	var config Config
	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatal(err)
	}
	return config
}

func fetchWANIPOverSSH(sshUser string, sshKey string, destinationIP string) string {
	privateKey, err := ssh.ParsePrivateKey([]byte(sshKey))
	if err != nil {
		log.Fatal(err)
	}
	config := &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(privateKey),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", destinationIP+":22", config)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	output, err := session.Output(`ip addr show lo | grep "inet " | awk "{print $2}"`)
	parsedWANIP := parseWANIPFromOutput(string(output))
	if err != nil {
		log.Fatal(err)
	}
	return string(parsedWANIP)

}

func parseWANIPFromOutput(output string) string {
	fields := strings.Fields(string(output))
	newFields := strings.Split(fields[1], "/")[0]
	return newFields
}

func checkIfDNSRecordNeedsUpdate(currentIP string, domain string) bool {
	if domain == "" {
		log.Fatal("No domain specified")
		return false
	}
	log.Print("Checking if DNS record needs updating")
	addresses, err := net.LookupHost(domain)
	if err != nil {
		log.Fatal(err)
	}
	if len(addresses) == 0 {
		log.Fatal("No DNS records found for domain")
	}
	if currentIP == addresses[0] {
		log.Printf("DNS record does not need updating (current IP: %s, DNS record IP: %s)", currentIP, addresses[0])
		return false
	}
	return true
}

func publishNewIPToCloudflare(currentIP string, config Config) error {
	log.Printf("Publishing new IP to Cloudflare (%s)", currentIP)
	log.Printf("Reading API key from %s", config.cloudFareToken)
	token := getKeyFromPath(config.cloudFareToken)
	api, err := cloudfare.NewWithAPIToken(token)
	if err != nil {
		log.Fatal(err)
		return err
	}

	newRecord := cloudfare.UpdateDNSRecordParams{
		Type:    "A",
		Name:    config.Domain,
		Content: currentIP,
		TTL:     120,
	}
	newerr := api.UpdateDNSRecord(context.Background(), nil, newRecord)
	return newerr
}

func main() {
	config := getConfigFromYaml()
	sshKey := getKeyFromPath(config.SSHKeyPath)
	sshResult := fetchWANIPOverSSH(config.SSHUser, sshKey, config.DestinationIP)
	log.Printf("Current WAN IP: %s", sshResult)
	if checkIfDNSRecordNeedsUpdate(sshResult, config.Domain) {
		log.Printf("DNS record needs updating (current IP: %s, DNS record IP %s)", sshResult, config.Domain)
		err := publishNewIPToCloudflare(sshResult, config)
		if err != nil {
			log.Fatal(err)
		}
	}
}
