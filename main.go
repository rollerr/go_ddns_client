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
	CloudFareTokenPath string `yaml:"cloudflare_token"`
	Email              string `yaml:"email"`
	ZoneRecordID       string `yaml:"zone_record_id"`
	ZoneID             string `yaml:"zone_id"`
	SSHKeyPath         string `yaml:"ssh_key_path"`
	SSHUser            string `yaml:"ssh_user"`
	Domain             string `yaml:"domain"`
	DestinationIP      string `yaml:"destination_ip"`
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
	flag.StringVar(&ConfigPath, "config", "config.yaml", "./")
	flag.Parse()
	log.Printf("Reading config from %s", ConfigPath)

	f, err := os.Open(ConfigPath)
	if err != nil {
		log.Fatal("Could not open config file: ", err)
	}
	defer f.Close()
	configFile, err := io.ReadAll(f)
	log.Printf("Config file is: %s", configFile)
	if err != nil {
		log.Fatal(err)
	}
	var YAMLConfig Config
	err = yaml.Unmarshal(configFile, &YAMLConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Cloudfare token path is: %s", YAMLConfig.CloudFareTokenPath)
	return YAMLConfig
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

	output, err := session.Output(`ip addr show eth0 | grep "inet " | awk "{print $2}"`)
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
	token := getKeyFromPath(config.CloudFareTokenPath)
	token = strings.TrimSpace(token)
	api, apierr := cloudfare.NewWithAPIToken(token)
	if apierr != nil {
		log.Fatal(apierr)
	}
	ctx := context.Background()

	zoneIdentifier := cloudfare.ZoneIdentifier(config.ZoneID)

	newRecord := cloudfare.UpdateDNSRecordParams{
		Type:    "A",
		ID:      config.ZoneRecordID,
		Name:    config.Domain,
		Content: currentIP,
		TTL:     120,
	}
	log.Printf("Updating DNS record to %s for domain: %s", currentIP, config.Domain)
	err := api.UpdateDNSRecord(ctx, zoneIdentifier, newRecord)
	if err != nil {
		log.Fatal(err)

	} else {
		log.Printf("DNS record updated to %s", currentIP)
	}
	return err
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
