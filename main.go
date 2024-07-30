package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/netip"
	"os"

	"golang.org/x/crypto/ssh"
)

func sshmuxServer(configFile string) {
	var config Config
	configFileBytes, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(configFileBytes, &config)
	if err != nil {
		log.Fatal(err)
	}
	sshConfig := &ssh.ServerConfig{
		ServerVersion:           "SSH-2.0-taokystrong",
		PublicKeyAuthAlgorithms: ssh.DefaultPubKeyAuthAlgos(),
	}
	for _, keyFile := range config.HostKeys {
		bytes, err := os.ReadFile(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		key, err := ssh.ParsePrivateKey(bytes)
		if err != nil {
			log.Fatal(err)
		}
		sshConfig.AddHostKey(key)
	}
	proxyUpstreams := make([]netip.Prefix, 0)
	for _, cidr := range config.ProxyCIDRs {
		network, err := netip.ParsePrefix(cidr)
		if err != nil {
			log.Fatal(err)
		}
		proxyUpstreams = append(proxyUpstreams, network)
	}
	sshmuxListenAddr(config.Address, sshConfig, proxyUpstreams, config)
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "/etc/sshmux/config.json", "config file")
	flag.Parse()
	sshmuxServer(configFile)
}
