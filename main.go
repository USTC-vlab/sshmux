package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
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
	sshmux, err := makeServer(config)
	if err != nil {
		log.Fatal(err)
	}
	sshmux.ListenAddr(config.Address)
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "/etc/sshmux/config.json", "config file")
	flag.Parse()
	sshmuxServer(configFile)
}
