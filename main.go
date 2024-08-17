package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
)

func sshmuxServer(configFile string) (*Server, error) {
	var config Config
	configFileBytes, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(configFileBytes, &config)
	if err != nil {
		log.Fatal(err)
	}
	sshmux, err := makeServer(config)
	if err != nil {
		return nil, err
	}
	return sshmux, nil
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "/etc/sshmux/config.json", "config file")
	flag.Parse()
	sshmux, err := sshmuxServer(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = sshmux.Start()
	if err != nil {
		log.Fatal(err)
	}
	sshmux.Wait()
}
