package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

func sshmuxServer(configFile string) (*Server, error) {
	if strings.HasSuffix(configFile, ".toml") {
		var config Config
		configFileBytes, err := os.ReadFile(configFile)
		if err != nil {
			return nil, err
		}
		err = toml.Unmarshal(configFileBytes, &config)
		if err != nil {
			return nil, err
		}
		return makeServer(config)
	} else {
		var legacyConfig LegacyConfig
		configFileBytes, err := os.ReadFile(configFile)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(configFileBytes, &legacyConfig)
		if err != nil {
			return nil, err
		}
		return makeLegacyServer(legacyConfig)
	}
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
