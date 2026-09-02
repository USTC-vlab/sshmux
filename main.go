package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/pelletier/go-toml/v2"
)

func loadConfig(configFile string) (Config, error) {
	var config Config
	configFileBytes, err := os.ReadFile(configFile)
	if err != nil {
		return config, err
	}
	if strings.HasSuffix(configFile, ".toml") {
		err = toml.Unmarshal(configFileBytes, &config)
		if err != nil {
			return config, err
		}
		return config, nil
	}
	log.Println("warning: The `config.json` API is deprecated. Please use `config.toml` instead.")
	var legacyConfig LegacyConfig
	err = json.Unmarshal(configFileBytes, &legacyConfig)
	if err != nil {
		return config, err
	}
	return convertLegacyConfig(legacyConfig), nil
}

func sshmuxServer(configFile string) (*Server, error) {
	config, err := loadConfig(configFile)
	if err != nil {
		return nil, err
	}
	return makeServer(config)
}

type serverLifecycle interface {
	Start() error
	Shutdown()
}

func runUntilSignal(server serverLifecycle, signals <-chan os.Signal) error {
	if err := server.Start(); err != nil {
		return err
	}
	<-signals
	server.Shutdown()
	return nil
}

func main() {
	var configFile string
	flag.StringVar(&configFile, "c", "/etc/sshmux/config.toml", "config file")
	flag.Parse()
	sshmux, err := sshmuxServer(configFile)
	if err != nil {
		log.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := runUntilSignal(sshmux, signals); err != nil {
		log.Fatal(err)
	}
}
