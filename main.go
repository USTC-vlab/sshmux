package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/pelletier/go-toml/v2"
)

func watchConfigFile(path string) (chan fsnotify.Event, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	err = watcher.Add(path)
	if err != nil {
		return nil, err
	}
	return watcher.Events, nil
}

func replaceServer(sshmux *Server, event fsnotify.Event) (*Server, error) {
	if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
		log.Printf("info: %s has been changed, reloading...\n", event.Name)
		// Start new server instance
		newServer, err := sshmuxServer(event.Name)
		if err != nil {
			return sshmux, fmt.Errorf("failed to parse %s: %w", event.Name, err)
		}
		err = newServer.Start()
		if err != nil {
			return sshmux, fmt.Errorf("failed to start sshmux server: %w", err)
		}
		// Replace old server
		go sshmux.Shutdown()
		return newServer, nil
	}
	if event.Has(fsnotify.Remove) || event.Has(fsnotify.Rename) {
		log.Printf("warn: %s has been deleted\n", event.Name)
	}
	return sshmux, nil
}

func sshmuxServer(configFile string) (*Server, error) {
	var config Config
	configFileBytes, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(configFile, ".toml") {
		err = toml.Unmarshal(configFileBytes, &config)
		if err != nil {
			return nil, err
		}
	} else {
		log.Println("warning: The `config.json` API is deprecated. Please use `config.toml` instead.")
		var legacyConfig LegacyConfig
		err = json.Unmarshal(configFileBytes, &legacyConfig)
		if err != nil {
			return nil, err
		}
		config = convertLegacyConfig(legacyConfig)
	}
	return makeServer(config)
}

func main() {
	var configFile string
	var reload bool
	flag.StringVar(&configFile, "c", "/etc/sshmux/config.toml", "config file")
	flag.BoolVar(&reload, "r", false, "auto reload")
	flag.Parse()
	sshmux, err := sshmuxServer(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = sshmux.Start()
	if err != nil {
		log.Fatal(err)
	}
	if reload {
		events, err := watchConfigFile(configFile)
		if err != nil {
			log.Fatal(err)
		}
		for event := range events {
			sshmux, err = replaceServer(sshmux, event)
			if err != nil {
				log.Print(err)
			}
		}
	} else {
		sshmux.Wait()
	}
}
