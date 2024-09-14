package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"

	"github.com/pelletier/go-toml/v2"
)

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
	var pprofFile string
	flag.StringVar(&configFile, "c", "/etc/sshmux/config.toml", "config file")
	flag.StringVar(&pprofFile, "pprof", "", "write pprof data to file")
	flag.Parse()
	if pprofFile != "" {
		f, err := os.Create(pprofFile)
		if err != nil {
			log.Fatal("failed to create pprof file: %w", err)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("failed to start pprof: %w", err)
		}
		defer pprof.StopCPUProfile()
		// Handle SIGINT/SIGTERM
		signalChan := make(chan os.Signal, 1)
		signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-signalChan
			pprof.StopCPUProfile()
			os.Exit(0)
		}()
	}
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
