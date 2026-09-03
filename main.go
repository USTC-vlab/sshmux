package main

import (
	"context"
	"encoding/json"
	"flag"
	"log/slog"
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
	slog.Warn("the `config.json` API is deprecated, use `config.toml` instead")
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
	// What sshmux says about itself before it has a logger, and after it has
	// torn one down, reaches the terminal the same shape as what the logger
	// writes there.
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
	var configFile string
	flag.StringVar(&configFile, "c", "/etc/sshmux/config.toml", "config file")
	flag.Parse()
	sshmux, err := sshmuxServer(configFile)
	if err != nil {
		slog.LogAttrs(context.Background(), slog.LevelError, "sshmux could not start",
			defaultAttributeNames.errorAttributes(err)...)
		os.Exit(1)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	if err := runUntilSignal(sshmux, signals); err != nil {
		slog.LogAttrs(context.Background(), slog.LevelError, "sshmux could not start",
			defaultAttributeNames.errorAttributes(err)...)
		os.Exit(1)
	}
}
