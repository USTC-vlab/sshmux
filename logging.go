package main

import (
	"encoding/json"
	"log"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type LogMessage struct {
	LoginTime      int64  `json:"login_time"`
	DisconnectTime int64  `json:"disconnect_time"`
	ClientIp       string `json:"remote_ip"`
	HostIp         string `json:"host_ip"`
	Username       string `json:"user_name"`
}

func runLogger(logger string, ch <-chan LogMessage) {
	conn, err := net.Dial("udp", logger)
	if err != nil {
		log.Printf("Logger Dial failed: %s\n", err)
		// Drain the channel to avoid blocking
		for range ch {
		}
	}
	for logMessage := range ch {
		jsonMsg, err := json.Marshal(logMessage)
		if err != nil {
			continue
		}
		conn.Write(jsonMsg)
	}
}

func sendLogAndClose(logMessage *LogMessage, session *ssh.PipeSession, logCh chan<- LogMessage) {
	session.Close()
	logMessage.DisconnectTime = time.Now().Unix()
	logCh <- *logMessage
}
