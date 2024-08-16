package main

import (
	"encoding/json"
	"log"
	"net"
	"time"
)

type LogMessage struct {
	ConnectTime    int64  `json:"connect_time"`
	DisconnectTime int64  `json:"disconnect_time"`
	ClientIp       string `json:"remote_ip"`
	HostIp         string `json:"host_ip"`
	Username       string `json:"username"`
	Authenticated  bool   `json:"authenticated"`
	ClientType     string `json:"client_type"`
}

type Logger struct {
	Channel chan LogMessage
}

func makeLogger(url string) Logger {
	channel := make(chan LogMessage, 256)
	go func() {
		if url == "" {
			for range channel {
			}
			return
		}
		conn, err := net.Dial("udp", url)
		if err != nil {
			log.Printf("Logger Dial failed: %s\n", err)
			// Drain the channel to avoid blocking
			for range channel {
			}
			return
		}
		for logMessage := range channel {
			jsonMsg, err := json.Marshal(logMessage)
			if err != nil {
				continue
			}
			conn.Write(jsonMsg)
		}
	}()
	return Logger{Channel: channel}
}

func (l Logger) SendLog(logMessage *LogMessage) {
	logMessage.DisconnectTime = time.Now().Unix()
	l.Channel <- *logMessage
}
