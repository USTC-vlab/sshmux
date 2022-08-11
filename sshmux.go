package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	Address               string   `json:"address"`
	HostKeys              []string `json:"host-keys"`
	API                   string   `json:"api"`
	Token                 string   `json:"token"`
	RecoveryServer        string   `json:"recovery-server"`
	RecoveryUsername      []string `json:"recovery-username"`
	AllUsernameNoPassword bool     `json:"all-username-nopassword"`
	UsernameNoPassword    []string `json:"username-nopassword"`
	Logger                string   `json:"logger"`
	Banner                string   `json:"banner"`
}

type LogMessage struct {
	LoginTime      int64  `json:"login_time"`
	DisconnectTime int64  `json:"disconnect_time"`
	ClientIp       string `json:"remote_ip"`
	HostIp         string `json:"host_ip"`
	Username       string `json:"user_name"`
}

var configFile string
var config Config

type UpstreamInformation struct {
	Host     string
	Signer   ssh.Signer
	Password *string
}

func parsePrivateKey(key string, cert string) ssh.Signer {
	if key == "" {
		return nil
	}
	signer, err := ssh.ParsePrivateKey([]byte(key))
	if err != nil {
		return nil
	}
	if cert == "" {
		return signer
	}
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cert))
	if err != nil {
		return signer
	}
	certSigner, err := ssh.NewCertSigner(pk.(*ssh.Certificate), signer)
	if err != nil {
		return signer
	}
	return certSigner
}

func isStringInArray(str string, arr []string) bool {
	for _, s := range arr {
		if s == str {
			return true
		}
	}
	return false
}

func authUser(request []byte, username string) (*UpstreamInformation, error) {
	res, err := http.Post(config.API, "application/json", bytes.NewBuffer(request))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	type Response struct {
		Status     string `json:"status"`
		Address    string `json:"address"`
		PrivateKey string `json:"private_key"`
		Cert       string `json:"cert"`
		Id         int    `json:"vmid"`
	}
	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}
	if response.Status != "ok" {
		return nil, nil
	}

	var upstream UpstreamInformation
	if isStringInArray(username, config.RecoveryUsername) {
		upstream.Host = config.RecoveryServer
		password := fmt.Sprintf("%d %s", response.Id, config.Token)
		upstream.Password = &password
	} else {
		upstream.Host = response.Address
	}
	upstream.Signer = parsePrivateKey(response.PrivateKey, response.Cert)
	return &upstream, nil
}

func authUserWithPublicKey(key ssh.PublicKey, unixUsername string) (*UpstreamInformation, error) {
	keyType := key.Type()
	keyData := base64.StdEncoding.EncodeToString(key.Marshal())
	type Request struct {
		AuthType      string `json:"auth_type"`
		UnixUsername  string `json:"unix_username"`
		PublicKeyType string `json:"public_key_type"`
		PublicKeyData string `json:"public_key_data"`
		Token         string `json:"token"`
	}
	request := Request{
		AuthType:      "key",
		UnixUsername:  unixUsername,
		PublicKeyType: keyType,
		PublicKeyData: keyData,
		Token:         config.Token,
	}
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return authUser(jsonData, unixUsername)
}

func authUserWithUserPass(username string, password string, unixUsername string) (*UpstreamInformation, error) {
	type Request struct {
		AuthType     string `json:"auth_type"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		UnixUsername string `json:"unix_username"`
		Token        string `json:"token"`
	}
	request := Request{
		AuthType:     "key",
		Username:     username,
		Password:     password,
		UnixUsername: unixUsername,
		Token:        config.Token,
	}
	jsonData, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	return authUser(jsonData, unixUsername)
}

func removePublicKeyMethod(methods []string) []string {
	res := []string{}
	for _, s := range methods {
		if s != "publickey" {
			res = append(res, s)
		}
	}
	return res
}

func handshake(session *ssh.PipeSession) error {
	hasSetUser := false
	var user string
	var upstream *UpstreamInformation
	if config.Banner != "" {
		err := session.Downstream.SendBanner(config.Banner)
		if err != nil {
			return err
		}
	}
	// Stage 1: Get publickey or keyboard-interactive answers, and authenticate the user with with API
	for {
		req, err := session.Downstream.ReadAuthRequest(true)
		if err != nil {
			return err
		}
		if !hasSetUser {
			user = req.User
			session.Downstream.SetUser(user)
			hasSetUser = true
		}
		if req.Method == "none" {
			session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
		} else if req.Method == "publickey" && !req.IsPublicKeyQuery {
			upstream, err = authUserWithPublicKey(*req.PublicKey, user)
			if err != nil {
				return err
			}
			if upstream != nil {
				break
			}
			session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
		} else if req.Method == "keyboard-interactive" {
			requireUnixPassword := !config.AllUsernameNoPassword &&
				!isStringInArray(user, config.RecoveryUsername) &&
				!isStringInArray(user, config.UsernameNoPassword)
			interactiveQuestions := []string{"Vlab username (Student ID): ", "Vlab password: "}
			interactiveEcho := []bool{true, false}
			if requireUnixPassword {
				interactiveQuestions = append(interactiveQuestions, "UNIX password: ")
				interactiveEcho = append(interactiveEcho, false)
			}

			answers, err := session.Downstream.InteractiveChallenge("",
				"Please enter Vlab username & password and UNIX password.",
				interactiveQuestions, interactiveEcho)
			if err != nil {
				return err
			}
			if len(answers) != len(interactiveQuestions) {
				return fmt.Errorf("ssh: numbers of answers and questions do not match")
			}
			username := answers[0]
			password := answers[1]
			upstream, err = authUserWithUserPass(username, password, user)
			if err != nil {
				return err
			}
			if upstream != nil {
				if requireUnixPassword {
					upstream.Password = &answers[2]
				}
				break
			}
			session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
		} else {
			session.Downstream.WriteAuthFailure([]string{"publickey", "keyboard-interactive"}, false)
		}
	}
	// Stage 2: connect to upstream
	conn, err := net.Dial("tcp", upstream.Host)
	if err != nil {
		return err
	}
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	err = session.InitUpstream(conn, upstream.Host, config)
	if err != nil {
		return err
	}
	// Firstly try publickey or password
	if upstream.Signer != nil {
		err = session.Upstream.WriteAuthRequestPublicKey(user, upstream.Signer)
	} else if upstream.Password != nil {
		err = session.Upstream.WriteAuthRequestPassword(user, *upstream.Password)
	} else {
		// Send a none auth request
		err = session.Upstream.WriteAuthNone(user)
	}
	if err != nil {
		return err
	}
	res, err := session.Upstream.ReadAuthResult()
	if err != nil {
		return err
	}
	// For the first auth fail, we mark it partial succss
	if !res.Success {
		err = session.Downstream.WriteAuthFailure(removePublicKeyMethod(res.Methods), true)
	} else {
		err = session.Downstream.WriteAuthResult(res)
	}
	if err != nil {
		return err
	}
	if res.Success {
		return nil
	}
	// Finally, pipe downstream and upstream's auth request and result
	// Note that publickey auth cannot be used anymore after this point
	for {
		req, err := session.Downstream.ReadAuthRequest(true)
		if err != nil {
			return err
		}
		err = session.Upstream.WriteAuthRequest(req)
		if err != nil {
			return err
		}
		res, err := session.Upstream.ReadAuthResult()
		if err != nil {
			return err
		}
		if !res.Success {
			err = session.Downstream.WriteAuthFailure(removePublicKeyMethod(res.Methods), res.PartialSuccess)
		} else {
			err = session.Downstream.WriteAuthResult(res)
		}
		if err != nil {
			return err
		}
		if res.Success {
			return nil
		}
	}
}

func runPipeSession(session *ssh.PipeSession, logMessage *LogMessage) error {
	err := handshake(session)
	if err != nil {
		return err
	}
	logMessage.Username = session.Downstream.User()
	logMessage.HostIp = session.Upstream.RemoteAddr().String()
	return session.RunPipe()
}

func sendLogAndClose(logMessage *LogMessage, session *ssh.PipeSession) {
	session.Close()
	conn, err := net.Dial("udp", config.Logger)
	if err != nil {
		return
	}
	logMessage.DisconnectTime = time.Now().Unix()
	jsonMsg, err := json.Marshal(logMessage)
	if err != nil {
		return
	}
	conn.Write(jsonMsg)
}

func main() {
	flag.StringVar(&configFile, "c", "/etc/sshmux.json", "config file")
	flag.Parse()
	configFile, err := ioutil.ReadFile(configFile)
	if err != nil {
		log.Fatal(err)
	}
	err = json.Unmarshal(configFile, &config)
	if err != nil {
		log.Fatal(err)
	}
	sshConfig := &ssh.ServerConfig{}
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
	listener, err := net.Listen("tcp", config.Address)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func() {
			session, err := ssh.NewPipeSession(conn, sshConfig)
			logMessage := LogMessage{
				LoginTime: time.Now().Unix(),
				ClientIp:  conn.RemoteAddr().String(),
			}
			if err != nil {
				return
			}
			defer sendLogAndClose(&logMessage, session)
			runPipeSession(session, &logMessage)
		}()
	}
}
