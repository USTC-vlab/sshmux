package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pires/go-proxyproto"
)

var sshmuxProxyAddr *net.TCPAddr = localhostTCPAddr(8122)
var sshmuxServerAddr *net.TCPAddr = localhostTCPAddr(8022)
var sshdProxiedAddr *net.TCPAddr = localhostTCPAddr(2332)
var sshdServerAddr *net.TCPAddr = localhostTCPAddr(2333)
var apiServerAddr *net.TCPAddr = localhostTCPAddr(5000)

func localhostTCPAddr(port int) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	}
}

var enableProxy bool

func initHttp(sshPrivateKey []byte) {
	sshAPIHandler := func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Cannot read body", http.StatusBadRequest)
			return
		}
		var dat map[string]interface{}
		if err := json.Unmarshal(body, &dat); err != nil {
			http.Error(w, "Not JSON", http.StatusBadRequest)
			return
		}

		res := &LegacyAuthResponse{
			Status:     "ok",
			Id:         1141919,
			PrivateKey: string(sshPrivateKey),
		}
		if enableProxy {
			res.Address = sshdProxiedAddr.String()
			res.ProxyProtocol = 2
		} else {
			res.Address = sshdServerAddr.String()
		}

		jsonRes, err := json.Marshal(res)
		if err != nil {
			http.Error(w, "Cannot encode JSON", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonRes)
	}

	authAPIHandler := func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Cannot read body", http.StatusBadRequest)
			return
		}
		var dat map[string]interface{}
		if err := json.Unmarshal(body, &dat); err != nil {
			http.Error(w, "Not JSON", http.StatusBadRequest)
			return
		}

		upstream := AuthUpstream{
			PrivateKey: string(sshPrivateKey),
		}
		if enableProxy {
			upstream.Host = sshdProxiedAddr.IP.String()
			upstream.Port = uint16(sshdProxiedAddr.Port)
			upstream.ProxyProtocol = 2
		} else {
			upstream.Host = sshdServerAddr.IP.String()
			upstream.Port = uint16(sshdServerAddr.Port)
		}

		jsonRes, err := json.Marshal(AuthResponse{Upstream: &upstream})
		if err != nil {
			http.Error(w, "Cannot encode JSON", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonRes)
	}

	router := httprouter.New()
	router.POST("/ssh", sshAPIHandler)
	router.POST("/v1/auth/:name", authAPIHandler)

	if err := http.ListenAndServe(apiServerAddr.String(), router); err != nil {
		log.Fatal(err)
	}
}

func initUpstreamProxyServer() {
	listener, err := net.ListenTCP("tcp", sshmuxProxyAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 22)}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			// 1. Set up downstream connection with sshmux
			sshmux, err := net.DialTCP("tcp", localAddr, sshmuxServerAddr)
			if err != nil {
				log.Fatal(err)
			}
			// 2. Send PROXY header to sshmux
			header := proxyproto.HeaderProxyFromAddrs(2, conn.RemoteAddr(), sshmux.RemoteAddr())
			_, err = header.WriteTo(sshmux)
			if err != nil {
				log.Fatal(err)
			}
			// 3. Forward TCP messages in both directions
			go func() {
				defer sshmux.Close()
				io.Copy(sshmux, conn)
			}()
			go func() {
				defer conn.Close()
				io.Copy(conn, sshmux)
			}()
		}()
	}
}

func initDownstreamProxyServer() {
	listener, err := net.ListenTCP("tcp", sshdProxiedAddr)
	if err != nil {
		log.Fatal(err)
	}
	// Enforce listener to accept PROXY protocol
	proxyListener := &proxyproto.Listener{
		Listener: listener,
		Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}
	defer proxyListener.Close()

	for {
		conn, err := proxyListener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			// 1. Set up downstream connection with sshd
			sshd, err := net.DialTCP("tcp", nil, sshdServerAddr)
			if err != nil {
				log.Fatal(err)
			}
			// 2. Forward TCP messages in both directions
			go func() {
				defer sshd.Close()
				io.Copy(sshd, conn)
			}()
			go func() {
				defer conn.Close()
				io.Copy(conn, sshd)
			}()
		}()
	}
}

func initEnv(t *testing.T) {
	// SSHD privilege separation directory
	os.MkdirAll("/run/sshd", 0o755)

	// Ensure private key permissions
	keyFiles := []string{"ssh_host_ecdsa_key", "ssh_host_ed25519_key", "ssh_host_rsa_key", "ssh_id_rsa"}
	for _, keyFile := range keyFiles {
		err := os.Chmod(filepath.Join("fixtures", keyFile), 0o400)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Read SSH private key
	privateKey, err := os.ReadFile("fixtures/ssh_id_rsa")
	if err != nil {
		t.Fatal(err)
	}

	// Setup API Server
	go initHttp(privateKey)
	go initUpstreamProxyServer()
	go initDownstreamProxyServer()
}

func onetimeSSHDServer(t *testing.T) *exec.Cmd {
	sshdPath, err := exec.LookPath("sshd")
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(
		sshdPath, "-d",
		"-h", filepath.Join(cwd, "fixtures/ssh_host_ed25519_key"),
		"-p", fmt.Sprint(sshdServerAddr.Port),
		"-o", "AuthorizedKeysFile="+filepath.Join(cwd, "fixtures/ssh_id_rsa.pub"),
		"-o", "StrictModes=no")
	// Bind sshd to stderr, to quickly check if it goes wrong
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal("sshd: ", err)
	}
	return cmd
}

func waitForSSHD(t *testing.T, cmd *exec.Cmd) {
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 255 {
			// pass
		} else {
			t.Fatal("sshd: ", err)
		}
	}
}

func testWithSSHClient(t *testing.T, address *net.TCPAddr, description string, proxy bool) {
	enableProxy = proxy
	cmd := onetimeSSHDServer(t)
	time.Sleep(100 * time.Millisecond)
	sshCommand := exec.Command(
		"ssh", "-p", fmt.Sprint(address.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "ControlMaster=no",
		"-i", "fixtures/ssh_id_rsa",
		"-o", "IdentityAgent=no",
		address.IP.String(), "uname")
	sshCommand.Dir, _ = os.Getwd()
	if err := sshCommand.Run(); err != nil {
		t.Fatal(fmt.Sprintf("%s: ", description), err)
	}
	waitForSSHD(t, cmd)
}

func TestSSHClientConnection(t *testing.T) {
	initEnv(t)
	configFiles := []string{"config.toml", "legacy.toml", "config.json"}

	for _, configFile := range configFiles {
		// start sshmux server
		sshmux, err := sshmuxServer(filepath.Join("fixtures", configFile))
		if err != nil {
			t.Fatal(err)
		}
		err = sshmux.Start()
		if err != nil {
			t.Fatal(err)
		}
		defer sshmux.Shutdown()

		// sanity check
		testWithSSHClient(t, sshdServerAddr, "sanity check", false)

		// test sshmux
		testWithSSHClient(t, sshmuxServerAddr, "sshmux", false)

		// test sshmux with upstream proxy
		testWithSSHClient(t, sshmuxProxyAddr, "sshmux (proxied src)", false)

		// test sshmux with downstream proxy
		testWithSSHClient(t, sshmuxServerAddr, "sshmux (proxied dst)", true)

		// test sshmux with two-way proxy
		testWithSSHClient(t, sshmuxProxyAddr, "sshmux (proxied)", true)
	}
}
