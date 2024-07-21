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

	"github.com/pires/go-proxyproto"
)

var sshmuxProxyAddr *net.TCPAddr = localhostTCPAddr(8122)
var sshmuxServerAddr *net.TCPAddr = localhostTCPAddr(8022)
var sshdProxyAddr *net.TCPAddr = localhostTCPAddr(2332)
var sshdServerAddr *net.TCPAddr = localhostTCPAddr(2333)
var apiServerAddr *net.TCPAddr = localhostTCPAddr(5000)

func localhostTCPAddr(port int) *net.TCPAddr {
	return &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: port,
	}
}

func mustGenerateKey(t *testing.T, path, typ string) {
	err := exec.Command("ssh-keygen", "-t", typ, "-f", path, "-N", "").Run()
	if err != nil {
		t.Fatal(err)
	}
}

var examplePrivate string
var enableProxy bool

func sshAPIHandler(w http.ResponseWriter, r *http.Request) {
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

	res := &AuthResponse{
		Status:     "ok",
		Id:         1141919,
		PrivateKey: examplePrivate,
	}
	if enableProxy {
		res.Address = sshdProxyAddr.String()
		res.Proxy = new(bool)
		*res.Proxy = true
	} else {
		res.Address = sshdServerAddr.String()
		res.Proxy = nil
	}

	jsonRes, err := json.Marshal(res)
	if err != nil {
		http.Error(w, "Cannot encode JSON", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonRes)
}

func initHttp() {
	http.HandleFunc("/ssh", sshAPIHandler)

	if err := http.ListenAndServe(apiServerAddr.String(), nil); err != nil {
		log.Fatal(err)
	}
}

func initUpstreamProxyServer() {
	listener, err := net.ListenTCP("tcp", sshmuxProxyAddr)
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			// 1. Set up downstream connection with sshmux
			downstream, err := net.DialTCP("tcp", nil, sshmuxServerAddr)
			if err != nil {
				log.Fatal(err)
			}
			// 2. Send PROXY header to downstream
			header := proxyproto.HeaderProxyFromAddrs(1, conn.RemoteAddr(), nil)
			_, err = header.WriteTo(downstream)
			if err != nil {
				log.Fatal(err)
			}
			// 3. Forward TCP messages in both ways
			go func() {
				defer downstream.Close()
				io.Copy(downstream, conn)
			}()
			go func() {
				defer downstream.Close()
				io.Copy(conn, downstream)
			}()
		}()
	}
}

func initDownstreamProxyServer() {
	listener, err := net.ListenTCP("tcp", sshdProxyAddr)
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
			downstream, err := net.DialTCP("tcp", nil, sshdServerAddr)
			if err != nil {
				log.Fatal(err)
			}
			// 2. Forward TCP messages in both ways
			go func() {
				defer downstream.Close()
				io.Copy(downstream, conn)
			}()
			go func() {
				defer downstream.Close()
				io.Copy(conn, downstream)
			}()
		}()
	}
}

func initEnv(t *testing.T, baseDir string) {
	// SSHD privilege separation directory
	os.MkdirAll("/run/sshd", 0o755)
	// Create host keys for sshd
	if err := os.RemoveAll(baseDir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.RemoveAll(baseDir)
	})
	mustGenerateKey(t, filepath.Join(baseDir, "ssh_host_rsa_key"), "rsa")
	mustGenerateKey(t, filepath.Join(baseDir, "ssh_host_ecdsa_key"), "ecdsa")
	mustGenerateKey(t, filepath.Join(baseDir, "ssh_host_ed25519_key"), "ed25519")

	examplePrivatePath := filepath.Join(baseDir, "example_rsa")
	mustGenerateKey(t, examplePrivatePath, "rsa")
	examplePrivateBytes, err := os.ReadFile(examplePrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	examplePrivate = string(examplePrivateBytes)

	// Setup API Server
	go initHttp()
	go initUpstreamProxyServer()
	go initDownstreamProxyServer()
}

func onetimeSSHDServer(t *testing.T, baseDir string) *exec.Cmd {
	sshdPath, err := exec.LookPath("sshd")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(
		sshdPath, "-d",
		"-h", filepath.Join(baseDir, "ssh_host_ed25519_key"),
		"-p", fmt.Sprint(sshdServerAddr.Port),
		"-o", "AuthorizedKeysFile="+filepath.Join(baseDir, "example_rsa.pub"),
		"-o", "StrictModes=no")
	cmd.Dir = baseDir
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

func sshCommand(address *net.TCPAddr, privateKeyPath string) *exec.Cmd {
	return exec.Command(
		"ssh", "-p", fmt.Sprint(address.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "ControlMaster=no",
		"-i", privateKeyPath,
		"-o", "IdentityAgent=no",
		address.IP.String(), "uname")
}

func testWithSSHClient(t *testing.T, address *net.TCPAddr, description string, proxy bool, baseDir, privateKeyPath string) {
	enableProxy = proxy
	cmd := onetimeSSHDServer(t, baseDir)
	time.Sleep(100 * time.Millisecond)
	err := sshCommand(address, privateKeyPath).Run()
	if err != nil {
		t.Fatal(fmt.Sprintf("%s: ", description), err)
	}
	waitForSSHD(t, cmd)
}

func TestSSHClientConnection(t *testing.T) {
	baseDir := "/tmp/sshmux"

	initEnv(t, baseDir)
	privateKeyPath := filepath.Join(baseDir, "example_rsa")
	go sshmuxServer("config.example.json")

	// sanity check
	testWithSSHClient(t, sshdServerAddr, "sanity check", false, baseDir, privateKeyPath)

	// test sshmux
	testWithSSHClient(t, sshmuxServerAddr, "sshmux", false, baseDir, privateKeyPath)

	// test sshmux with upstream proxy
	testWithSSHClient(t, sshmuxProxyAddr, "sshmux (proxied src)", false, baseDir, privateKeyPath)

	// test sshmux with downstream proxy
	testWithSSHClient(t, sshmuxServerAddr, "sshmux (proxied dst)", true, baseDir, privateKeyPath)

	// test sshmux with two-way proxy
	testWithSSHClient(t, sshmuxProxyAddr, "sshmux (proxied)", true, baseDir, privateKeyPath)
}
