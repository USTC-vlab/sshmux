package main

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/pires/go-proxyproto"
)

func mustGenerateKey(t *testing.T, path, typ string) {
	err := exec.Command("ssh-keygen", "-t", typ, "-f", path, "-N", "").Run()
	if err != nil {
		t.Fatal(err)
	}
}

var examplePrivate string

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
		Address:    "127.0.0.1:2332",
		Id:         1141919,
		PrivateKey: examplePrivate,
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

	if err := http.ListenAndServe("127.0.0.1:5000", nil); err != nil {
		log.Fatal(err)
	}
}

func initUpstreamProxyServer() {
	listener, err := net.Listen("tcp", "127.0.0.1:2222")
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
			target, err := net.ResolveTCPAddr("tcp", "127.0.0.1:8022")
			if err != nil {
				log.Fatal(err)
			}
			downstream, err := net.DialTCP("tcp", nil, target)
			if err != nil {
				log.Fatal(err)
			}
			// 2. Send PROXY header
			header := proxyproto.HeaderProxyFromAddrs(1, conn.RemoteAddr(), downstream.RemoteAddr())
			_, err = header.WriteTo(downstream)
			if err != nil {
				log.Fatal(err)
			}
			// 3. Forward TCP messages in a loop
			for {
				data := make([]byte, 0)
				_, err := conn.Read(data)
				if err != nil {
					if err == syscall.EINVAL {
						downstream.Close()
					} else {
						log.Print(err)
					}
					break
				}
				_, err = downstream.Write(data)
				if err != nil {
					log.Print(err)
					break
				}
			}
		}()
	}
}

func initDownstreamProxyServer() {
	listener, err := net.Listen("tcp", "127.0.0.1:2332")
	if err != nil {
		log.Fatal(err)
	}
	proxyListener := &proxyproto.Listener{Listener: listener}
	defer proxyListener.Close()

	for {
		conn, err := proxyListener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			// 1. Set up downstream connection with sshmux
			target, err := net.ResolveTCPAddr("tcp", "127.0.0.1:2333")
			if err != nil {
				log.Fatal(err)
			}
			downstream, err := net.DialTCP("tcp", nil, target)
			if err != nil {
				log.Fatal(err)
			}
			// 2. Forward TCP messages in a loop
			for {
				data := make([]byte, 0)
				_, err := conn.Read(data)
				if err != nil {
					if err == syscall.EINVAL {
						downstream.Close()
					} else {
						log.Print(err)
					}
					break
				}
				_, err = downstream.Write(data)
				if err != nil {
					log.Print(err)
					break
				}
			}
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
		"-p", "2333",
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

func sshCommand(port, privateKeyPath string) *exec.Cmd {
	return exec.Command(
		"ssh", "-p", port,
		"-o", "StrictHostKeyChecking=no",
		"-o", "ControlMaster=no",
		"-i", privateKeyPath,
		"-o", "IdentityAgent=no",
		"localhost", "uname")
}

func TestSSHClientConnection(t *testing.T) {
	sleepDuration := 100 * time.Millisecond
	baseDir := "/tmp/sshmux"

	initEnv(t, baseDir)
	privateKeyPath := filepath.Join(baseDir, "example_rsa")
	go sshmuxServer("config.example.json")

	// Sanity check
	cmd := onetimeSSHDServer(t, baseDir)
	time.Sleep(sleepDuration)
	err := sshCommand("2333", privateKeyPath).Run()
	if err != nil {
		t.Fatal("sanity check: ", err)
	}
	waitForSSHD(t, cmd)

	cmd = onetimeSSHDServer(t, baseDir)
	time.Sleep(sleepDuration)
	err = sshCommand("2222", privateKeyPath).Run()
	if err != nil {
		t.Fatal("ssh: ", err)
	}
	waitForSSHD(t, cmd)
}
