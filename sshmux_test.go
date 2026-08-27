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
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"
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
var enablePartialAuth bool
var inited bool

// partialAuthToken is the answer expected by the auth API when partial auth is
// enabled, before it hands out any upstream information.
const partialAuthToken = "testtoken"

// checkClientInfo validates the client information sshmux reports on an auth
// request, and describes the first problem found, if any.
func checkClientInfo(request AuthRequest) string {
	host, port, err := net.SplitHostPort(request.ClientAddress)
	if err != nil {
		return fmt.Sprintf("malformed client address %q", request.ClientAddress)
	}
	// every test client connects from localhost, including the ones whose
	// address only survives in the PROXY header
	if host != "127.0.0.1" || port == "0" {
		return fmt.Sprintf("unexpected client address %q", request.ClientAddress)
	}
	if !strings.HasPrefix(request.ClientVersion, "SSH-2.0-") {
		return fmt.Sprintf("unexpected client version %q", request.ClientVersion)
	}
	if request.SessionID == "" {
		return "missing session ID"
	}
	return ""
}

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

		res := map[string]any{
			"status":      "ok",
			"vmid":        1141919,
			"private_key": string(sshPrivateKey),
		}
		if enableProxy {
			res["address"] = sshdProxiedAddr.String()
			res["proxy_protocol"] = 2
		} else {
			res["address"] = sshdServerAddr.String()
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
		var req AuthRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Not an auth request", http.StatusBadRequest)
			return
		}
		if problem := checkClientInfo(req); problem != "" {
			// the message reaches the SSH client, but log it as well to explain
			// the connection failure the test will report
			log.Printf("auth API: %s", problem)
			failure := AuthFailure{Message: problem, Disconnect: true}
			jsonRes, err := json.Marshal(AuthResponse{Failure: &failure})
			if err != nil {
				http.Error(w, "Cannot encode JSON", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			w.Write(jsonRes)
			return
		}

		if enablePartialAuth {
			deny := func(message string) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"failure":{"message":"` + message + `"}}`))
			}
			// The public key identifies the user, and must be carried over to the
			// requests that follow its acceptance.
			if req.PublicKey == "" {
				deny("public key required")
				return
			}
			switch req.Method {
			case "publickey":
				// Partially accept the public key, and ask for the token over
				// keyboard-interactive.
				res := map[string]any{
					"challenges": []map[string]any{{
						"instruction": "Please enter your token.",
						"fields": []map[string]any{
							{"key": "token", "prompt": "Token: ", "secret": true},
						},
					}},
				}
				jsonRes, err := json.Marshal(res)
				if err != nil {
					http.Error(w, "Cannot encode JSON", http.StatusInternalServerError)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.Write(jsonRes)
				return
			case "keyboard-interactive":
				// The challenges are answered on the follow-up request, which the
				// partial success has sent the user to.
				if req.Payload["token"] != partialAuthToken {
					deny("invalid token")
					return
				}
			default:
				deny("unsupported auth method")
				return
			}
		}

		res := map[string]any{
			"upstream": map[string]any{
				"host":        sshdServerAddr.IP.String(),
				"port":        sshdServerAddr.Port,
				"private_key": string(sshPrivateKey),
			},
		}
		if enableProxy {
			res["proxy"] = map[string]any{
				"host": sshdProxiedAddr.IP.String(),
				"port": sshdProxiedAddr.Port,
			}
		}

		jsonRes, err := json.Marshal(res)
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
	if inited {
		return
	}
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
	inited = true
}

func onetimeSSHDServer(t *testing.T) *exec.Cmd {
	t.Helper()

	sshdPath, err := exec.LookPath("sshd")
	if err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.ListenTCP("tcp", localhostTCPAddr(0))
	if err != nil {
		t.Fatal("allocate sshd port: ", err)
	}
	sshdServerAddr.Port = listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal("release sshd port: ", err)
	}

	cmd := exec.Command(
		sshdPath, "-D", "-e",
		"-h", filepath.Join(cwd, "fixtures/ssh_host_ed25519_key"),
		"-p", fmt.Sprint(sshdServerAddr.Port),
		"-o", "AuthorizedKeysFile="+filepath.Join(cwd, "fixtures/ssh_id_rsa.pub"),
		"-o", "StrictModes=no")
	// Bind sshd to stderr, to quickly check if it goes wrong
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal("sshd: ", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", sshdServerAddr.String(), 50*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		if cmd.ProcessState != nil || time.Now().After(deadline) {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatalf("sshd did not become ready on %s: %v", sshdServerAddr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cmd
}

func stopSSHD(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Kill(); err != nil && !strings.Contains(err.Error(), "process already finished") {
		t.Error("stop sshd: ", err)
	}
	if err := cmd.Wait(); err != nil {
		if _, ok := err.(*exec.ExitError); !ok {
			t.Error("wait for sshd: ", err)
		}
	}
}

func testWithSSHClient(t *testing.T, address *net.TCPAddr, description string, proxy bool) {
	enableProxy = proxy
	cmd := onetimeSSHDServer(t)
	defer stopSSHD(t, cmd)
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
}

func testWithGolangSSHChallengeClient(t *testing.T, address *net.TCPAddr, description string, proxy bool) {
	challenge := func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		answers = make([]string, len(questions))
		for i, q := range questions {
			if strings.Contains(q, "Vlab username") {
				answers[i] = "testuser"
			} else if strings.Contains(q, "Vlab password") {
				answers[i] = "testpassword"
			} else if strings.Contains(q, "UNIX password") {
				answers[i] = "testunixpassword"
			} else {
				t.Fatalf("Unexpected question: %s", q)
			}
		}
		return answers, nil
	}

	enableProxy = proxy
	cmd := onetimeSSHDServer(t)
	defer stopSSHD(t, cmd)

	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}

	config := &ssh.ClientConfig{
		User: currentUser.Username,
		Auth: []ssh.AuthMethod{
			ssh.KeyboardInteractive(challenge),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", address.String(), config)
	if err != nil {
		t.Fatal(fmt.Sprintf("%s: failed to dial: ", description), err)
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(fmt.Sprintf("%s: failed to create session: ", description), err)
	}

	if err := session.Run("uname"); err != nil {
		t.Fatal(fmt.Sprintf("%s: failed to run command: ", description), err)
	}

	session.Close()
	client.Close()

}

func testWithGolangSSHPartialAuthClient(t *testing.T, address *net.TCPAddr, description string, proxy bool) {
	challenged := false
	challenge := func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
		challenged = true
		answers = make([]string, len(questions))
		for i, q := range questions {
			if strings.Contains(q, "Token") {
				answers[i] = partialAuthToken
			} else {
				t.Fatalf("Unexpected question: %s", q)
			}
		}
		return answers, nil
	}

	enableProxy = proxy
	enablePartialAuth = true
	defer func() { enablePartialAuth = false }()
	cmd := onetimeSSHDServer(t)
	defer stopSSHD(t, cmd)

	privateKey, err := os.ReadFile("fixtures/ssh_id_rsa")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("failed to get current user: %v", err)
	}

	config := &ssh.ClientConfig{
		User: currentUser.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.KeyboardInteractive(challenge),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", address.String(), config)
	if err != nil {
		t.Fatal(fmt.Sprintf("%s: failed to dial: ", description), err)
	}

	if !challenged {
		t.Fatalf("%s: expected a keyboard-interactive challenge after partial success", description)
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal(fmt.Sprintf("%s: failed to create session: ", description), err)
	}

	if err := session.Run("uname"); err != nil {
		t.Fatal(fmt.Sprintf("%s: failed to run command: ", description), err)
	}

	session.Close()
	client.Close()

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

func TestLegacySSHChallengeClientConnection(t *testing.T) {
	initEnv(t)
	configFiles := []string{"legacy.toml", "config.json"}

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

		// we can't do sanity check here as default ssh server does not support challenge-response authentication

		// test sshmux
		testWithGolangSSHChallengeClient(t, sshmuxServerAddr, "sshmux", false)

		// test sshmux with upstream proxy
		testWithGolangSSHChallengeClient(t, sshmuxProxyAddr, "sshmux (proxied src)", false)

		// test sshmux with downstream proxy
		testWithGolangSSHChallengeClient(t, sshmuxServerAddr, "sshmux (proxied dst)", true)

		// test sshmux with two-way proxy
		testWithGolangSSHChallengeClient(t, sshmuxProxyAddr, "sshmux (proxied)", true)
	}
}

func TestSSHPartialAuthChallengeClientConnection(t *testing.T) {
	initEnv(t)

	// start sshmux server
	sshmux, err := sshmuxServer(filepath.Join("fixtures", "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	err = sshmux.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer sshmux.Shutdown()

	// test sshmux
	testWithGolangSSHPartialAuthClient(t, sshmuxServerAddr, "sshmux", false)

	// test sshmux with upstream proxy
	testWithGolangSSHPartialAuthClient(t, sshmuxProxyAddr, "sshmux (proxied src)", false)

	// test sshmux with downstream proxy
	testWithGolangSSHPartialAuthClient(t, sshmuxServerAddr, "sshmux (proxied dst)", true)

	// test sshmux with two-way proxy
	testWithGolangSSHPartialAuthClient(t, sshmuxProxyAddr, "sshmux (proxied)", true)
}
