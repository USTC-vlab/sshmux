package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/julienschmidt/httprouter"
	"github.com/pires/go-proxyproto"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	tracev1 "go.opentelemetry.io/proto/otlp/trace/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

// The addresses of the services making up the test environment. None of them
// is known before the service is bound: every port is picked by the kernel, so
// that concurrent packages and back-to-back runs cannot collide.
var (
	// the auth API sshmux asks about every connection
	apiServerAddr *net.TCPAddr
	// sshmux itself, restarted for each configuration under test
	sshmuxServerAddr *net.TCPAddr
	// a PROXY protocol server in front of sshmux, standing in for a load balancer
	sshmuxProxyAddr *net.TCPAddr
	// the sshd the auth API hands out, restarted for each connection test
	sshdServerAddr *net.TCPAddr
	// a PROXY protocol server in front of sshd, for proxied upstreams
	sshdProxiedAddr *net.TCPAddr
)

// proxySourceIP is the address the PROXY protocol server in front of sshmux
// connects from. The fixtures name it as the one host sshmux accepts PROXY
// headers from, and it has to differ from the client's own 127.0.0.1 for the
// tests to tell a header sshmux honoured from one it ignored.
var proxySourceIP = net.IPv4(127, 0, 0, 22)

// Linux routes the whole of 127.0.0.0/8 to the loopback interface. macOS
// configures 127.0.0.1 alone and rejects the rest with EADDRNOTAVAIL unless an
// alias has been added by hand, so that is the one place worth asking.
var proxySourceAvailable = runtime.GOOS != "darwin" || canBindProxySource()

func canBindProxySource() bool {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: proxySourceIP})
	if err != nil {
		return false
	}
	listener.Close()
	return true
}

// requireProxySource skips a test that reaches sshmux through the PROXY
// protocol server, on a machine where that server cannot have an address of
// its own.
func requireProxySource(t *testing.T) {
	t.Helper()
	if !proxySourceAvailable {
		t.Skipf("%s is not a local address (macOS: sudo ifconfig lo0 alias %s up)", proxySourceIP, proxySourceIP)
	}
}

// listenLocalhost binds a loopback port chosen by the kernel. Callers read the
// address it landed on back off the listener.
func listenLocalhost(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen: ", err)
	}
	return listener
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

// serveAPI answers auth requests on listener until it fails.
func serveAPI(listener net.Listener, sshPrivateKey []byte) {
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

	if err := http.Serve(listener, router); err != nil {
		log.Fatal(err)
	}
}

// serveUpstreamProxy forwards connections on listener to sshmux, prefixed
// with a PROXY header naming their origin.
func serveUpstreamProxy(listener net.Listener) {
	defer listener.Close()

	localAddr := &net.TCPAddr{IP: proxySourceIP}

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

// serveDownstreamProxy forwards connections on listener to sshd, requiring a
// PROXY header from sshmux.
func serveDownstreamProxy(listener net.Listener) {
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

// startServer starts sshmux from a fixture and records the address it listens
// on.
func startServer(t *testing.T, configFile string, adjust ...func(*Config)) *Server {
	t.Helper()
	config, err := loadConfig(filepath.Join("fixtures", configFile))
	if err != nil {
		t.Fatal(err)
	}

	// The ports in the fixtures are there to read as realistic examples; the
	// server belongs on the ones this run actually uses.
	config.Address = "127.0.0.1:0"
	endpoint, err := url.Parse(config.Auth.Endpoint)
	if err != nil {
		t.Fatal("parse auth endpoint: ", err)
	}
	endpoint.Host = apiServerAddr.String()
	config.Auth.Endpoint = endpoint.String()
	for _, adjust := range adjust {
		adjust(&config)
	}

	sshmux, err := makeServer(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshmux.Start(); err != nil {
		t.Fatal(err)
	}
	sshmuxServerAddr = sshmux.Addr().(*net.TCPAddr)
	return sshmux
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

	// Bind each service before starting it, so that the address it landed on
	// is known by the time the tests, the fixtures and the other services are
	// pointed at it.
	apiListener := listenLocalhost(t)
	apiServerAddr = apiListener.Addr().(*net.TCPAddr)
	go serveAPI(apiListener, privateKey)

	upstreamProxyListener := listenLocalhost(t)
	sshmuxProxyAddr = upstreamProxyListener.Addr().(*net.TCPAddr)
	go serveUpstreamProxy(upstreamProxyListener)

	downstreamProxyListener := listenLocalhost(t)
	sshdProxiedAddr = downstreamProxyListener.Addr().(*net.TCPAddr)
	go serveDownstreamProxy(downstreamProxyListener)

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
	// sshd binds the port itself, so hold one only long enough to learn a
	// number nothing else on the machine is using.
	listener := listenLocalhost(t)
	sshdServerAddr = listener.Addr().(*net.TCPAddr)
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

// runSSHClient runs a command over the system ssh client against address.
func runSSHClient(t *testing.T, address *net.TCPAddr) {
	t.Helper()
	sshCommand := exec.Command(
		"ssh", "-p", fmt.Sprint(address.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "ControlMaster=no",
		"-i", "fixtures/ssh_id_rsa",
		"-o", "IdentityAgent=no",
		address.IP.String(), "uname")
	sshCommand.Dir, _ = os.Getwd()
	if err := sshCommand.Run(); err != nil {
		t.Fatal("ssh: ", err)
	}
}

// sanityCheckSSHD talks to a throwaway sshd directly, so that a broken
// environment can be told apart from a broken sshmux.
func sanityCheckSSHD(t *testing.T) {
	t.Helper()
	enableProxy = false
	cmd := onetimeSSHDServer(t)
	defer stopSSHD(t, cmd)
	runSSHClient(t, sshdServerAddr)
}

func testWithSSHClient(t *testing.T, address *net.TCPAddr, proxy bool) {
	t.Helper()
	enableProxy = proxy
	cmd := onetimeSSHDServer(t)
	defer stopSSHD(t, cmd)
	runSSHClient(t, address)
}

func testWithGolangSSHChallengeClient(t *testing.T, address *net.TCPAddr, proxy bool) {
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
		t.Fatal("failed to dial: ", err)
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal("failed to create session: ", err)
	}

	if err := session.Run("uname"); err != nil {
		t.Fatal("failed to run command: ", err)
	}

	session.Close()
	client.Close()

}

func testWithGolangSSHPartialAuthClient(t *testing.T, address *net.TCPAddr, proxy bool) {
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
		t.Fatal("failed to dial: ", err)
	}

	if !challenged {
		t.Fatal("expected a keyboard-interactive challenge after partial success")
	}

	session, err := client.NewSession()
	if err != nil {
		t.Fatal("failed to create session: ", err)
	}

	if err := session.Run("uname"); err != nil {
		t.Fatal("failed to run command: ", err)
	}

	session.Close()
	client.Close()

}

func TestSSHClientConnection(t *testing.T) {
	initEnv(t)
	configFiles := []string{"config.toml", "legacy.toml", "config.json"}

	for _, configFile := range configFiles {
		t.Run(configFile, func(t *testing.T) {
			sshmux := startServer(t, configFile)
			defer sshmux.Shutdown()

			t.Run("sshd", func(t *testing.T) {
				sanityCheckSSHD(t)
			})
			t.Run("sshmux", func(t *testing.T) {
				testWithSSHClient(t, sshmuxServerAddr, false)
			})
			t.Run("proxied src", func(t *testing.T) {
				requireProxySource(t)
				testWithSSHClient(t, sshmuxProxyAddr, false)
			})
			t.Run("proxied dst", func(t *testing.T) {
				testWithSSHClient(t, sshmuxServerAddr, true)
			})
			t.Run("proxied both ways", func(t *testing.T) {
				requireProxySource(t)
				testWithSSHClient(t, sshmuxProxyAddr, true)
			})
		})
	}
}

func TestLegacySSHChallengeClientConnection(t *testing.T) {
	initEnv(t)
	configFiles := []string{"legacy.toml", "config.json"}

	// there is no sanity check here: the default ssh server does not support
	// challenge-response authentication
	for _, configFile := range configFiles {
		t.Run(configFile, func(t *testing.T) {
			sshmux := startServer(t, configFile)
			defer sshmux.Shutdown()

			t.Run("sshmux", func(t *testing.T) {
				testWithGolangSSHChallengeClient(t, sshmuxServerAddr, false)
			})
			t.Run("proxied src", func(t *testing.T) {
				requireProxySource(t)
				testWithGolangSSHChallengeClient(t, sshmuxProxyAddr, false)
			})
			t.Run("proxied dst", func(t *testing.T) {
				testWithGolangSSHChallengeClient(t, sshmuxServerAddr, true)
			})
			t.Run("proxied both ways", func(t *testing.T) {
				requireProxySource(t)
				testWithGolangSSHChallengeClient(t, sshmuxProxyAddr, true)
			})
		})
	}
}

func TestSSHPartialAuthChallengeClientConnection(t *testing.T) {
	initEnv(t)

	sshmux := startServer(t, "config.toml")
	defer sshmux.Shutdown()

	t.Run("sshmux", func(t *testing.T) {
		testWithGolangSSHPartialAuthClient(t, sshmuxServerAddr, false)
	})
	t.Run("proxied src", func(t *testing.T) {
		requireProxySource(t)
		testWithGolangSSHPartialAuthClient(t, sshmuxProxyAddr, false)
	})
	t.Run("proxied dst", func(t *testing.T) {
		testWithGolangSSHPartialAuthClient(t, sshmuxServerAddr, true)
	})
	t.Run("proxied both ways", func(t *testing.T) {
		requireProxySource(t)
		testWithGolangSSHPartialAuthClient(t, sshmuxProxyAddr, true)
	})
}

// startMetricsServer starts sshmux with the metrics fixture, adjusted to the
// addresses this run actually uses and to the exporter these tests read from.
func startMetricsServer(t *testing.T) *Server {
	t.Helper()
	return startServer(t, "metrics.toml", func(config *Config) {
		// The fixture exercises the configuration surface, not these tests: it
		// names an OTLP collector that is not listening, a fixed Prometheus
		// port, and turns off the connection grouping the assertions read.
		config.Metrics.OTLP.Enabled = false
		config.Metrics.Prometheus.Address = "127.0.0.1:0"
		config.Metrics.ConnectionGrouping = nil
	})
}

// dropConnection connects to address and hangs up without saying anything.
func dropConnection(t *testing.T, address *net.TCPAddr) {
	t.Helper()
	conn, err := net.Dial("tcp", address.String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
}

// scrapeUntil polls the Prometheus endpoint until want shows up, since a
// session is only recorded once its handler winds down.
func scrapeUntil(t *testing.T, metrics *Metrics, want string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var body string
	for time.Now().Before(deadline) {
		body = scrape(t, metrics)
		if strings.Contains(body, want) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return body
}

// testSessionMetrics checks that a connection that went away before the SSH
// handshake is still accounted for as an accepted and then failed session.
func testSessionMetrics(t *testing.T, metrics *Metrics) {
	t.Helper()
	body := scrapeUntil(t, metrics, "sshmux_sessions_total{")
	for _, want := range []string{
		`sshmux_connections_total 1`,
		`sshmux_connections_active 0`,
		`sshmux_sessions_total{`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape output does not contain %q:\n%s", want, body)
		}
	}
}

// testUpstreamMetrics checks that the backend address the auth API returned
// reaches the metrics.
func testUpstreamMetrics(t *testing.T, metrics *Metrics) {
	t.Helper()
	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`sshmux_sessions_total{event_outcome="success",server_address=%q,server_port="%d",user_name=%q} 1`,
		sshdServerAddr.IP.String(), sshdServerAddr.Port, currentUser.Username)
	if body := scrapeUntil(t, metrics, want); !strings.Contains(body, want) {
		t.Errorf("scrape output does not contain %q:\n%s", want, body)
	}
}

// TestServerMetricsWiring checks that a connection served by the real server
// shows up in the exported metrics, i.e. that the instruments are wired into
// the connection handler and not just reachable in isolation.
func TestServerMetricsWiring(t *testing.T) {
	initEnv(t)

	sshmux := startMetricsServer(t)
	defer sshmux.Shutdown()

	t.Run("dropped connection", func(t *testing.T) {
		dropConnection(t, sshmuxServerAddr)
		testSessionMetrics(t, sshmux.Metrics)
	})
}

// TestServerMetricsUpstreamGrouping drives a real SSH client through sshmux and
// checks that the backend address the auth API returned reaches the metrics.
func TestServerMetricsUpstreamGrouping(t *testing.T) {
	initEnv(t)

	sshmux := startMetricsServer(t)
	defer sshmux.Shutdown()

	t.Run("sshmux", func(t *testing.T) {
		testWithSSHClient(t, sshmuxServerAddr, false)
		testUpstreamMetrics(t, sshmux.Metrics)
	})
}

func collectSpans(t *testing.T) (*httptest.Server, func() []*tracev1.Span) {
	t.Helper()
	var mu sync.Mutex
	var spans []*tracev1.Span
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		var request collectortrace.ExportTraceServiceRequest
		if err := proto.Unmarshal(body, &request); err != nil {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				spans = append(spans, scope.Spans...)
			}
		}
	}))
	t.Cleanup(server.Close)
	return server, func() []*tracev1.Span {
		mu.Lock()
		defer mu.Unlock()
		return append([]*tracev1.Span(nil), spans...)
	}
}

// startTracerServer starts sshmux with the tracer fixture, pointed at a
// collector these tests can read back.
func startTracerServer(t *testing.T, collector *httptest.Server) *Server {
	t.Helper()
	return startServer(t, "tracer.toml", func(config *Config) {
		// The fixture exercises the configuration surface, not these tests: it
		// names a gRPC collector, samples a quarter of traces, which would make
		// the assertions intermittent, and asks for the ECS attribute names,
		// which spell the application protocol differently.
		config.Tracer.OTLP.Protocol = "http"
		config.Tracer.OTLP.Endpoint = collector.URL + "/v1/traces"
		config.Tracer.SampleRatio = nil
		config.Tracer.Convention = AttributeConventionDefault
	})
}

// flushSpans exports whatever the batcher is holding, so that the spans of a
// finished session can be inspected without shutting the server down.
func flushSpans(t *testing.T, sshmux *Server) {
	t.Helper()
	if err := sshmux.Tracer.ForceFlush(t.Context()); err != nil {
		t.Fatal("flush spans: ", err)
	}
}

// testWithHeldSSHClient brings a session up and runs check while the client is
// still connected, so that what reached the collector mid-session can be told
// apart from what only arrives once the session closes.
func testWithHeldSSHClient(t *testing.T, address *net.TCPAddr, check func()) {
	t.Helper()
	enableProxy = false
	cmd := onetimeSSHDServer(t)
	defer stopSSHD(t, cmd)

	key, err := os.ReadFile("fixtures/ssh_id_rsa")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal("parse client key: ", err)
	}
	currentUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	client, err := ssh.Dial("tcp", address.String(), &ssh.ClientConfig{
		User:            currentUser.Username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatal("failed to dial: ", err)
	}
	defer client.Close()

	check()
}

// awaitSpans flushes until want spans have been exported: the server finishes
// the last of them just after the client sees the session come up.
func awaitSpans(t *testing.T, sshmux *Server, spans func() []*tracev1.Span, want int) []*tracev1.Span {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var exported []*tracev1.Span
	for time.Now().Before(deadline) {
		flushSpans(t, sshmux)
		if exported = spans(); len(exported) >= want {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return exported
}

// spanHasAttribute reports whether a span carries key.
// spanNames reports the names of spans, for a failed assertion to show.
func spanNames(spans []*tracev1.Span) []string {
	names := make([]string, 0, len(spans))
	for _, span := range spans {
		names = append(names, span.Name)
	}
	return names
}

func spanHasAttribute(span *tracev1.Span, key string) bool {
	for _, attr := range span.Attributes {
		if attr.Key == key {
			return true
		}
	}
	return false
}

// testSpanTree checks that a session produced the expected spans, and that
// they nest under one another.
func testSpanTree(t *testing.T, spans []*tracev1.Span) {
	t.Helper()

	byName := map[string]*tracev1.Span{}
	for _, span := range spans {
		byName[span.Name] = span
	}
	for _, want := range []string{"establish ssh session", "ssh handshake", "authenticate user", "connect upstream"} {
		if _, ok := byName[want]; !ok {
			t.Errorf("no %q span was exported; got %v", want, slices.Sorted(maps.Keys(byName)))
		}
	}
	session, handshake := byName["establish ssh session"], byName["ssh handshake"]
	if session == nil || handshake == nil {
		t.Fatal("missing the spans needed to check nesting")
	}
	if len(session.ParentSpanId) != 0 {
		t.Error(`"establish ssh session" has a parent, want it to be the trace root`)
	}
	if !bytes.Equal(handshake.ParentSpanId, session.SpanId) {
		t.Error(`"ssh handshake" is not a child of "establish ssh session"`)
	}
	if auth := byName["authenticate user"]; auth != nil && !bytes.Equal(auth.ParentSpanId, handshake.SpanId) {
		t.Error(`"authenticate user" is not a child of "ssh handshake"`)
	}
	// A collector builds its service graph out of the kinds, so the session
	// sshmux serves and the calls it makes on that session's behalf have to be
	// told apart.
	if session.Kind != tracev1.Span_SPAN_KIND_SERVER {
		t.Errorf("session span kind = %v, want SPAN_KIND_SERVER", session.Kind)
	}
	for _, name := range []string{"authenticate user", "connect upstream"} {
		if span := byName[name]; span != nil && span.Kind != tracev1.Span_SPAN_KIND_CLIENT {
			t.Errorf("%q span kind = %v, want SPAN_KIND_CLIENT", name, span.Kind)
		}
	}
	// Which addresses a span names follows from its kind: the session is
	// reached from a client, the auth and dial spans reach out to a server.
	wantAttributes := map[string][]string{
		"establish ssh session": {
			"network.protocol.name", "network.protocol.version",
			"user.name",
			"client.address", "client.port",
			"network.peer.address", "network.peer.port",
		},
		"authenticate user": {"server.address", "server.port", "network.peer.address", "network.peer.port"},
		"connect upstream":  {"server.address", "server.port", "network.peer.address", "network.peer.port"},
	}
	for name, keys := range wantAttributes {
		span := byName[name]
		if span == nil {
			continue
		}
		for _, key := range keys {
			if !spanHasAttribute(span, key) {
				t.Errorf("%q span carries no %q attribute", name, key)
			}
		}
	}
	if handshake := byName["ssh handshake"]; handshake != nil {
		// An internal span covers no connection, so it has no peer to name.
		for _, key := range []string{"network.peer.address", "network.peer.port"} {
			if spanHasAttribute(handshake, key) {
				t.Errorf(`"ssh handshake" carries %q, want no peer on an internal span`, key)
			}
		}
	}
	for name, span := range byName {
		if !bytes.Equal(span.TraceId, session.TraceId) {
			t.Errorf("%q is in a different trace from the session", name)
		}
	}
}

func TestServerSpans(t *testing.T) {
	initEnv(t)

	collector, spans := collectSpans(t)
	sshmux := startTracerServer(t, collector)
	defer sshmux.Shutdown()

	t.Run("sshmux", func(t *testing.T) {
		testWithHeldSSHClient(t, sshmuxServerAddr, func() {
			// Every span of the session has to be exported while the client is
			// still connected: a span left open for the life of a session is
			// held in memory and never reaches the collector.
			testSpanTree(t, awaitSpans(t, sshmux, spans, 4))
		})
	})
}

func TestSSHProtocolVersion(t *testing.T) {
	cases := []struct{ identification, want string }{
		{"SSH-2.0-OpenSSH_9.9", "2.0"},
		// The software version is free to carry more dashes, and comments.
		{"SSH-2.0-Go-1.2 some comment", "2.0"},
		{"SSH-1.99-OpenSSH_3.9", "1.99"},
		{"SSH-2.0-", "2.0"},
		{"", ""},
		{"SSH-2.0", ""},
		{"HTTP/1.1-nonsense-here", ""},
	}
	for _, tc := range cases {
		if got := sshProtocolVersion(tc.identification); got != tc.want {
			t.Errorf("sshProtocolVersion(%q) = %q, want %q", tc.identification, got, tc.want)
		}
	}
}

// testFailedSessionSpan checks the span of a connection that never reached the
// SSH transport: there is one, it is the session span, and it failed.
func testFailedSessionSpan(t *testing.T, spans []*tracev1.Span) {
	t.Helper()
	if len(spans) != 1 {
		t.Fatalf("%d spans were exported, want 1: %v", len(spans), spanNames(spans))
	}
	span := spans[0]
	if span.Name != "establish ssh session" {
		t.Errorf("the span is %q, want %q", span.Name, "establish ssh session")
	}
	if span.Kind != tracev1.Span_SPAN_KIND_SERVER {
		t.Errorf("span kind = %v, want SPAN_KIND_SERVER", span.Kind)
	}
	if span.Status.GetCode() != tracev1.Status_STATUS_CODE_ERROR {
		t.Errorf("span status = %v, want STATUS_CODE_ERROR", span.Status.GetCode())
	}
	for _, key := range []string{"client.address", "client.port", "network.peer.address"} {
		if !spanHasAttribute(span, key) {
			t.Errorf("the span carries no %q attribute", key)
		}
	}
}

// TestServerSpanWithoutSession checks that a connection dropped before the SSH
// transport is up is still traced, rather than only counted.
func TestServerSpanWithoutSession(t *testing.T) {
	initEnv(t)

	collector, spans := collectSpans(t)
	sshmux := startTracerServer(t, collector)
	defer sshmux.Shutdown()

	t.Run("dropped connection", func(t *testing.T) {
		dropConnection(t, sshmuxServerAddr)
		testFailedSessionSpan(t, awaitSpans(t, sshmux, spans, 1))
	})
}
