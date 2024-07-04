package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func mustGenerateKey(path string, typ string) {
	err := exec.Command("ssh-keygen", "-t", typ, "-f", path, "-N", "").Run()
	if err != nil {
		log.Fatal(err)
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
		Address:    "127.0.0.1:2333",
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

func initEnv(t *testing.T, baseDir string) {
	// Create host keys for sshd
	mustGenerateKey(filepath.Join(baseDir, "ssh_host_rsa_key"), "rsa")
	mustGenerateKey(filepath.Join(baseDir, "ssh_host_ecdsa_key"), "ecdsa")
	mustGenerateKey(filepath.Join(baseDir, "ssh_host_ed25519_key"), "ed25519")

	examplePrivatePath := filepath.Join(baseDir, "example_rsa")
	mustGenerateKey(examplePrivatePath, "rsa")
	examplePrivateBytes, err := os.ReadFile(examplePrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	examplePrivate = string(examplePrivateBytes)

	// Setup API Server
	go initHttp()
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
	baseDir := t.TempDir()

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
	err = sshCommand("8022", privateKeyPath).Run()
	if err != nil {
		t.Fatal("ssh: ", err)
	}
	waitForSSHD(t, cmd)
}
