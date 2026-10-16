// Copyright 2026 The sshmux Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

type authPacketTransport struct {
	connTransport
	scriptedPacketConn
	writeErr error
}

func (c *authPacketTransport) Close() error { return nil }

func (c *authPacketTransport) readPacket() ([]byte, error) {
	return c.scriptedPacketConn.readPacket()
}

func (c *authPacketTransport) writePacket(packet []byte) error {
	if c.writeErr != nil {
		return c.writeErr
	}
	return c.scriptedPacketConn.writePacket(packet)
}

func TestDownstreamPublicKeyQuery(t *testing.T) {
	rsaCert := &Certificate{
		Key: testPublicKeys["rsa"], CertType: UserCert,
		ValidBefore: CertTimeInfinity,
	}
	if err := rsaCert.SignCert(rand.Reader, testSigners["rsa"]); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		algo string
		key  PublicKey
	}{
		{KeyAlgoRSA, testPublicKeys["rsa"]},
		{KeyAlgoRSASHA256, testPublicKeys["rsa"]},
		{KeyAlgoRSASHA512, testPublicKeys["rsa"]},
		{CertAlgoRSAv01, rsaCert},
		{CertAlgoRSASHA256v01, rsaCert},
		{CertAlgoRSASHA512v01, rsaCert},
		{KeyAlgoED25519, testPublicKeys["ed25519"]},
		{KeyAlgoECDSA256, testPublicKeys["ecdsa"]},
	} {
		t.Run(tt.algo, func(t *testing.T) {
			keyBlob := tt.key.Marshal()
			query := Marshal(&publickeyAuthMsg{
				User: "test", Service: serviceSSH, Method: "publickey",
				Algoname: tt.algo, PubKey: keyBlob,
			})
			for _, skipQuery := range []bool{false, true} {
				transport := &authPacketTransport{scriptedPacketConn: scriptedPacketConn{
					reads: [][]byte{query, Marshal(&userAuthRequestMsg{
						User: "test", Service: serviceSSH, Method: "none",
					})},
				}}
				downstream := &Downstream{connection: &connection{transport: transport}}
				req, err := downstream.ReadAuthRequest(skipQuery)
				if err != nil {
					t.Fatal(err)
				}
				if !skipQuery {
					if !req.IsPublicKeyQuery || len(transport.writes) != 0 {
						t.Fatal("query should be returned without a reply")
					}
					continue
				}
				if req.Method != "none" || len(transport.writes) != 1 {
					t.Fatalf("method = %q, replies = %d", req.Method, len(transport.writes))
				}
				var reply userAuthPubKeyOkMsg
				if err := Unmarshal(transport.writes[0], &reply); err != nil {
					t.Fatal(err)
				}
				if reply.Algo != tt.algo || !bytes.Equal(reply.PubKey, keyBlob) {
					t.Fatalf("PK_OK did not echo query: algorithm = %q, want %q", reply.Algo, tt.algo)
				}
			}
		})
	}
}

func TestDownstreamPublicKeyQueryWriteError(t *testing.T) {
	wantErr := errors.New("write failed")
	transport := &authPacketTransport{
		scriptedPacketConn: scriptedPacketConn{reads: [][]byte{Marshal(&publickeyAuthMsg{
			User: "test", Service: serviceSSH, Method: "publickey",
			Algoname: KeyAlgoRSASHA512, PubKey: testPublicKeys["rsa"].Marshal(),
		})}},
		writeErr: wantErr,
	}
	downstream := &Downstream{connection: &connection{transport: transport}}
	if _, err := downstream.ReadAuthRequest(true); !errors.Is(err, wantErr) {
		t.Fatalf("ReadAuthRequest error = %v, want %v", err, wantErr)
	}
}

type scriptedPacketConn struct {
	reads  [][]byte
	writes [][]byte
}

func (c *scriptedPacketConn) readPacket() ([]byte, error) {
	if len(c.reads) == 0 {
		return nil, io.EOF
	}
	packet := c.reads[0]
	c.reads = c.reads[1:]
	return packet, nil
}

func (c *scriptedPacketConn) writePacket(packet []byte) error {
	c.writes = append(c.writes, append([]byte(nil), packet...))
	return nil
}

func (c *scriptedPacketConn) Close() error { return nil }

func TestPipeRejectsUpdateHostKeysRequestsInBothDirections(t *testing.T) {
	directions := []struct {
		name       string
		handlePing bool
	}{
		{name: "upstream to downstream"},
		{name: "downstream to upstream", handlePing: true},
	}
	requestTypes := []string{
		"hostkeys-00@openssh.com",
		"hostkeys-prove-00@openssh.com",
	}

	for _, direction := range directions {
		for _, requestType := range requestTypes {
			for _, wantReply := range []bool{false, true} {
				name := direction.name + "/" + requestType
				if wantReply {
					name += "/with reply"
				}
				t.Run(name, func(t *testing.T) {
					src := &scriptedPacketConn{reads: [][]byte{Marshal(&globalRequestMsg{
						Type:      requestType,
						WantReply: wantReply,
						Data:      []byte("host key data"),
					})}}
					dst := &scriptedPacketConn{}

					if _, err := pipe(dst, src, direction.handlePing); err != io.EOF {
						t.Fatalf("pipe returned %v, want EOF", err)
					}
					if len(dst.writes) != 0 {
						t.Fatalf("forwarded %q request", requestType)
					}
					if wantReply {
						if len(src.writes) != 1 || len(src.writes[0]) == 0 || src.writes[0][0] != msgRequestFailure {
							t.Fatalf("responses = %v, want one request failure", src.writes)
						}
					} else if len(src.writes) != 0 {
						t.Fatalf("responses = %v, want none", src.writes)
					}
				})
			}
		}
	}
}

func TestPipeForwardsOtherGlobalRequests(t *testing.T) {
	want := Marshal(&globalRequestMsg{
		Type:      "keepalive@openssh.com",
		WantReply: true,
		Data:      []byte("payload"),
	})
	src := &scriptedPacketConn{reads: [][]byte{want}}
	dst := &scriptedPacketConn{}

	if _, err := pipe(dst, src, false); err != io.EOF {
		t.Fatalf("pipe returned %v, want EOF", err)
	}
	if len(dst.writes) != 1 || string(dst.writes[0]) != string(want) {
		t.Fatalf("forwarded packets = %v, want %v", dst.writes, want)
	}
	if len(src.writes) != 0 {
		t.Fatalf("responses = %v, want none", src.writes)
	}
}
