// Copyright 2026 The sshmux Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"io"
	"testing"
)

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

					if err := pipe(dst, src, direction.handlePing); err != io.EOF {
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

	if err := pipe(dst, src, false); err != io.EOF {
		t.Fatalf("pipe returned %v, want EOF", err)
	}
	if len(dst.writes) != 1 || string(dst.writes[0]) != string(want) {
		t.Fatalf("forwarded packets = %v, want %v", dst.writes, want)
	}
	if len(src.writes) != 0 {
		t.Fatalf("responses = %v, want none", src.writes)
	}
}
