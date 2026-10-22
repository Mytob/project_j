//go:build linux

package main

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerUIDUsesKernelUnixCredentials(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "peer.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- connection
	}()
	client, err := net.Dial("unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case connection := <-accepted:
		defer connection.Close()
		uid, err := peerUID(connection)
		if err != nil {
			t.Fatal(err)
		}
		if uid != uint32(os.Geteuid()) {
			t.Fatalf("peer UID = %d, want kernel-reported process UID %d", uid, os.Geteuid())
		}
	case err := <-acceptErr:
		t.Fatal(err)
	}
}
