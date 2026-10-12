package main

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func bridgeTCP(a, b net.Conn, mirrorFn func([]byte)) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = copyWithMirror(b, a, mirrorFn)
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		_, _ = copyWithMirror(a, b, nil)
		closeWrite(a)
	}()
	wg.Wait()
}

// TestTCPHalfCloseThroughBridge checks that CloseWrite on one leg is visible as
// EOF on the peer after copyWithMirror + closeWrite bridging.
func TestTCPHalfCloseThroughBridge(t *testing.T) {
	client, proxyIn := tcpPair(t)
	proxyOut, server := tcpPair(t)

	done := make(chan struct{})
	go func() {
		bridgeTCP(proxyIn, proxyOut, nil)
		close(done)
	}()

	serverDone := make(chan []byte, 1)
	go func() {
		buf, err := io.ReadAll(server)
		if err != nil {
			t.Errorf("server read: %v", err)
		}
		serverDone <- buf
	}()

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if err := client.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	var payload []byte
	select {
	case payload = <-serverDone:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive request in time")
	}
	if string(payload) != "ping" {
		t.Fatalf("server got %q, want ping", payload)
	}

	if _, err := server.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	if err := server.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	resp, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp) != "pong" {
		t.Fatalf("client got %q, want pong", resp)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("bridge did not finish in time")
	}

	client.Close()
	proxyIn.Close()
	proxyOut.Close()
	server.Close()
}
