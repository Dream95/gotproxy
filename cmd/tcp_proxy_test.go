package main

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

func TestIsProxySelfTarget(t *testing.T) {
	orig := localIPv4s
	localIPv4s = func() ([]net.IP, error) {
		return []net.IP{
			net.ParseIP("192.0.2.10").To4(),
			net.ParseIP("172.17.0.1").To4(),
		}, nil
	}
	t.Cleanup(func() { localIPv4s = orig })

	acceptedOnPublic := &net.TCPAddr{IP: net.ParseIP("203.0.113.5"), Port: 18000}
	acceptedOnLoopback := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 18000}

	cases := []struct {
		name   string
		target string
		local  net.Addr
		listen string
		port   uint16
		want   bool
	}{
		{"direct access to accepted address", "203.0.113.5:18000", acceptedOnPublic, "0.0.0.0", 18000, true},
		{"lan address on wildcard listener", "192.0.2.10:18000", acceptedOnPublic, "0.0.0.0", 18000, true},
		{"docker bridge gateway", "172.17.0.1:18000", acceptedOnPublic, "0.0.0.0", 18000, true},
		{"loopback on wildcard listener", "127.0.0.1:18000", acceptedOnPublic, "0.0.0.0", 18000, true},
		{"remote host on the proxy port", "1.2.3.4:18000", acceptedOnPublic, "0.0.0.0", 18000, false},
		{"local address on another port", "192.0.2.10:443", acceptedOnPublic, "0.0.0.0", 18000, false},
		{"loopback when bound to loopback", "127.0.0.1:18000", acceptedOnLoopback, "127.0.0.1", 18000, true},
		{"other local address when bound to loopback", "192.0.2.10:18000", acceptedOnLoopback, "127.0.0.1", 18000, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isProxySelfTarget(tc.target, tc.local, tc.listen, tc.port)
			if got != tc.want {
				t.Fatalf("isProxySelfTarget(%q, %v, %q, %d) = %v, want %v", tc.target, tc.local, tc.listen, tc.port, got, tc.want)
			}
		})
	}
}

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
