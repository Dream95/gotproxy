package main

import (
	"fmt"
	"log"
	"net"
)

// DefaultProxyPort is the proxy port used when --p-port is not provided.
const DefaultProxyPort = 18000

// listenHostFor returns the address the auto-started proxy binds to:
// loopback in normal mode, all interfaces in container mode (redirected
// traffic arrives from the Docker bridge gateway).
func listenHostFor(containerName string) string {
	if containerName != "" {
		return "0.0.0.0"
	}
	return "127.0.0.1"
}

// resolveProxyPort returns the port for the auto-started proxy. The default
// port is kept when bindable by every enabled protocol; otherwise a random
// high port that can host them all is picked so gotproxy still starts.
func resolveProxyPort(defaultPort uint16, listenHost string, enableTCP, enableUDP bool) (uint16, error) {
	if proxyPortBindable(listenHost, defaultPort, enableTCP, enableUDP) {
		return defaultPort, nil
	}

	network := "tcp"
	if !enableTCP {
		network = "udp"
	}
	var lastErr error
	for i := 0; i < 10; i++ {
		port, err := ephemeralPort(network, listenHost)
		if err != nil {
			return 0, fmt.Errorf("pick random proxy port: %w", err)
		}
		if proxyPortBindable(listenHost, port, enableTCP, enableUDP) {
			log.Printf("Default proxy port %d is occupied, using random high port %d", defaultPort, port)
			return port, nil
		}
		lastErr = fmt.Errorf("candidate port %d became busy", port)
	}
	return 0, fmt.Errorf("no free port for proxy after 10 tries (tcp=%v udp=%v): %w", enableTCP, enableUDP, lastErr)
}

// proxyPortBindable reports whether port can be bound by all enabled protocols.
func proxyPortBindable(listenHost string, port uint16, enableTCP, enableUDP bool) bool {
	if enableTCP && !canBind("tcp", listenHost, port) {
		return false
	}
	if enableUDP && !canBind("udp", listenHost, port) {
		return false
	}
	return true
}

func canBind(network, listenHost string, port uint16) bool {
	addr := fmt.Sprintf("%s:%d", listenHost, port)
	switch network {
	case "tcp":
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return false
		}
		l.Close()
		return true
	case "udp":
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return false
		}
		pc.Close()
		return true
	default:
		return false
	}
}

// ephemeralPort asks the kernel for a free high port by binding port 0 and
// releasing it immediately.
func ephemeralPort(network, listenHost string) (uint16, error) {
	addr := fmt.Sprintf("%s:0", listenHost)
	switch network {
	case "tcp":
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return 0, err
		}
		defer l.Close()
		return uint16(l.Addr().(*net.TCPAddr).Port), nil
	case "udp":
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return 0, err
		}
		defer pc.Close()
		return uint16(pc.LocalAddr().(*net.UDPAddr).Port), nil
	default:
		return 0, fmt.Errorf("unsupported network %q", network)
	}
}
