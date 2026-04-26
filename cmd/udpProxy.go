package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/txthinking/socks5"
)

const udpReadTimeout = 5 * time.Second

// StartUDPProxy listens on addr (UDP) and forwards packets to original destinations
// looked up from the BPF map (key = client addr, value = original dst ip:port).
func StartUDPProxy(addr string, udpMap *ebpf.Map) {
	if udpMap == nil {
		return
	}
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		log.Printf("UDP proxy: resolve %s: %v", addr, err)
		return
	}
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		log.Printf("UDP proxy: listen %s: %v", addr, err)
		return
	}
	defer conn.Close()

	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP proxy: read: %v", err)
			continue
		}
		if n == 0 {
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		go handleUDPPacket(conn, clientAddr, payload, udpMap)
	}
}

func handleUDPPacket(proxyConn *net.UDPConn, clientAddr *net.UDPAddr, payload []byte, udpMap *ebpf.Map) {
	targetAddr, err := getUDPOriginalDest(clientAddr, udpMap)
	if err != nil {
		log.Printf("UDP proxy: lookup original dest for %s: %v", clientAddr, err)
		return
	}
	fmt.Printf("UDP Original destination: %s\n", targetAddr)

	var remoteConn net.Conn
	if socks5ProxyAddr == "" {
		remoteConn, err = net.DialTimeout("udp", targetAddr, 5*time.Second)
	} else {
		remoteConn, err = dialUDPViaSOCKS5(targetAddr)
	}
	if err != nil {
		log.Printf("UDP proxy: dial %s: %v", targetAddr, err)
		return
	}
	defer remoteConn.Close()

	_, err = remoteConn.Write(payload)
	if err != nil {
		log.Printf("UDP proxy: write to %s: %v", targetAddr, err)
		return
	}

	remoteConn.SetReadDeadline(time.Now().Add(udpReadTimeout))
	respBuf := make([]byte, 64*1024)
	m, err := remoteConn.Read(respBuf)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return
		}
		log.Printf("UDP proxy: read from %s: %v", targetAddr, err)
		return
	}
	_, err = proxyConn.WriteToUDP(respBuf[:m], clientAddr)
	if err != nil {
		log.Printf("UDP proxy: write back to client %s: %v", clientAddr, err)
	}
}

// getUDPOriginalDest looks up the BPF map with key (clientIP, clientPort) and returns "ip:port".
// BPF stores: key src_ip (network order), src_port (host); value dst_ip (network order), dst_port (host).
func getUDPOriginalDest(clientAddr *net.UDPAddr, udpMap *ebpf.Map) (string, error) {
	ip4 := clientAddr.IP.To4()
	if ip4 == nil {
		return "", fmt.Errorf("not IPv4")
	}
	key := proxyUdpDestKey{
		SrcIp:   binary.BigEndian.Uint32(ip4),
		SrcPort: uint16(clientAddr.Port),
	}
	var val proxyUdpDestVal
	if err := udpMap.Lookup(&key, &val); err != nil {
		// Fallback entry keyed only by source port for container/bridge paths.
		key.SrcIp = 0
		if err := udpMap.Lookup(&key, &val); err != nil {
			return "", err
		}
	}
	// DstIp is network order (big-endian), DstPort is host order
	targetIP := net.IPv4(byte(val.DstIp>>24), byte(val.DstIp>>16), byte(val.DstIp>>8), byte(val.DstIp))
	return fmt.Sprintf("%s:%d", targetIP.String(), val.DstPort), nil
}

func dialUDPViaSOCKS5(targetAddr string) (net.Conn, error) {

	if err := validateSocks5UpstreamConfig(); err != nil {
		return nil, err
	}

	client, err := socks5.NewClient(socks5ProxyAddr, socks5User, socks5Pass, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 client: %w", err)
	}

	return client.Dial("udp", targetAddr)
}
