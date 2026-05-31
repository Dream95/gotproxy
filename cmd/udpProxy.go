package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/txthinking/socks5"
)

const (
	udpSessionIdleTimeout = 60 * time.Second
	udpSessionSendQueue   = 256
	udpDialTimeout        = 5 * time.Second
)

const (
	localDNSStubAddr = "127.0.0.53:53"
	publicDNSAddr    = "1.1.1.1:53"
)

type udpSessionManager struct {
	proxyConn *net.UDPConn
	udpMap    *ebpf.Map
	mirror    *MirrorDispatcher
	sessions  sync.Map
}

type udpSession struct {
	mgr        *udpSessionManager
	key        string
	clientAddr *net.UDPAddr
	targetAddr string
	remote     net.Conn
	sendCh     chan []byte
	done       chan struct{}
	lastActive atomic.Int64
	closeOnce  sync.Once
}

// StartUDPProxy listens on addr (UDP) and forwards packets to original destinations
// looked up from the BPF map (key = client addr, value = original dst ip:port).
func StartUDPProxy(addr string, udpMap *ebpf.Map, mirror *MirrorDispatcher) {
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

	mgr := &udpSessionManager{
		proxyConn: conn,
		udpMap:    udpMap,
		mirror:    mirror,
	}

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
		mgr.dispatch(clientAddr, payload)
	}
}

func (m *udpSessionManager) dispatch(clientAddr *net.UDPAddr, payload []byte) {
	key := clientAddr.String()
	if v, ok := m.sessions.Load(key); ok {
		v.(*udpSession).tryEnqueue(payload)
		return
	}

	sess, err := m.createSession(clientAddr)
	if err != nil {
		return
	}

	actual, loaded := m.sessions.LoadOrStore(key, sess)
	if loaded {
		sess.close()
		actual.(*udpSession).tryEnqueue(payload)
		return
	}

	go sess.run()
	sess.tryEnqueue(payload)
}

func (m *udpSessionManager) createSession(clientAddr *net.UDPAddr) (*udpSession, error) {
	targetAddr, err := getUDPOriginalDest(clientAddr, m.udpMap)
	if err != nil {
		log.Printf("UDP proxy: lookup original dest for %s: %v", clientAddr, err)
		return nil, err
	}
	targetAddr = maybeRewriteLocalDNSStub(targetAddr)
	log.Printf("UDP Original destination: %s", targetAddr)

	var remoteConn net.Conn
	if socks5ProxyAddr == "" {
		remoteConn, err = net.DialTimeout("udp", targetAddr, udpDialTimeout)
	} else {
		remoteConn, err = dialUDPViaSOCKS5(targetAddr)
	}
	if err != nil {
		log.Printf("UDP proxy: dial %s: %v", targetAddr, err)
		return nil, err
	}

	sess := &udpSession{
		mgr:        m,
		key:        clientAddr.String(),
		clientAddr: clientAddr,
		targetAddr: targetAddr,
		remote:     remoteConn,
		sendCh:     make(chan []byte, udpSessionSendQueue),
		done:       make(chan struct{}),
	}
	sess.touch()
	return sess, nil
}

func (m *udpSessionManager) removeSession(key string) {
	m.sessions.Delete(key)
}

func (s *udpSession) touch() {
	s.lastActive.Store(time.Now().UnixNano())
}

func (s *udpSession) idleExpired() bool {
	last := time.Unix(0, s.lastActive.Load())
	return time.Since(last) >= udpSessionIdleTimeout
}

func (s *udpSession) tryEnqueue(payload []byte) {
	select {
	case <-s.done:
		log.Printf("UDP proxy: session %s already closed, dropping packet", s.key)
	case s.sendCh <- payload:
		s.touch()
	default:
		log.Printf("UDP proxy: session %s send queue full (%d), dropping packet", s.key, udpSessionSendQueue)
	}
}

func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.remote.Close()
	})
}

func (s *udpSession) run() {
	defer s.mgr.removeSession(s.key)
	defer s.close()

	go s.writeLoop()

	buf := make([]byte, 64*1024)
	for {
		if s.idleExpired() {
			return
		}

		remaining := udpSessionIdleTimeout - time.Since(time.Unix(0, s.lastActive.Load()))
		readDeadline := time.Second
		if remaining < readDeadline {
			readDeadline = remaining
		}
		if readDeadline <= 0 {
			return
		}

		s.remote.SetReadDeadline(time.Now().Add(readDeadline))
		n, err := s.remote.Read(buf)
		if n > 0 {
			if _, werr := s.mgr.proxyConn.WriteToUDP(buf[:n], s.clientAddr); werr != nil {
				log.Printf("UDP proxy: write back to client %s: %v", s.clientAddr, werr)
				return
			}
			s.touch()
			continue
		}
		if err != nil {
			if isUDPReadTimeout(err) {
				continue
			}
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("UDP proxy: read from %s: %v", s.targetAddr, err)
			}
			return
		}
	}
}

func (s *udpSession) writeLoop() {
	for {
		select {
		case <-s.done:
			return
		case payload := <-s.sendCh:
			if _, err := s.remote.Write(payload); err != nil {
				log.Printf("UDP proxy: write to %s: %v", s.targetAddr, err)
				s.close()
				return
			}
			if s.mgr.mirror != nil && s.mgr.mirror.ShouldMirror("udp") {
				s.mgr.mirror.Enqueue("udp", payload)
			}
			s.touch()
		}
	}
}

func isUDPReadTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func maybeRewriteLocalDNSStub(targetAddr string) string {
	if noDNS53 {
		return targetAddr
	}
	if targetAddr != localDNSStubAddr {
		return targetAddr
	}
	log.Printf("UDP proxy: rewrite DNS destination %s -> %s", localDNSStubAddr, publicDNSAddr)
	return publicDNSAddr
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
