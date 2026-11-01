package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/net/proxy"
)

// StartProxy starts TCP/UDP proxy on proxyPort based on enableTCP/enableUDP.
func StartProxy(udpMap, portsMap, socksMap *ebpf.Map, enableTCP bool, enableUDP bool, listenHost string, proxyPort uint16, mirrorOpts MirrorOptions) {
	proxyAddr := fmt.Sprintf("%s:%d", listenHost, proxyPort)
	mirror := NewMirrorDispatcher(mirrorOpts)
	if mirror != nil && strings.TrimSpace(mirrorOpts.Target) == proxyAddr {
		log.Fatalf("Invalid mirror config: --mirror-target must not equal proxy listen address %s", proxyAddr)
	}

	if !enableTCP && !enableUDP {
		log.Printf("Proxy: enableTCP and enableUDP are both false, nothing to start")
		return
	}

	if enableTCP {
		listener, err := net.Listen("tcp", proxyAddr)
		if err != nil {
			log.Fatalf("Failed to start TCP proxy server: %v", err)
		}
		log.Printf("TCP proxy server with PID %d listening on %s", os.Getpid(), proxyAddr)
		go acceptLoop(listener, mirror, portsMap, socksMap, listenHost, proxyPort)
	}

	if enableUDP && udpMap != nil {
		go StartUDPProxy(proxyAddr, udpMap, mirror)
		log.Printf("UDP proxy server with PID %d listening on %s", os.Getpid(), proxyAddr)
	}
}

func acceptLoop(listener net.Listener, mirror *MirrorDispatcher, portsMap, socksMap *ebpf.Map, listenHost string, proxyPort uint16) {
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, mirror, portsMap, socksMap, listenHost, proxyPort)
	}
}

func getsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(optname), uintptr(optval), uintptr(unsafe.Pointer(optlen)), 0)
	if e != 0 {
		return e
	}
	return
}

func handleConnection(conn net.Conn, mirror *MirrorDispatcher, portsMap, socksMap *ebpf.Map, listenHost string, proxyPort uint16) {
	defer conn.Close()

	targetConn, err := getTargetConnection(conn, portsMap, socksMap, listenHost, proxyPort)
	if err != nil {
		log.Printf("Connection error: %v", err)
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, copyErr := copyWithMirror(targetConn, conn, func(chunk []byte) {
			if mirror != nil && mirror.ShouldMirror("tcp") {
				mirror.Enqueue("tcp", chunk)
			}
		})
		closeWrite(targetConn)
		if copyErr != nil && !isExpectedCopyError(copyErr) {
			log.Printf("Failed copying data to target: %v", copyErr)
		}
	}()
	go func() {
		defer wg.Done()
		_, copyErr := copyWithMirror(conn, targetConn, nil)
		closeWrite(conn)
		if copyErr != nil && !isExpectedCopyError(copyErr) {
			log.Printf("Failed copying data from target: %v", copyErr)
		}
	}()
	wg.Wait()
}

func copyWithMirror(dst io.Writer, src io.Reader, mirrorFn func([]byte)) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			chunk := buf[:nr]
			nwTotal := 0
			for nwTotal < nr {
				nw, writeErr := dst.Write(chunk[nwTotal:])
				if nw > 0 {
					nwTotal += nw
				}
				if writeErr != nil {
					return written, writeErr
				}
				if nw == 0 {
					return written, io.ErrShortWrite
				}
			}
			written += int64(nr)
			if mirrorFn != nil {
				mirrorFn(chunk)
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func isExpectedCopyError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return true
	}

	// Common benign errors during shutdown/race of half-closes.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if errors.Is(opErr.Err, syscall.ECONNRESET) || errors.Is(opErr.Err, syscall.EPIPE) {
			return true
		}
	}

	msg := err.Error()
	if strings.Contains(msg, "use of closed network connection") {
		return true
	}
	return false
}

// localIPv4s lists IPv4 addresses assigned to local interfaces.
// Tests replace it to avoid depending on the host's interfaces.
var localIPv4s = listLocalIPv4

func listLocalIPv4() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP == nil {
			continue
		}
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		out = append(out, ip4)
	}
	return out, nil
}

func isProxySelfTarget(target string, localAddr net.Addr, listenHost string, listenPort uint16) bool {
	ip, port, ok := splitIPv4Target(target)
	if !ok || port != listenPort {
		return false
	}
	if localIP, localPort, ok := splitIPv4Target(addrString(localAddr)); ok && localPort == listenPort && localIP.Equal(ip) {
		return true
	}
	return ipHitsListener(ip, listenHost)
}

func addrString(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func splitIPv4Target(hostport string) (net.IP, uint16, bool) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, 0, false
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return nil, 0, false
	}
	return ip, uint16(port), true
}

func ipHitsListener(ip net.IP, listenHost string) bool {
	listenIP := net.ParseIP(listenHost).To4()
	if listenIP == nil {
		return false
	}
	if !listenIP.IsUnspecified() {
		return listenIP.Equal(ip)
	}
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	locals, err := localIPv4s()
	if err != nil {
		log.Printf("proxy self-target check: list local addresses: %v", err)
		return false
	}
	for _, local := range locals {
		if local.Equal(ip) {
			return true
		}
	}
	return false
}

func getTargetConnection(conn net.Conn, portsMap, socksMap *ebpf.Map, listenHost string, proxyPort uint16) (net.Conn, error) {
	sourceAddr := conn.RemoteAddr().String()
	sourceIP, sourcePort, splitErr := net.SplitHostPort(sourceAddr)
	if splitErr != nil {
		sourceIP = sourceAddr
		sourcePort = "unknown"
	}

	var target string
	if meta, err := lookupTCPConnMeta(conn.RemoteAddr(), portsMap, socksMap); err == nil {
		target = meta.TargetAddr()
		log.Printf("TCP Source: %s:%s -> Original destination: %s meta={%s}", sourceIP, sourcePort, target, meta)
	} else {
		// Fallback: SO_ORIGINAL_DST restores destination; also retries map
		// lookup afterward in case sockops had not yet populated map_ports.
		rawConn, rawErr := conn.(*net.TCPConn).SyscallConn()
		if rawErr != nil {
			log.Printf("Failed to get raw connection: %v", rawErr)
			return nil, rawErr
		}

		var originalDst SockAddrIn
		var sockErr error
		rawConn.Control(func(fd uintptr) {
			optlen := uint32(unsafe.Sizeof(originalDst))
			sockErr = getsockopt(int(fd), syscall.SOL_IP, SO_ORIGINAL_DST, unsafe.Pointer(&originalDst), &optlen)
		})
		if sockErr != nil {
			log.Printf("getsockopt SO_ORIGINAL_DST failed: %v (map lookup: %v)", sockErr, err)
			return nil, sockErr
		}

		targetAddr := net.IPv4(originalDst.SinAddr[0], originalDst.SinAddr[1], originalDst.SinAddr[2], originalDst.SinAddr[3]).String()
		targetPort := (uint16(originalDst.SinPort[0]) << 8) | uint16(originalDst.SinPort[1])
		target = fmt.Sprintf("%s:%d", targetAddr, targetPort)

		if meta, retryErr := lookupTCPConnMeta(conn.RemoteAddr(), portsMap, socksMap); retryErr == nil {
			target = meta.TargetAddr()
			log.Printf("TCP Source: %s:%s -> Original destination: %s meta={%s}", sourceIP, sourcePort, target, meta)
		} else {
			log.Printf("TCP Source: %s:%s -> Original destination: %s (SO_ORIGINAL_DST fallback, map err: %v)",
				sourceIP, sourcePort, target, err)
		}
	}

	if isProxySelfTarget(target, conn.LocalAddr(), listenHost, proxyPort) {
		return nil, fmt.Errorf("refusing to dial %s: target is the proxy listener", target)
	}

	if httpProxyAddr != "" {
		targetConn, err := dialViaHTTPConnect(httpProxyAddr, target)
		if err != nil {
			return nil, fmt.Errorf("failed to connect via HTTP CONNECT: %w", err)
		}
		return targetConn, nil
	}

	if socks5ProxyAddr == "" {
		targetConn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to destination: %w", err)
		}
		return targetConn, nil
	}

	auth, err := socks5AuthOrNil()
	if err != nil {
		return nil, err
	}

	dialer, err := proxy.SOCKS5("tcp", socks5ProxyAddr, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("cannot create SOCKS5 dialer: %w", err)
	}

	targetConn, err := dialer.Dial("tcp", target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect via SOCKS5: %w", err)
	}
	return targetConn, nil
}
