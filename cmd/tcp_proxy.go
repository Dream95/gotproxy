package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/net/proxy"
)

// StartProxy starts TCP/UDP proxy on proxyPort based on enableTCP/enableUDP.
func StartProxy(udpMap *ebpf.Map, enableTCP bool, enableUDP bool, listenHost string, mirrorOpts MirrorOptions) {
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
		go acceptLoop(listener, mirror)
	}

	if enableUDP && udpMap != nil {
		go StartUDPProxy(proxyAddr, udpMap, mirror)
		log.Printf("UDP proxy server with PID %d listening on %s", os.Getpid(), proxyAddr)
	}
}

func acceptLoop(listener net.Listener, mirror *MirrorDispatcher) {
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn, mirror)
	}
}

func getsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(optname), uintptr(optval), uintptr(unsafe.Pointer(optlen)), 0)
	if e != 0 {
		return e
	}
	return
}

func handleConnection(conn net.Conn, mirror *MirrorDispatcher) {
	defer conn.Close()

	targetConn, err := getTargetConnection(conn)
	if err != nil {
		log.Printf("Connection error: %v", err)
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, copyErr := copyWithMirror(targetConn, conn, func(chunk []byte) {
			if mirror != nil && mirror.ShouldMirror("tcp") {
				mirror.Enqueue("tcp", chunk)
			}
		})
		if copyErr != nil && copyErr != io.EOF {
			log.Printf("Failed copying data to target: %v", copyErr)
		}
	}()
	_, err = copyWithMirror(conn, targetConn, nil)
	if err != nil {
		log.Printf("Failed copying data from target: %v", err)
	}
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

func proxyBidirectional(a net.Conn, b net.Conn) error {
	errCh := make(chan error, 2)

	// a -> b
	go func() {
		_, err := io.Copy(b, a)
		// Signal to the other direction that no more data will be sent to b.
		if cw, ok := b.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		errCh <- err
	}()

	// b -> a
	go func() {
		_, err := io.Copy(a, b)
		if cw, ok := a.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		errCh <- err
	}()

	// Wait for both directions to complete; return first non-nil error.
	var firstErr error
	for range 2 {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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

func getTargetConnection(conn net.Conn) (net.Conn, error) {

	// Using RawConn is necessary to perform low-level operations on the underlying socket file descriptor in Go.
	// This allows us to use getsockopt to retrieve the original destination address set by the SO_ORIGINAL_DST option,
	// which isn't directly accessible through Go's higher-level networking API.
	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		log.Printf("Failed to get raw connection: %v", err)
		return nil, err
	}

	var originalDst SockAddrIn
	// If Control is not nil, it is called after creating the network connection but before binding it to the operating system.
	rawConn.Control(func(fd uintptr) {
		optlen := uint32(unsafe.Sizeof(originalDst))
		// Retrieve the original destination address by making a syscall with the SO_ORIGINAL_DST option.
		err = getsockopt(int(fd), syscall.SOL_IP, SO_ORIGINAL_DST, unsafe.Pointer(&originalDst), &optlen)
		if err != nil {
			log.Printf("getsockopt SO_ORIGINAL_DST failed: %v", err)
		}
	})

	targetAddr := net.IPv4(originalDst.SinAddr[0], originalDst.SinAddr[1], originalDst.SinAddr[2], originalDst.SinAddr[3]).String()
	targetPort := (uint16(originalDst.SinPort[0]) << 8) | uint16(originalDst.SinPort[1])

	sourceAddr := conn.RemoteAddr().String()
	sourceIP, sourcePort, splitErr := net.SplitHostPort(sourceAddr)
	if splitErr != nil {
		sourceIP = sourceAddr
		sourcePort = "unknown"
	}

	log.Printf("TCP Source: %s:%s -> Original destination: %s:%d", sourceIP, sourcePort, targetAddr, targetPort)

	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)

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
