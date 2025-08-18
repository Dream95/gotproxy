package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

func StartProxy(proxyPort uint16) {
	// log.Printf("Proxy server with PID %d listening on %s", options.ProxyPid, proxyAddr)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", proxyPort)
	// Start the proxy server on the localhost
	// We only demonstrate IPv4 in this example, but the same approach can be used for IPv6
	listener, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}

	log.Printf("Proxy server with PID %d listening on %s", os.Getpid(), proxyAddr)
	go acceptLoop(listener)
}

func acceptLoop(listener net.Listener) {
	defer listener.Close()
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func getsockopt(s int, level int, optname int, optval unsafe.Pointer, optlen *uint32) (err error) {
	_, _, e := syscall.Syscall6(syscall.SYS_GETSOCKOPT, uintptr(s), uintptr(level), uintptr(optname), uintptr(optval), uintptr(unsafe.Pointer(optlen)), 0)
	if e != 0 {
		return e
	}
	return
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Using RawConn is necessary to perform low-level operations on the underlying socket file descriptor in Go.
	// This allows us to use getsockopt to retrieve the original destination address set by the SO_ORIGINAL_DST option,
	// which isn't directly accessible through Go's higher-level networking API.
	rawConn, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		log.Printf("Failed to get raw connection: %v", err)
		return
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

	fmt.Printf("Original destination: %s:%d\n", targetAddr, targetPort)

	// Check that the original destination address is reachable from the proxy
	targetConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", targetAddr, targetPort), 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to original destination: %v", err)
		return
	}
	defer targetConn.Close()

	fmt.Printf("Proxying connection from %s to %s\n", conn.RemoteAddr(), targetConn.RemoteAddr())

	// The following code creates two data transfer channels:
	// - From the client to the target server (handled by a separate goroutine).
	// - From the target server to the client (handled by the main goroutine).
	go func() {
		_, err = io.Copy(targetConn, conn)
		if err != nil {
			log.Printf("Failed copying data to target: %v", err)
		}
	}()
	_, err = io.Copy(conn, targetConn)
	if err != nil {
		log.Printf("Failed copying data from target: %v", err)
	}
}
