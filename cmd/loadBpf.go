package main

import (
	"context"
	"encoding/binary"
	"gotproxy/common"
	"log"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-D ARCH_$TARGET" -target $TARGET  -type Config proxy proxy.c -- -I../.output/ -I../libbpf/include/uapi -I../vmlinux/$TARGET

const (
	CGROUP_PATH     = "/sys/fs/cgroup" // Root cgroup path
	SO_ORIGINAL_DST = 80               // Socket option to get the original destination address
)

// SockAddrIn is a struct to hold the sockaddr_in structure for IPv4 "retrieved" by the SO_ORIGINAL_DST.
type SockAddrIn struct {
	SinFamily uint16
	SinPort   [2]byte
	SinAddr   [4]byte
	// Pad to match the size of sockaddr_in
	Pad [8]byte
}
type Options struct {
	ProxyPort     uint16 // Port where the proxy server listens
	ProxyPid      uint64 // PID of the proxy server
	Command       string
	Pids          []uint64
	ContainerName string
	Ip4           uint32
	Ip4Mask       uint8
	EnableTCP     bool
	EnableUDP     bool
}

func LoadBpf(options *Options) {
	// Remove resource limits for kernels <5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Print("Removing memlock:", err)
	}

	// Load the compiled eBPF ELF and load it into the kernel
	var objs proxyObjects
	if err := loadProxyObjects(&objs, nil); err != nil {
		log.Fatalf("Error loading eBPF objects: %v", err)
	}
	defer objs.Close()

	// Log the effective proxy protocol before starting user-space forwarding.
	mode := "both"
	if options.EnableTCP && !options.EnableUDP {
		mode = "tcp"
	} else if !options.EnableTCP && options.EnableUDP {
		mode = "udp"
	} else if !options.EnableTCP && !options.EnableUDP {
		mode = "none"
	}
	log.Printf("Proxy protocol enabled: %s (tcp=%v udp=%v)", mode, options.EnableTCP, options.EnableUDP)

	proxyListenHost := "127.0.0.1"
	proxyRedirectIP := uint32(0x7f000001)
	if options.ContainerName != "" {
		proxyListenHost = "0.0.0.0"
		gatewayIP, err := common.ResolveDockerBridgeGatewayIPv4(context.Background())
		if err != nil {
			// Fallback to Docker default bridge gateway for compatibility with typical setups.
			log.Printf("Resolve Docker bridge gateway failed: %v, fallback to 172.17.0.1", err)
			proxyRedirectIP = 0xac110001
		} else {
			proxyRedirectIP = binary.BigEndian.Uint32(gatewayIP.To4())
		}
		log.Printf("Container mode enabled: proxy listen=%s, redirect gateway=%d.%d.%d.%d",
			proxyListenHost,
			byte(proxyRedirectIP>>24),
			byte(proxyRedirectIP>>16),
			byte(proxyRedirectIP>>8),
			byte(proxyRedirectIP))
	}

	// Start TCP (and UDP) proxy so it can use objs.MapUdpDest for UDP original-dest lookup
	if options.ProxyPid == 0 {
		StartProxy(objs.MapUdpDest, options.EnableTCP, options.EnableUDP, proxyListenHost)
	}

	// Attach eBPF programs to the root cgroup
	connect4Link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    CGROUP_PATH,
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CgConnect4,
	})
	if err != nil {
		log.Print("Attaching CgConnect4 program to Cgroup:", err)
	}
	defer connect4Link.Close()

	sockopsLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    CGROUP_PATH,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.CgSockOps,
	})
	if err != nil {
		log.Print("Attaching CgSockOps program to Cgroup:", err)
	}
	defer sockopsLink.Close()

	sockoptLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    CGROUP_PATH,
		Attach:  ebpf.AttachCGroupGetsockopt,
		Program: objs.CgSockOpt,
	})
	if err != nil {
		log.Print("Attaching CgSockOpt program to Cgroup:", err)
	}
	defer sockoptLink.Close()

	kprobeLink, err := link.Kprobe("tcp_set_state", objs.TcpSetState, nil)
	if err != nil {
		log.Print("Attaching TcpSetState program as kprobe:", err)
	}
	defer kprobeLink.Close()

	var key uint32 = 0
	var pid uint64
	if options.ProxyPid == 0 {
		pid = uint64(os.Getpid())
	} else {
		pid = options.ProxyPid
	}
	config := proxyConfig{
		ProxyPort:         options.ProxyPort,
		ProxyPid:          pid,
		ProxyIp:           proxyRedirectIP,
		FilterByPid:       len(options.Pids) > 0,
		FilterByPgid:      len(options.Pids) > 0,
		FilterByContainer: options.ContainerName != "",
		FilterIp:          options.Ip4,
		FilterIpMask:      options.Ip4Mask,
		EnableTcp:         options.EnableTCP,
		EnableUdp:         options.EnableUDP,
	}
	stringToInt8Array(config.Command[:], options.Command)
	err = objs.proxyMaps.MapConfig.Update(&key, &config, ebpf.UpdateAny)
	if err != nil {
		log.Fatalf("Failed to update proxyMaps map: %v", err)
	}
	for _, pid := range options.Pids {
		err := objs.FilterPidMap.Update(uint32(pid), int8(1), ebpf.UpdateAny)
		if err != nil {
			log.Fatalf("Failed to update FilterPidMap: %v", err)
		}
	}
	if options.ContainerName != "" {
		containerNS, err := common.ResolveContainerNamespacesByName(context.Background(), options.ContainerName)
		if err != nil {
			log.Fatalf("Failed to resolve container namespaces: %v", err)
		}
		if containerNS.PidNS == 0 && containerNS.MntNS == 0 && containerNS.NetNS == 0 {
			log.Fatalf("Container %q does not expose usable namespaces for filtering", options.ContainerName)
		}
		log.Printf("Container %q namespaces: pid=%d mnt=%d net=%d", options.ContainerName, containerNS.PidNS, containerNS.MntNS, containerNS.NetNS)

		if containerNS.PidNS != 0 {
			if err := objs.FilterPidnsMap.Update(containerNS.PidNS, int8(1), ebpf.UpdateAny); err != nil {
				log.Fatalf("Failed to update FilterPidnsMap: %v", err)
			}
		}
		if containerNS.MntNS != 0 {
			if err := objs.FilterMntnsMap.Update(containerNS.MntNS, int8(1), ebpf.UpdateAny); err != nil {
				log.Fatalf("Failed to update FilterMntnsMap: %v", err)
			}
		}
		if containerNS.NetNS != 0 {
			if err := objs.FilterNetnsMap.Update(containerNS.NetNS, int8(1), ebpf.UpdateAny); err != nil {
				log.Fatalf("Failed to update FilterNetnsMap: %v", err)
			}
		}
	}

	select {}
}

func stringToInt8Array(dst []int8, src string) {
	for i := range dst {
		dst[i] = 0
	}

	srcBytes := []byte(src)
	copyLen := len(srcBytes)
	if copyLen >= len(dst) {
		copyLen = len(dst) - 1
	}
	for i := 0; i < copyLen; i++ {
		dst[i] = int8(srcBytes[i])
	}
}
