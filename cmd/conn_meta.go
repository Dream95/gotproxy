package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
)

// Match flag bits — keep in sync with enum match_flags in proxy.c.
const (
	MatchCmd       uint32 = 1 << 0
	MatchPid       uint32 = 1 << 1
	MatchPgid      uint32 = 1 << 2
	MatchContainer uint32 = 1 << 3
	MatchTracked   uint32 = 1 << 4
)

// ConnMeta is userspace connection metadata read from eBPF maps for routing.
type ConnMeta struct {
	Pid        uint32
	Tgid       uint32
	Pgid       uint32
	Pidns      uint32
	Mntns      uint32
	Netns      uint32
	MatchFlags uint32
	Comm       string
	DstIP      net.IP
	DstPort    uint16
}

func (m ConnMeta) TargetAddr() string {
	if m.DstIP == nil {
		return ""
	}
	return fmt.Sprintf("%s:%d", m.DstIP.String(), m.DstPort)
}

func (m ConnMeta) String() string {
	return fmt.Sprintf("pid=%d tgid=%d pgid=%d comm=%q flags=0x%x ns(pid=%d mnt=%d net=%d) dst=%s",
		m.Pid, m.Tgid, m.Pgid, m.Comm, m.MatchFlags, m.Pidns, m.Mntns, m.Netns, m.TargetAddr())
}

func connMetaFromBPF(meta proxyConnMeta, dstIP uint32, dstPort uint16) ConnMeta {
	return ConnMeta{
		Pid:        meta.Pid,
		Tgid:       meta.Tgid,
		Pgid:       meta.Pgid,
		Pidns:      meta.PidnsInum,
		Mntns:      meta.MntnsInum,
		Netns:      meta.NetnsInum,
		MatchFlags: meta.MatchFlags,
		Comm:       int8ArrayToString(meta.Comm[:]),
		DstIP:      hostOrderIPv4(dstIP),
		DstPort:    dstPort,
	}
}

func int8ArrayToString(b []int8) string {
	raw := make([]byte, len(b))
	for i, v := range b {
		if v == 0 {
			return string(raw[:i])
		}
		raw[i] = byte(v)
	}
	return strings.TrimRight(string(raw), "\x00")
}

// hostOrderIPv4 converts a host-order IPv4 uint32 (as stored by bpf_ntohl) to net.IP.
func hostOrderIPv4(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip))
}

func parseRemoteIPv4Port(addr net.Addr) (ip uint32, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0, 0, err
	}
	ip4 := net.ParseIP(host).To4()
	if ip4 == nil {
		return 0, 0, fmt.Errorf("not IPv4: %s", host)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, 0, err
	}
	if p < 0 || p > 65535 {
		return 0, 0, fmt.Errorf("invalid port: %s", portStr)
	}
	// map_ports keys use sockops local_ip4 / sk->dst_ip4, which are IPv4
	// addresses in network byte order stored as __u32. On little-endian that
	// numeric value matches NativeEndian over the wire-order byte slice
	// (e.g. 127.0.0.1 -> 0x0100007f), not BigEndian (0x7f000001).
	return binary.NativeEndian.Uint32(ip4), uint16(p), nil
}

// lookupTCPConnMeta resolves ConnMeta via map_ports → map_socks using the client RemoteAddr.
func lookupTCPConnMeta(remote net.Addr, portsMap, socksMap *ebpf.Map) (ConnMeta, error) {
	if portsMap == nil || socksMap == nil {
		return ConnMeta{}, fmt.Errorf("tcp meta maps not available")
	}
	srcIP, srcPort, err := parseRemoteIPv4Port(remote)
	if err != nil {
		return ConnMeta{}, err
	}
	key := proxyPortKey{
		SrcIp:   srcIP,
		SrcPort: srcPort,
	}
	var cookie uint64
	if err := portsMap.Lookup(&key, &cookie); err != nil {
		return ConnMeta{}, err
	}
	var sock proxySocket
	if err := socksMap.Lookup(&cookie, &sock); err != nil {
		return ConnMeta{}, err
	}
	return connMetaFromBPF(sock.Meta, sock.DstAddr, sock.DstPort), nil
}

// lookupUDPConnMeta looks up map_udp_dest for the client address (with src_ip=0 fallback).
func lookupUDPConnMeta(clientAddr *net.UDPAddr, udpMap *ebpf.Map) (ConnMeta, error) {
	if udpMap == nil {
		return ConnMeta{}, fmt.Errorf("udp map not available")
	}
	ip4 := clientAddr.IP.To4()
	if ip4 == nil {
		return ConnMeta{}, fmt.Errorf("not IPv4")
	}
	key := proxyUdpDestKey{
		SrcIp:   binary.BigEndian.Uint32(ip4),
		SrcPort: uint16(clientAddr.Port),
	}
	var val proxyUdpDestVal
	if err := udpMap.Lookup(&key, &val); err != nil {
		key.SrcIp = 0
		if err := udpMap.Lookup(&key, &val); err != nil {
			return ConnMeta{}, err
		}
	}
	return connMetaFromBPF(val.Meta, val.DstIp, val.DstPort), nil
}
