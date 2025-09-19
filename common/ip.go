package common

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

func ParseIPWithMask(ipStr string) (uint32, uint8, error) {
	if ipStr == "" {
		return 0, 0, nil
	}
	if strings.Contains(ipStr, "/") {
		_, ipNet, err := net.ParseCIDR(ipStr)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid CIDR: %s", ipStr)
		}

		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			return 0, 0, fmt.Errorf("not an IPv4 CIDR: %s", ipStr)
		}

		maskSize, _ := ipNet.Mask.Size()
		ipVal := binary.LittleEndian.Uint32(ip4)
		return ipVal, uint8(maskSize), nil
	} else {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return 0, 0, fmt.Errorf("invalid IP: %s", ipStr)
		}

		ip4 := ip.To4()
		if ip4 == nil {
			return 0, 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
		}

		ipVal := binary.LittleEndian.Uint32(ip4)

		fmt.Printf("Parsed IP: %s, Mask=32\n", ipStr)
		return ipVal, 32, nil
	}
}
