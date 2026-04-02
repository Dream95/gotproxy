package main

import (
	"fmt"

	"golang.org/x/net/proxy"
)

func validateSocks5UpstreamConfig() error {
	hasAddr := socks5ProxyAddr != ""
	hasUser := socks5User != ""
	hasPass := socks5Pass != ""

	if (hasUser || hasPass) && !hasAddr {
		return fmt.Errorf("--socks5-user/--socks5-pass provided but --socks5 is empty")
	}

	if !hasUser && !hasPass {
		return nil
	}
	if hasUser != hasPass {
		return fmt.Errorf("--socks5-user and --socks5-pass must be set together")
	}

	// RFC1929: 1..255 bytes for both username and password.
	if l := len(socks5User); l == 0 || l > 255 {
		return fmt.Errorf("invalid --socks5-user length %d (must be 1..255)", l)
	}
	if l := len(socks5Pass); l == 0 || l > 255 {
		return fmt.Errorf("invalid --socks5-pass length %d (must be 1..255)", l)
	}

	return nil
}

func socks5AuthOrNil() (*proxy.Auth, error) {
	if socks5ProxyAddr == "" {
		return nil, nil
	}
	if socks5User == "" && socks5Pass == "" {
		return nil, nil
	}
	if err := validateSocks5UpstreamConfig(); err != nil {
		return nil, err
	}
	return &proxy.Auth{User: socks5User, Password: socks5Pass}, nil
}
