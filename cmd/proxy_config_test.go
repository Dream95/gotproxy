package main

import (
	"strings"
	"testing"
)

type upstreamProxyConfig struct {
	socks5Addr   string
	socks5User   string
	socks5Pass   string
	httpProxy    string
	httpProxyUser string
	httpProxyPass string
}

func setUpstreamProxyConfig(t *testing.T, cfg upstreamProxyConfig) {
	t.Helper()

	prev := upstreamProxyConfig{
		socks5Addr:    socks5ProxyAddr,
		socks5User:    socks5User,
		socks5Pass:    socks5Pass,
		httpProxy:     httpProxyAddr,
		httpProxyUser: httpProxyUser,
		httpProxyPass: httpProxyPass,
	}

	socks5ProxyAddr = cfg.socks5Addr
	socks5User = cfg.socks5User
	socks5Pass = cfg.socks5Pass
	httpProxyAddr = cfg.httpProxy
	httpProxyUser = cfg.httpProxyUser
	httpProxyPass = cfg.httpProxyPass

	t.Cleanup(func() {
		socks5ProxyAddr = prev.socks5Addr
		socks5User = prev.socks5User
		socks5Pass = prev.socks5Pass
		httpProxyAddr = prev.httpProxy
		httpProxyUser = prev.httpProxyUser
		httpProxyPass = prev.httpProxyPass
	})
}

func TestValidateUpstreamProxyConfig_Socks5HTTPProxyConflict(t *testing.T) {
	tests := []struct {
		name string
		cfg  upstreamProxyConfig
	}{
		{
			name: "both proxy addresses set",
			cfg: upstreamProxyConfig{
				socks5Addr: "127.0.0.1:1080",
				httpProxy:  "127.0.0.1:8080",
			},
		},
		{
			name: "both addresses with credentials",
			cfg: upstreamProxyConfig{
				socks5Addr:    "127.0.0.1:1080",
				socks5User:    "alice",
				socks5Pass:     "secret",
				httpProxy:     "127.0.0.1:8080",
				httpProxyUser: "bob",
				httpProxyPass: "token",
			},
		},
		{
			name: "socks5 with auth and bare http-proxy",
			cfg: upstreamProxyConfig{
				socks5Addr: "127.0.0.1:1080",
				socks5User: "alice",
				socks5Pass:  "secret",
				httpProxy:  "127.0.0.1:8080",
			},
		},
		{
			name: "bare socks5 and http-proxy with auth",
			cfg: upstreamProxyConfig{
				socks5Addr:    "127.0.0.1:1080",
				httpProxy:     "127.0.0.1:8080",
				httpProxyUser: "bob",
				httpProxyPass: "token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUpstreamProxyConfig(t, tt.cfg)

			err := validateUpstreamProxyConfig()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); got != "--socks5 and --http-proxy are mutually exclusive" {
				t.Fatalf("unexpected error: %q", got)
			}
		})
	}
}

func TestValidateUpstreamProxyConfig_NoConflict(t *testing.T) {
	tests := []struct {
		name string
		cfg  upstreamProxyConfig
	}{
		{
			name: "neither proxy configured",
			cfg:  upstreamProxyConfig{},
		},
		{
			name: "socks5 only",
			cfg: upstreamProxyConfig{
				socks5Addr: "127.0.0.1:1080",
			},
		},
		{
			name: "socks5 with auth",
			cfg: upstreamProxyConfig{
				socks5Addr: "127.0.0.1:1080",
				socks5User: "alice",
				socks5Pass:  "secret",
			},
		},
		{
			name: "http-proxy only",
			cfg: upstreamProxyConfig{
				httpProxy: "127.0.0.1:8080",
			},
		},
		{
			name: "http-proxy with auth",
			cfg: upstreamProxyConfig{
				httpProxy:     "127.0.0.1:8080",
				httpProxyUser: "bob",
				httpProxyPass: "token",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUpstreamProxyConfig(t, tt.cfg)

			err := validateUpstreamProxyConfig()
			if err != nil {
				t.Fatalf("expected no conflict error, got: %v", err)
			}
		})
	}
}

func TestValidateUpstreamProxyConfig_CredentialErrorsWithoutConflict(t *testing.T) {
	tests := []struct {
		name    string
		cfg     upstreamProxyConfig
		wantErr string
	}{
		{
			name: "http-proxy user without address",
			cfg: upstreamProxyConfig{
				httpProxyUser: "bob",
			},
			wantErr: "--http-proxy-user/--http-proxy-pass provided but --http-proxy is empty",
		},
		{
			name: "socks5 pass without address",
			cfg: upstreamProxyConfig{
				socks5Pass: "secret",
			},
			wantErr: "--socks5-user/--socks5-pass provided but --socks5 is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setUpstreamProxyConfig(t, tt.cfg)

			err := validateUpstreamProxyConfig()
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("unexpected error: %q", err.Error())
			}
		})
	}
}
