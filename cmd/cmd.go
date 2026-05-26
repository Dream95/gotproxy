package main

import (
	"fmt"
	"gotproxy/common"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	command         string
	noCmdTrack      bool
	proxyPort       uint16
	proxyPid        uint64
	pids            []string
	containerName   string
	ipStr           string
	socks5ProxyAddr string
	socks5User      string
	socks5Pass      string
	proto           string
	noDNS53         bool
	mirrorEnable    bool
	mirrorTarget    string
	mirrorProto     string
	mirrorTimeoutMs int
	mirrorQueue     int
	mirrorDropFull  bool
)

var rootCmd = &cobra.Command{
	Use:     "gotproxy",
	Version: Version,
	Short:   "A simple tcp transparent proxy tool for Linux",
	Run: func(cmd *cobra.Command, args []string) {
		log.Printf("gotproxy version %s", Version)

		if err := validateSocks5UpstreamConfig(); err != nil {
			log.Fatal(err)
		}

		var enableTCP, enableUDP bool
		switch proto {
		case "both":
			enableTCP, enableUDP = true, true
		case "tcp":
			enableTCP, enableUDP = true, false
		case "udp":
			enableTCP, enableUDP = false, true
		default:
			log.Fatalf("Invalid --proto value %q, expected one of: both|tcp|udp", proto)
		}
		resolvedMirrorProto := strings.TrimSpace(strings.ToLower(mirrorProto))
		if resolvedMirrorProto == "auto" {
			resolvedMirrorProto = proto
		}
		switch resolvedMirrorProto {
		case "both", "tcp", "udp":
		default:
			log.Fatalf("Invalid --mirror-proto value %q, expected one of: auto|both|tcp|udp", mirrorProto)
		}
		if mirrorEnable && strings.TrimSpace(mirrorTarget) == "" {
			log.Fatalf("Invalid mirror config: --mirror-enable requires --mirror-target")
		}
		if mirrorTimeoutMs <= 0 {
			log.Fatalf("Invalid --mirror-timeout-ms value %d, expected > 0", mirrorTimeoutMs)
		}
		if mirrorQueue <= 0 {
			log.Fatalf("Invalid --mirror-queue value %d, expected > 0", mirrorQueue)
		}

		Options := &Options{
			Command:       command,
			NoCmdTrack:    noCmdTrack,
			ProxyPid:      proxyPid,
			ProxyPort:     proxyPort,
			ContainerName: containerName,
			EnableTCP:     enableTCP,
			EnableUDP:     enableUDP,
			Mirror: MirrorOptions{
				Enabled:    mirrorEnable,
				Target:     strings.TrimSpace(mirrorTarget),
				Proto:      resolvedMirrorProto,
				Timeout:    time.Duration(mirrorTimeoutMs) * time.Millisecond,
				QueueSize:  mirrorQueue,
				DropOnFull: mirrorDropFull,
			},
		}

		if ok, err := common.HasPermission(); err != nil {
			log.Fatal("check capabilities failed: ", err)
			return
		} else if !ok {
			log.Fatal("gotproxy requires CAP_BPF to run. Please run gotproxy with sudo.")
			return
		}

		ip, mask, err := common.ParseIPWithMask(ipStr)
		if err != nil {
			log.Fatal(err)
		}
		Options.Ip4 = ip
		Options.Ip4Mask = mask

		for _, pid := range pids {
			pidInt, err := strconv.ParseUint(pid, 10, 64)
			if err != nil {
				fmt.Println("Invalid pid:", pid)
				continue
			}
			Options.Pids = append(Options.Pids, pidInt)
		}
		LoadBpf(Options)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&command, "cmd", "", "The command to be proxied. If not provided, all traffic will be proxied globally.")
	rootCmd.PersistentFlags().BoolVar(&noCmdTrack, "no-cmd-track", false, "Disable fork-based child process tracking for --cmd (legacy comm-only matching).")
	rootCmd.PersistentFlags().Uint16Var(&proxyPort, "p-port", 18000, "The proxy port")
	rootCmd.PersistentFlags().Uint64Var(&proxyPid, "p-pid", 0, "The process ID of the proxy. If not provided, the program will automatically start a forwarding proxy.")
	rootCmd.PersistentFlags().StringSliceVar(&pids, "pids", []string{}, "The pid to be proxied, seperate by ','")
	rootCmd.PersistentFlags().StringVar(&containerName, "container-name", "", "The container name to be proxied")
	rootCmd.PersistentFlags().StringVar(&ipStr, "ip", "", "The ip to be proxied,only support ipv4")
	rootCmd.PersistentFlags().StringVar(&socks5ProxyAddr, "socks5", "", "The socks5 proxyAddr.")
	rootCmd.PersistentFlags().StringVar(&socks5User, "socks5-user", "", "The SOCKS5 username. Requires --socks5-pass.")
	rootCmd.PersistentFlags().StringVar(&socks5Pass, "socks5-pass", "", "The SOCKS5 password. Requires --socks5-user.")
	rootCmd.PersistentFlags().StringVar(&proto, "proto", "both", "Proxy protocol: both|tcp|udp")
	rootCmd.PersistentFlags().BoolVar(&noDNS53, "no-dns53", false, "Disable UDP DNS destination rewrite from 127.0.0.53:53 to 1.1.1.1:53")
	rootCmd.PersistentFlags().BoolVar(&mirrorEnable, "mirror-enable", false, "Enable traffic mirroring")
	rootCmd.PersistentFlags().StringVar(&mirrorTarget, "mirror-target", "", "Mirror destination address, e.g. 10.0.0.2:9000")
	rootCmd.PersistentFlags().StringVar(&mirrorProto, "mirror-proto", "auto", "Mirror protocol: auto|both|tcp|udp")
	rootCmd.PersistentFlags().IntVar(&mirrorTimeoutMs, "mirror-timeout-ms", 100, "Mirror write timeout in milliseconds")
	rootCmd.PersistentFlags().IntVar(&mirrorQueue, "mirror-queue", 1024, "Mirror async queue size")
	rootCmd.PersistentFlags().BoolVar(&mirrorDropFull, "mirror-drop-on-full", true, "Drop mirrored packets when mirror queue is full")
}
