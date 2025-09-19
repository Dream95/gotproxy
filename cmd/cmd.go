package main

import (
	"fmt"
	"gotproxy/common"
	"log"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var (
	command         string
	proxyPort       uint16
	proxyPid        uint64
	pids            []string
	ipStr           string
	socks5ProxyAddr string
)

var rootCmd = &cobra.Command{
	Use:   "gotproxy",
	Short: "A simple tcp transparent proxy tool for Linux",
	Run: func(cmd *cobra.Command, args []string) {
		Options := &Options{
			Command:   command,
			ProxyPid:  proxyPid,
			ProxyPort: proxyPort,
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

		if proxyPid == 0 {
			StartProxy()
		}
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
	rootCmd.PersistentFlags().Uint16Var(&proxyPort, "p-port", 18000, "The proxy port")
	rootCmd.PersistentFlags().Uint64Var(&proxyPid, "p-pid", 0, "The process ID of the proxy. If not provided, the program will automatically start a forwarding proxy.")
	rootCmd.PersistentFlags().StringSliceVar(&pids, "pids", []string{}, "The pid to be proxied, seperate by ','")
	rootCmd.PersistentFlags().StringVar(&ipStr, "ip", "", "The ip to be proxied,only support ipv4")
	rootCmd.PersistentFlags().StringVar(&socks5ProxyAddr, "socks5", "", "The socks5 proxyAddr.")
}
