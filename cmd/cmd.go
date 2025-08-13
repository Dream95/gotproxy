package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	command   string
	proxyPort uint16
	proxyPid  uint64
)

var rootCmd = &cobra.Command{
	Use:   "goproxy",
	Short: "A simple tproxy tool for Linux",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func main() {
	Execute()
	StartProxy(&Options{
		ProxyPort: proxyPort,
		ProxyPid:  proxyPid,
		Command:   command,
	})
}

func init() {
	rootCmd.PersistentFlags().StringVar(&command, "comm", "", "The command to proxy")
	rootCmd.PersistentFlags().Uint16Var(&proxyPort, "port", 18000, "The proxy port")
	rootCmd.PersistentFlags().Uint64Var(&proxyPid, "pid", 0, "The proxy pid")
}
