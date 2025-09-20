# gotproxy

[简体中文](./README_CN.md) | English

This is a simple transparent proxy tool developed in Go, leveraging eBPF. It enables transparent proxying for network traffic either globally or targeted by specific IP addresses, process IDs, or process name.

The program offers direct transparent proxy network forwarding with SOCKS5 support, serving as a modern alternative to tools like redsocks and proxychains. Furthermore, it can be integrated with other proxy software or Layer 7 proxies to implement advanced functionalities such as traffic splitting, firewalls, or creating a Mock Server.

## 📦 Installation & Usage

**Installation**

Download binary from [release](https://github.com/Dream95/gotproxy/releases) or build from source:

1.  Clone the repository:
    ```bash
    git clone https://github.com/Dream95/gotproxy.git
    cd gotproxy
    git submodule update --init --recursive
    ./init_env.sh
    ```
2.  Build from source:
    ```bash
    make build-bpf && make
    ```

**Usage**

`gotproxy` requires root privileges to function.

```bash
sudo ./gotproxy [flags]
```
| Flag | Description |
| :--- | :--- |
| **--cmd** | The command name to be proxied. If not provided, all traffic will be proxied globally. |
| **--pids** | The pid to be proxied, seperate by ','. |
|  **--ip** | The Target IP address to be proxied. Supports IPv4 and IPv4 CIDR notation.|
| **--p-pid** | The process ID of the proxy. If not provided, the program will automatically start a forwarding proxy. |
| **--p-port** | The proxy port. |
| **--socks5**	| The SOCKS5 proxy Server network address. If configured, SOCKS5 proxying will be used. |

Features Under Development：
IPv6 support
UDP support

***Examples***
1. Proxy a specific command:

```bash
sudo ./gotproxy --cmd "curl"
 ```

2. Proxy network traffic and forward via SOCKS5:
```bash
sudo ./gotproxy --socks5 192.168.1.2:1080
 ```
Where '192.168.1.2:1080' is the IP and port of the SOCKS5 proxy server.


## Known Limitations ##
* Theoretically, a connection should be determined by a 5-tuple, but for most cases, connection mapping is currently based only on protocol type and source port.

* In scenarios where proxying is based on process name, if a process starts a child process and uses execve to execute a new command, proxying will not work.

* Since UDP network proxying is not yet supported, when using SOCKS5 proxy, please use Do53/TCP or ensure your SOCKS5 server supports server-side DNS resolution.

## Thanks
Some code is referenced from

- [transparent-proxy-ebpf](https://github.com/dorkamotorka/transparent-proxy-ebpf)
- [kyanos](https://github.com/hengyoush/kyanos)
