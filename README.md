# gotproxy

[简体中文](./README_CN.md) | English

This is a lightweight networking tool built on eBPF with userspace logic written in Go. It transparently proxies and forwards traffic, with fine-grained control across global scope, specific IPs, process IDs, process names, and other dimensions. Compared with traditional tools such as proxychains, gotproxy supports richer proxying rules and native TCP and UDP. You can enable traffic mirroring (mirror) to duplicate live traffic efficiently to a configured destination for debugging, recording, shadow replay, troubleshooting, and regression testing.

It also composes cleanly with other proxies or Layer 7 (L7) systems for advanced use cases such as traffic splitting or Mock Server scenarios. Complex traffic management is achievable through straightforward flag configuration.

## 📦 Installation & Usage

**Installation**

Download binaries directly from [release](https://github.com/Dream95/gotproxy/releases).

***Build from source***

1. Clone the repository:
    ```bash
    git clone https://github.com/Dream95/gotproxy.git
    cd gotproxy
    git submodule update --init --recursive
    ./init_env.sh
    ```
2. Build:
    ```bash
    make build-bpf && make
    ```

**Usage**

`gotproxy` requires root privileges to function.

```bash
sudo ./gotproxy [flags]
```
### Proxy / forwarding flags

| Flag | Description |
| :--- | :--- |
| **--cmd** | Process name to proxy (`comm`, max 16 bytes). Child processes forked from a matching process are tracked automatically. If not set, traffic is proxied globally. |
| **--follow-forks** | Track child processes forked from `--cmd` matches (default: true). Set `--follow-forks=false` for legacy `comm`-only matching. |
| **--pids** | Process IDs to proxy, comma-separated. |
| **--container-name** | Container name to proxy (Docker running container name). |
| **--ip** | Target IP address to proxy. Supports IPv4 and IPv4 CIDR notation. |
| **--p-pid** | Process ID of the proxy program. Traffic from this process is excluded to avoid proxy loops. If not set, the program starts a forwarding proxy automatically. |
| **--p-port** | Port the proxy listens on. |
| **--socks5** | SOCKS5 upstream address. When set, SOCKS5 proxying is used. |
| **--socks5-user** | SOCKS5 username (RFC1929). Must be set together with `--socks5-pass`. |
| **--socks5-pass** | SOCKS5 password (RFC1929). Must be set together with `--socks5-user`. |
| **--proto** | Proxy protocol selection: `both` (default) / `tcp` / `udp`. When set to `tcp`, only TCP traffic is redirected; when set to `udp`, only UDP traffic is redirected. |
| **--no-dns53** | Disable automatic UDP DNS rewrite from `127.0.0.53:53` to `1.1.1.1:53` (enabled by default). |

### Mirror (traffic mirroring) flags

Mirroring is independent of proxy forwarding: it best-effort duplicates the original traffic to a target address.

| Flag | Description |
| :--- | :--- |
| **--mirror-enable** | Enable best-effort traffic mirroring. |
| **--mirror-target** | Mirror destination address, for example `10.0.0.2:9000`. |
| **--mirror-proto** | Mirror protocol: `auto` (default, follows `--proto`) / `both` / `tcp` / `udp`. |
| **--mirror-timeout-ms** | Mirror write timeout in milliseconds (default: `100`). |
| **--mirror-queue** | Mirror async queue size (default: `1024`). |
| **--mirror-drop-on-full** | Drop mirrored packets when queue is full (default: `true`). |

Features under development:

IPv6 support

***Examples***
1. Proxy a specific process name:

```bash
sudo ./gotproxy --cmd "curl"
 ```

2. Proxy network traffic and forward via SOCKS5:

```bash
sudo ./gotproxy --socks5 192.168.1.2:1080
 ```
Where `192.168.1.2:1080` is the IP and port of the SOCKS5 proxy server.

SOCKS5 with username/password:

```bash
sudo ./gotproxy --socks5 192.168.1.2:1080 --socks5-user alice --socks5-pass 'secret'
```

3. TCP-only proxy:
```bash
sudo ./gotproxy --proto tcp
```

4. UDP-only proxy:
```bash
sudo ./gotproxy --proto udp
```

5. Proxy with traffic mirroring:

```bash
sudo ./gotproxy --proto both --mirror-enable --mirror-target 10.0.0.2:9000
```

6. Proxy by container name:
```bash
sudo ./gotproxy --container-name curl-test
```

7. Container name and PID filters together:
```bash
sudo ./gotproxy --container-name curl-test --pids 1234
```
When multiple process/container filters are specified (such as `--container-name`, `--cmd`, `--pids`), they use OR semantics: matching any one filter will be proxied.


## Known limitations:

* Theoretically, a connection should be determined by a 5-tuple, but for most cases, connection mapping is currently based only on protocol type and source port.
* With `--cmd`, child processes created via `fork` (including after `execve`, e.g. `git` → `git-remote-https`) are tracked by default (`--follow-forks`, on by default). Use `--follow-forks=false` to restore legacy `comm`-only matching. Processes unrelated to the matched tree are not tracked.
* The current implementation of UDP proxy is not perfect, and there may be issues in certain scenarios.
* By default, UDP DNS destination `127.0.0.53:53` is automatically rewritten to `1.1.1.1:53`; set `--no-dns53` to turn this off.

## License

Userspace code (Go) is licensed under the [Apache License 2.0](LICENSE).

eBPF programs (e.g. `cmd/proxy.c`) are licensed under **GPL-2.0-only OR Apache-2.0**.
They declare `Dual BSD/GPL` in the BPF ELF `license` section so the Linux kernel
can load them when GPL-compatible helpers are used. See [NOTICE](NOTICE) for
third-party components.

## Thanks
Some code is referenced from

- [transparent-proxy-ebpf](https://github.com/dorkamotorka/transparent-proxy-ebpf)
- [kyanos](https://github.com/hengyoush/kyanos)
