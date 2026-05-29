# gotproxy

简体中文 | [English](./README.md)

这是一个简单的基于eBpf(用户态使用Go语言)的轻量级网络工具。它可以将网络流量透明地进行代理和转发，支持针对全局、指定 IP、进程 ID，或进程名称等多维度的流量细粒度控制。与传统工具（如 proxychains）相比，gotproxy 能够支持更复杂的流量代理规则，并且原生支持 TCP 和 UDP 协议。同时可以开启流量复制功能（mirror），将真实流量高效同步到指定目标地址，便于实现 Debug、数据录制、影子流量回放等功能，适用于故障排查、回归测试等场景。

此外，可与其他代理软件或L7代理系统灵活结合使用，实现高阶的流量分流、或 Mock Server 等场景需求。通过简单的参数配置，即可高效完成复杂网络流量管理任务。

## 📦 安装和使用

**安装**

直接在[release](https://github.com/Dream95/gotproxy/releases)中下载二进制文件

***自行编译***
1.  克隆git仓库:
    ```bash
    git clone https://github.com/Dream95/gotproxy.git
    cd gotproxy
    git submodule update --init --recursive
    ./init_env.sh
    ```
2.  编译:
    ```bash
    make build-bpf && make
    ```


**使用**

`gotproxy` 需要 root 权限才能运行.

```bash
sudo ./gotproxy [flags]
```
### 代理 / 转发 flags

| Flag | 描述 |
| :--- | :--- |
| **--cmd** | 需要代理的进程名称（`comm`，最多 16 字节）。匹配进程 fork 出的子进程会自动纳入跟踪（含 exec 后换名，如 `git` → `git-remote-https`）。未配置则全局代理。 |
| **--follow-forks** | 跟踪 `--cmd` 匹配进程 fork 出的子进程（默认开启）。设为 `--follow-forks=false` 则仅按当前 `comm` 匹配（旧行为）。 |
| **--pids** | 需要代理的进程id, 按照逗号进行分割. |
| **--container-name** | 需要代理的容器名称（Docker 运行中的容器名）。 |
| **--ip** | 需要代理的目标ip. 支持ipv4和ipv4 CIDR.|
| **--p-pid** | 代理程序的进程id. 会自动过滤不代理该进程的网络通信，以免网络循环。如果没有配置, 本程序会自动启动一个转发代理服务. |
| **--p-port** | 代理服务监听的端口。 |
| **--socks5** | socks5代理的服务端地址，如果配置，会进行socks5代理. |
| **--socks5-user** | socks5 账号（RFC1929）。需要同时设置 `--socks5-pass`。 |
| **--socks5-pass** | socks5 密码（RFC1929）。需要同时设置 `--socks5-user`。 |
| **--proto** | 代理协议选择：`both`（默认）/ `tcp` / `udp`。当设置为 `tcp` 时只重定向 TCP 流量；设置为 `udp` 时只重定向 UDP 流量。 |
| **--no-dns53** | 关闭 UDP DNS 对 `127.0.0.53:53` 的自动改写。默认会自动改写为 `1.1.1.1:53`。 |

### Mirror（流量复制）flags

Mirror 与代理/转发功能相互独立：它会尽力将原始流量复制一份发送到指定目标。

| Flag | 描述 |
| :--- | :--- |
| **--mirror-enable** | 开启尽力而为的流量复制。 |
| **--mirror-target** | 复制目标地址，例如 `10.0.0.2:9000`。 |
| **--mirror-proto** | 复制协议：`auto`（默认，跟随 `--proto`）/ `both` / `tcp` / `udp`。 |
| **--mirror-timeout-ms** | 复制写超时时间（毫秒，默认 `100`）。 |
| **--mirror-queue** | 复制异步队列大小（默认 `1024`）。 |
| **--mirror-drop-on-full** | 当队列满时是否丢弃复制数据（默认 `true`）。 |


正在开发中的功能：
支持ipv6



***示例***
1. 代理一个特定的进程名称的网络代理:

```bash
sudo ./gotproxy --cmd "curl"
 ```

2. 代理网络并进行socks5转发:

```bash
sudo ./gotproxy --socks5 192.168.1.2:1080
 ```
其中‘192.168.1.2:1080’是socks5代理服务器的ip和端口

也支持带账号密码的 socks5 上游：

```bash
sudo ./gotproxy --socks5 192.168.1.2:1080 --socks5-user alice --socks5-pass 'secret'
```

3. 仅代理 TCP:
```bash
sudo ./gotproxy --proto tcp
```

4. 仅代理 UDP:
```bash
sudo ./gotproxy --proto udp
```

5. 代理并开启流量镜像（Mirror）:

```bash
sudo ./gotproxy --proto both --mirror-enable --mirror-target 10.0.0.2:9000
```

6. 按容器名称代理:
```bash
sudo ./gotproxy --container-name curl-test
```

7. 容器名 + pid 同时过滤:
```bash
sudo ./gotproxy --container-name curl-test --pids 1234
```
当同时配置多个进程/容器过滤条件（如 `--container-name`、`--cmd`、`--pids`）时，使用 OR 关系：命中任意一个条件就会被代理。

## 已知限制：
* 理论上应该根据5元组确定一个连接，但是考虑大多数情况目前只根据协议类型和源端口进行连接映射。
* 使用 `--cmd` 时，默认通过 fork 跟踪子进程（`--follow-forks`，默认开启，含 exec 后换名）。使用 `--follow-forks=false` 可恢复仅匹配当前 `comm` 的旧行为。与匹配进程树无关的进程不会被跟踪。
* 目前的udp代理实现并不完善，某些场景下可能存在问题。
* 默认会将 UDP DNS 目标 `127.0.0.53:53` 自动改写为 `1.1.1.1:53`；如需关闭可设置 `--no-dns53`。

## 许可证

用户态代码（Go）采用 [Apache License 2.0](LICENSE)。

eBPF 程序（如 `cmd/proxy.c`）采用 **GPL-2.0-only OR Apache-2.0** 双许可；加载进内核时在 BPF ELF 的 `license` 段声明 `Dual BSD/GPL`，以满足内核对 GPL 兼容 helper 的要求。第三方组件见 [NOTICE](NOTICE)。

## 感谢
一些代码引用自：

- [transparent-proxy-ebpf](https://github.com/dorkamotorka/transparent-proxy-ebpf)
- [kyanos](https://github.com/hengyoush/kyanos)
