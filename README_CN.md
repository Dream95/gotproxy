# gotproxy

简体中文 | [English](./README.md)

这是一个简单的基于eBpf使用GO语言编写的透明代理程序，可以进行全局或者按照特定的ip,进程id,进程名称进行透明代理。
该程序可以直接进行透明代理网络转发，支持socks5代理，可以替代redsocks,proxychains软件。也可以搭配其它代理软件或者L7层的代理实现分流，防火墙，MockServer的功能。

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
| Flag | 描述 |
| :--- | :--- |
| **--cmd** | 需要代理的进程名称. 如果没有配置，则会进行全局流量代理. |
| **--pids** | 需要代理的进程id, 按照逗号进行分割. |
| **--ip** | 需要代理的目标ip. |
| **--p-pid** | 代理程序的进程id. 会自动过滤不代理该进程的网络通信，以免网络循环。如果没有配置, 本程序会自动启动一个转发代理服务. |
| **--p-port** | 代理服务监听的端口。 |
| **--socks5** | socks5代理的服务端地址，如果配置，会进行socks5代理. |


正在开发中的功能：
支持ipv6,支持udp



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

## 已知限制：
* 理论上应该根据5元组确定一个连接，但是考虑大多数情况目前只根据协议类型和源端口进行连接映射。
* 在根据进程名称进行代理的场景中，如果进程启动了子进程并使用了execve执行一个新命令，会无法进行代理。
* 因为暂不支持udp的网络代理，因此在使用socks5代理时,请使用Do53/TCP,或者你的socks5服务端支持服务端DNS解析。


## 感谢
一些代码引用自：

- [transparent-proxy-ebpf](https://github.com/dorkamotorka/transparent-proxy-ebpf)
- [kyanos](https://github.com/hengyoush/kyanos)
