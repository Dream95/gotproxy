# gotproxy

A simple transparent proxy for Linux that routes network traffic based on the specific process command name.

## 📦 Installation & Usage

**Installation**

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
| **--p-pid** | The process ID of the proxy. If not provided, the program will automatically start a forwarding proxy. |
| **--p-port** | The proxy port. |

***Examples***
1. Proxy a specific command:

```bash
sudo ./gotproxy --cmd "curl"
 ```

## Thanks
The code is referenced from

- [transparent-proxy-ebpf](https://github.com/dorkamotorka/transparent-proxy-ebpf)
- [kyanos](https://github.com/hengyoush/kyanos)
