//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h> 
#include <bpf/bpf_endian.h>

#define MAX_CONNECTIONS 20000
#define MAX_PIDS 64

// #define DEBUG

#ifdef DEBUG
  #define BPF_LOG_DEBUG(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
  #define BPF_LOG_DEBUG(fmt, ...)
#endif

/* Always-on logs for troubleshooting key hook paths. */
#define BPF_LOG_INFO(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)


struct Config {
  __u16 proxy_port;
  __u64 proxy_pid;
  __u32 proxy_ip;
  __u32  filter_ip;
  __u8 filter_ip_mask;
  bool filter_by_pid;
  bool filter_by_pgid;
  bool filter_by_container;
  bool enable_tcp;
  bool enable_udp;
  char command[TASK_COMM_LEN];
};

struct Socket {
  __u32 src_addr;
  __u16 src_port;
  __u32 dst_addr;
  __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10);
    __type(key, u32);
    __type(value, u8);
} filter_pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, u32);
    __type(value, u8);
} filter_pidns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, u32);
    __type(value, u8);
} filter_mntns_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, u32);
    __type(value, u8);
} filter_netns_map SEC(".maps");

struct {
  int (*type)[BPF_MAP_TYPE_ARRAY];
  int (*max_entries)[1];
  __u32 *key;
  struct Config *value;
} map_config SEC(".maps");

struct {
  int (*type)[BPF_MAP_TYPE_HASH];
  int (*max_entries)[MAX_CONNECTIONS];
  __u64 *key;
  struct Socket *value;
} map_socks SEC(".maps");

struct {
  int (*type)[BPF_MAP_TYPE_HASH];
  int (*max_entries)[MAX_CONNECTIONS];
  __u16 *key;
  __u64 *value;
} map_ports SEC(".maps");

// Key for UDP original destination lookup: (client_ip, client_port) as seen by proxy
struct UdpDestKey {
  __u32 src_ip;
  __u16 src_port;
  __u16 pad;
};

// Value: original destination that was redirected to proxy
struct UdpDestVal {
  __u32 dst_ip;
  __u16 dst_port;
  __u16 pad;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_CONNECTIONS);
  __type(key, struct UdpDestKey);
  __type(value, struct UdpDestVal);
} map_udp_dest SEC(".maps");


struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_CONNECTIONS);
  __type(key, __u64);
  __type(value, __u16);
} map_udp_cookie_to_port SEC(".maps");

#define SO_ORIGINAL_DST 80
#define SOL_IP 0

#define AF_INET 2
#define AF_INET6 10

static __always_inline __u32
get_current_pgid(void)
{
  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  if (!task)
    return 0;

  /* PIDTYPE_PGID is 2 in kernel enum pid_type. */
  struct pid *pgid_pid = BPF_CORE_READ(task, signal, pids[2]);
  if (!pgid_pid)
    return 0;

  return BPF_CORE_READ(pgid_pid, numbers[0].nr);
}

static __always_inline bool
match_container_ns(void)
{
  struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
  if (!task) {
    return false;
  }

  __u32 pidns_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
  __u32 mntns_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
  __u32 netns_id = BPF_CORE_READ(task, nsproxy, net_ns, ns.inum);

  if (pidns_id && bpf_map_lookup_elem(&filter_pidns_map, &pidns_id)) {
    return true;
  }
  if (mntns_id && bpf_map_lookup_elem(&filter_mntns_map, &mntns_id)) {
    return true;
  }
  if (netns_id && bpf_map_lookup_elem(&filter_netns_map, &netns_id)) {
    return true;
  }

  return false;
}

static __always_inline bool
match_process(struct Config *conf)
{
  bool has_cmd = conf->command[0] != '\0';
  bool has_pid_filter = conf->filter_by_pid || conf->filter_by_pgid;
  bool has_container_filter = conf->filter_by_container;

  if (!has_cmd && !has_pid_filter && !has_container_filter) {
    return true;
  }

  bool cmd_matched = false;
  bool pid_matched = false;
  bool container_matched = false;

  if (has_cmd) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    cmd_matched = (__builtin_memcmp(comm, conf->command, TASK_COMM_LEN) == 0);
  }

  if (has_pid_filter && conf->filter_by_pid) {
    __u32 current_pid = bpf_get_current_pid_tgid() >> 32;
    if (bpf_map_lookup_elem(&filter_pid_map, &current_pid)) {
      pid_matched = true;
    }
  }

  if (has_pid_filter && !pid_matched && conf->filter_by_pgid) {
    __u32 current_pgid = get_current_pgid();
    if (current_pgid && bpf_map_lookup_elem(&filter_pid_map, &current_pgid)) {
      pid_matched = true;
    }
  }

  if (has_container_filter) {
    container_matched = match_container_ns();
  }

  if ((has_container_filter && container_matched) ||
      (has_cmd && cmd_matched) ||
      (has_pid_filter && pid_matched)) {
    return true;
  }
  return false;
}


SEC("cgroup/connect4")
int cg_connect4(struct bpf_sock_addr *ctx) {
  if (ctx->user_family != AF_INET) return 1;
  if (ctx->protocol != IPPROTO_TCP && ctx->protocol != IPPROTO_UDP) return 1;

  __u32 current_pid = bpf_get_current_pid_tgid() >> 32;
  __u32 key = 0;
  struct Config *conf = bpf_map_lookup_elem(&map_config, &key);
  if (!conf) {
    BPF_LOG_INFO("connect4: config miss pid=%u\n", current_pid);
    return 1;
  }
  if (current_pid == conf->proxy_pid) return 1;

  if (!match_process(conf)) {
    BPF_LOG_INFO("connect4: process no match pid=%u\n", current_pid);
    return 1;
  }

  if (conf->filter_ip)
  {
    __u32 mask = 0xFFFFFFFF >> (32 - conf->filter_ip_mask);
    if ((ctx->user_ip4 & mask) != (conf->filter_ip & mask))
    {
      BPF_LOG_INFO("connect4: ip no match pid=%u\n", current_pid);
      return 1;
    }
  }

  __u32 dst_addr = bpf_ntohl(ctx->user_ip4);
  __u16 dst_port = bpf_ntohl(ctx->user_port) >> 16;

  /* Do not re-proxy traffic that already targets the proxy endpoint. */
  if (dst_addr == conf->proxy_ip && dst_port == conf->proxy_port) {
    BPF_LOG_INFO("connect4: skip self target=%x:%u\n", dst_addr, dst_port);
    return 1;
  }

  if (ctx->protocol == IPPROTO_TCP) {
    if (!conf->enable_tcp) return 1;
    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct Socket sock;
    __builtin_memset(&sock, 0, sizeof(sock));
    sock.dst_addr = dst_addr;
    sock.dst_port = dst_port;
    bpf_map_update_elem(&map_socks, &cookie, &sock, 0);

    ctx->user_ip4 = bpf_htonl(conf->proxy_ip);
    ctx->user_port = bpf_htonl(conf->proxy_port << 16);

    BPF_LOG_INFO("connect4: tcp redirect dst=%x:%u -> proxy=%x:%u pid=%u\n",
                 dst_addr, dst_port, conf->proxy_ip, conf->proxy_port, current_pid);
    return 1;
  }

  /*
   * UDP: read ctx->sk BEFORE any helper that passes ctx as argument.
   * Helpers like bpf_get_socket_cookie(ctx) or bpf_bind(ctx,...) mark
   * ctx as "modified", after which the verifier forbids pointer
   * dereferences through it (e.g. ctx->sk).  Scalar reads/writes
   * (ctx->user_ip4, ctx->user_port) remain fine.
   */
  if (!conf->enable_udp) return 1;
  struct bpf_sock *sk = ctx->sk;
  if (!sk) {
    BPF_LOG_INFO("connect4: udp no sk pid=%u\n", current_pid);
    return 1;
  }
  __u16 src_port = sk->src_port;

  if (src_port == 0) {
    /*
     * Socket not yet bound — force-bind to a random port.
     * We pick the value ourselves so we know it without having to
     * read back from ctx->sk (which is forbidden after bpf_bind).
     */
    struct sockaddr_in bind_sa;
    __builtin_memset(&bind_sa, 0, sizeof(bind_sa));
    bind_sa.sin_family      = AF_INET;
    bind_sa.sin_addr.s_addr = 0;

    __u32 rand = bpf_get_prandom_u32();
    __u16 port = 10000 + (__u16)(rand % 55536);
    bind_sa.sin_port = bpf_htons(port);
    if (bpf_bind(ctx, (struct sockaddr *)&bind_sa, sizeof(bind_sa)) == 0)
      src_port = port;
  }

  if (src_port == 0)
    return 1;

  struct UdpDestKey dkey;
  __builtin_memset(&dkey, 0, sizeof(dkey));
  /*
   * Source IP seen by user-space proxy differs between host/container
   * network paths, so keep key portable by matching on source port.
   */
  dkey.src_ip   = 0;
  dkey.src_port = src_port;

  struct UdpDestVal dval;
  __builtin_memset(&dval, 0, sizeof(dval));
  dval.dst_ip   = dst_addr;
  dval.dst_port = dst_port;
  bpf_map_update_elem(&map_udp_dest, &dkey, &dval, 0);

  ctx->user_ip4  = bpf_htonl(conf->proxy_ip);
  ctx->user_port = bpf_htonl(conf->proxy_port << 16);

  BPF_LOG_INFO("connect4: udp redirect dst=%x:%u src_port=%u proxy=%x:%u pid=%u\n",
               dst_addr, dst_port, src_port, conf->proxy_ip, conf->proxy_port, current_pid);
  return 1;
}

// This program is called whenever there's a socket operation on a particular cgroup (retransmit timeout, connection establishment, etc.)
// This is just to record client source address and port after succesful connection establishment to the proxy
SEC("sockops")
int cg_sock_ops(struct bpf_sock_ops *ctx) {
  // Only forward on IPv4 connections
  if (ctx->family != AF_INET) return 0;

  // Active socket with an established connection
  if (ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
    __u64 cookie = bpf_get_socket_cookie(ctx);
   
    struct Socket *sock = bpf_map_lookup_elem(&map_socks, &cookie);
    if (sock) {
      __u16 src_port = ctx->local_port;
      bpf_map_update_elem(&map_ports, &src_port, &cookie, 0);
      BPF_LOG_INFO("sockops: map_ports set src_port=%u dst=%x:%u\n",
                   src_port, sock->dst_addr, sock->dst_port);
    } else {
      BPF_LOG_INFO("sockops: map_socks miss local_port=%u\n", ctx->local_port);
    }
  }
  return 0;
}

// This is triggered when the proxy queries the original destination information through getsockopt SO_ORIGINAL_DST. 
// This program uses the source port of the client to retrieve the socket's cookie from map_ports, 
// and then from map_socks to get the original destination information, 
// then establishes a connection with the original target and forwards the client's request.
SEC("cgroup/getsockopt")
int cg_sock_opt(struct bpf_sockopt *ctx) {
  if (ctx->optname != SO_ORIGINAL_DST) return 1;
  BPF_LOG_INFO("getsockopt: start level=%d optname=%d optlen=%d\n",
               ctx->level, ctx->optname, ctx->optlen);

  /*
   * SO_ORIGINAL_DST is scoped by level (SOL_IP). Without this check we may
   * hit unrelated options that reuse numeric value 80 under other levels.
   */
  if (ctx->level != SOL_IP) {
    BPF_LOG_INFO("getsockopt: skip non-sol_ip level=%d\n", ctx->level);
    return 1;
  }

  if (!ctx->sk) {
    BPF_LOG_INFO("getsockopt: sk is null\n");
    return 1;
  }

  /*
   * Go may accept redirected IPv4 traffic on a dual-stack listener as
   * AF_INET6 sockets (v4-mapped). Keep processing both AF_INET/AF_INET6
   * and restore IPv4 original destination to userspace.
   */
  if (ctx->sk->family != AF_INET && ctx->sk->family != AF_INET6) {
    BPF_LOG_INFO("getsockopt: skip unsupported family=%u\n", ctx->sk->family);
    return 1;
  }
  if (ctx->sk->protocol != IPPROTO_TCP) {
    BPF_LOG_INFO("getsockopt: skip protocol=%u\n", ctx->sk->protocol);
    return 1;
  }

  __u16 src_port = bpf_ntohs(ctx->sk->dst_port);

  // Retrieve the socket cookie using the clients' src_port 
  __u64 *cookie = bpf_map_lookup_elem(&map_ports, &src_port);
  if (!cookie) {
    BPF_LOG_INFO("getsockopt: map_ports miss src_port=%u\n", src_port);
    return 1;
  }

  // Using the cookie (socket identifier), retrieve the original socket (client connect to destination) from map_socks
  struct Socket *sock = bpf_map_lookup_elem(&map_socks, cookie);
  if (!sock) {
    BPF_LOG_INFO("getsockopt: map_socks miss src_port=%u\n", src_port);
    return 1;
  }

  struct sockaddr_in *sa = ctx->optval;
  if ((void*)(sa + 1) > ctx->optval_end) {
    BPF_LOG_INFO("getsockopt: optval too short optlen=%d\n", ctx->optlen);
    return 1;
  }

  // Establish a connection with the original destination target
  ctx->optlen = sizeof(*sa);
  sa->sin_family = AF_INET;
  sa->sin_addr.s_addr = bpf_htonl(sock->dst_addr); 
  sa->sin_port = bpf_htons(sock->dst_port); 
  ctx->retval = 0;
  BPF_LOG_INFO("getsockopt: restore src_port=%u dst=%x:%u\n",
               src_port, sock->dst_addr, sock->dst_port);
  return 1;
}

SEC("kprobe/tcp_set_state")
int tcp_set_state(struct pt_regs *ctx)
{
  struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
  int state = (int)PT_REGS_PARM2(ctx);

  if (state == TCP_CLOSE)
  {
    __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u64 *cookie = bpf_map_lookup_elem(&map_ports, &src_port);
    if (cookie)
    {
      BPF_LOG_INFO("tcp_close: cleanup src_port=%u\n", src_port);
      bpf_map_delete_elem(&map_ports, &src_port);
      bpf_map_delete_elem(&map_socks, &cookie);
    }
  }

  return 0;
}

char __LICENSE[] SEC("license") = "GPL";