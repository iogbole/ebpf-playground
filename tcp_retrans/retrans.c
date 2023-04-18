#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <netinet/tcp.h> // include tcp.h header

#define AF_INET 2
#define AF_INET6 10

struct event {
    __u64 timestamp;
    __u32 pid;
    __u16 sport, dport;
    __u8 saddr[4], daddr[4];
    __u8 saddr_v6[16], daddr_v6[16];
    __u16 family;
    __u8 state;
};

struct tcp_retransmit_skb_ctx {
    __u64 _pad0;
    void *skbaddr;
    void *skaddr;
    __u16 family;
    __u16 _pad1;
    __be32 saddr, daddr;
    __be16 source, dest;
    __u32 seq, ack_seq;
    __u16 window;
    __u16 check, urg_ptr;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tracepoint__tcp__tcp_retransmit_skb(struct tcp_retransmit_skb_ctx *ctx)
{
    __u32 key = 0; // CPU 0
    struct event event = {};
    event.timestamp = bpf_ktime_get_ns();
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.sport = bpf_ntohs(ctx->source);
    event.dport = bpf_ntohs(ctx->dest);
    event.family = ctx->family;

    // get the TCP connection state
    struct tcphdr *tcph = (struct tcphdr *)(ctx + 1);
    event.state = tcph->th_flags & TH_STATE_MASK;

    if (event.family == AF_INET) {
        bpf_probe_read(event.saddr, sizeof(event.saddr), &ctx->saddr);
        bpf_probe_read(event.daddr, sizeof(event.daddr), &ctx->daddr);
    } else if (event.family == AF_INET6) {
        bpf_probe_read(event.saddr_v6, sizeof(event.saddr_v6), &ctx->saddr);
        bpf_probe_read(event.daddr_v6, sizeof(event.daddr_v6), &ctx->daddr);
    }

    bpf_perf_event_output(ctx, &events, key, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
