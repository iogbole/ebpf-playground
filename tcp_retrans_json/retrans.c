#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

struct event {
    __u64 timestamp;
    __u32 pid;
    __u16 sport, dport;
    __u8 saddr[4], daddr[4];
    __u8 saddr_v6[16], daddr_v6[16];
    __u16 family;
    int state;
};

struct tcp_retransmit_skb_ctx {
    __u64 _pad0;
    void *skbaddr;
    void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
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
    event.sport = ctx->sport;
    event.dport = ctx->dport;
    event.family = ctx->family;
    event.state = ctx->state;

    if (event.family == AF_INET) {
        bpf_probe_read(event.saddr, sizeof(event.saddr), ctx->saddr);
        bpf_probe_read(event.daddr, sizeof(event.daddr), ctx->daddr);
    } else if (event.family == AF_INET6) {
        bpf_probe_read(event.saddr_v6, sizeof(event.saddr_v6), ctx->saddr_v6);
        bpf_probe_read(event.daddr_v6, sizeof(event.daddr_v6), ctx->daddr_v6);
    }

    bpf_perf_event_output(ctx, &events, key, &event, sizeof(event));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
