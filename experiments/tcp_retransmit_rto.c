#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10

// Declare the tcp_event struct for storing retransmission event data
struct tcp_event
{
    u64 timestamp;
    u32 pid;
    __u16 sport;
    __u16 dport;
     int state;
     __u32 retrans;
    __u32 rto;
    __u32 rtt;
    __u32 snd_cwnd;
    __u32 ssthresh;
    __u8 saddr4[4];
    __u8 daddr4[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
        u16 family;
    
   
};

// Define a struct to store trace event data from tcp_retransmit_skb tracepoint
struct trace_event_raw_tp_tcp_tcp_retransmit_skb {
    __u64 _pad0;
    __u64 skbaddr;
    __u64 skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u16 family;
};


// Define a map for perf_event_array to collect TCP retransmission events
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} tcp_retransmit_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct tcp_sock));
} tcp_sock_storage SEC(".maps");

// Attach the eBPF program to the tcp/tcp_retransmit_skb tracepoint
SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb(struct trace_event_raw_tp_tcp_tcp_retransmit_skb *ctx)
{
    __u32 key = 0; // CPU 0

    // Populate the tcp_event struct with relevant data
    struct tcp_event e = {};

    e.timestamp = bpf_ktime_get_ns();
    e.pid = bpf_get_current_pid_tgid() >> 32;

    e.sport = ctx->sport;
    e.dport = ctx->dport;
    e.state = ctx->state;
    e.family = ctx->family;

    // Look up the tcp_sock data in the per-CPU array map
    if (!ctx->skaddr)
    {
        return 0;
    }

    struct tcp_sock *tp = bpf_map_lookup_elem(&tcp_sock_storage, &key);
    if (!tp)
    {
        return 0;
    }

    bpf_probe_read_kernel(tp, sizeof(struct tcp_sock), ctx->skaddr);

    e.retrans = tp->total_retrans;
    e.rto = tp->frto;
    e.rtt = tp->srtt_us;
    e.snd_cwnd = tp->snd_cwnd;
    e.ssthresh = tp->snd_ssthresh;

    if (e.family == AF_INET)
    {
        bpf_probe_read(e.saddr4, sizeof(e.saddr4), ctx->saddr);
        bpf_probe_read(e.daddr4, sizeof(e.daddr4), ctx->daddr);
    }
    else if (e.family == AF_INET6)
    {
        bpf_probe_read(e.saddr_v6, sizeof(e.saddr_v6), ctx->saddr_v6);
        bpf_probe_read(e.daddr_v6, sizeof(e.daddr_v6), ctx->daddr_v6);
    }

    // Output the tcp_event data to the perf_event_array
    bpf_perf_event_output(ctx, &tcp_retransmit_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
