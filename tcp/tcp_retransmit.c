/*
The program defines two maps, tcp_retransmit_events and tcp_sock_storage, which are used to store and retrieve data.

The program is triggered by the tracepoint/tcp/tcp_retransmit_skb event and when triggered, it copies relevant information about the TCP 
retransmission event from ctx (an instance of the trace_event_raw_tp_tcp_tcp_retransmit_skb struct) into a tcp_event struct (e).

The tcp_event struct includes fields to store the type of event, the source port, destination port, and source/destination IP addresses. 

The IP addresses are stored in byte arrays (saddr and daddr), and their values are copied from the saddr_v6 and daddr_v6 fields of ctx
using the __builtin_memcpy function.

The program then looks up the tcp_sock data structure associated with the TCP connection in the tcp_sock_storage map using bpf_map_lookup_elem. 

Once the data is retrieved, the program can extract the desired metrics from the tcp_sock structure.

Finally, the program outputs the tcp_event structure to the tcp_retransmit_events map using bpf_perf_event_output. 

The tcp_retransmit_events map is of type BPF_MAP_TYPE_PERF_EVENT_ARRAY, which allows the program to store and retrieve performance data.
*/

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#define EVENT_TYPE_TCP_RETRANSMIT 1

struct tcp_event {
    int type;
    __u16 sport;
    __u16 dport;
    __u8 saddr[16];
    __u8 daddr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tcp_retransmit_events SEC(".maps");

struct trace_event_raw_tp_tcp_tcp_retransmit_skb {
    __u64 unused;
    void *sbkaddr;
    void *skaddr;
#if __KERNEL >= 420
    int state;
#endif
    __u16 sport;
    __u16 dport;
#if __KERNEL >= 512
    __u16 family;
#endif
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct tcp_sock));
} tcp_sock_storage SEC(".maps");

SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb(struct trace_event_raw_tp_tcp_tcp_retransmit_skb *ctx)
{
    struct tcp_event e = {
        .type = EVENT_TYPE_TCP_RETRANSMIT,
        .sport = ctx->sport,
        .dport = ctx->dport,
    };

    //One of the key benefits of using __builtin_memcpy over memcpy is that it can be optimized by the compiler to generate more efficient machine code

    __builtin_memcpy(&e.saddr, &ctx->saddr_v6, sizeof(e.saddr));
    __builtin_memcpy(&e.daddr, &ctx->daddr_v6, sizeof(e.daddr));

    int key = 0;
    struct tcp_sock *tp = bpf_map_lookup_elem(&tcp_sock_storage, &key);
    if (!tp) {
        return 0;
    }

    // Here you can access the fields of tp to extract the desired metrics

    bpf_perf_event_output(ctx, &tcp_retransmit_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
