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
// #include <linux/socket.h> //commenting because ip.family isn't only support in kernerl 5.12 and above. I am using 5.10.

// Define the event type for TCP retransmissions
#define EVENT_TYPE_TCP_RETRANSMIT 1

// Declare the tcp_event struct for storing retransmission event data
struct tcp_event
{
    int type;
    __u16 sport;
    __u16 dport;
    __u8 saddr[16];
    __u8 daddr[16];
    __u32 retrans;
    __u32 rto;
    __u32 rtt;
    __u32 snd_cwnd;
    __u32 ssthresh;
};

// Define a map for perf_event_array to collect TCP retransmission events
struct
{
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} tcp_retransmit_events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(struct tcp_sock));
} tcp_sock_storage SEC(".maps");

// Define a struct to store trace event data from tcp_retransmit_skb tracepoint
struct trace_event_raw_tp_tcp_tcp_retransmit_skb
{
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

// Attach the eBPF program to the tcp/tcp_retransmit_skb tracepoint
SEC("tracepoint/tcp/tcp_retransmit_skb")
int tcp_retransmit_skb(struct trace_event_raw_tp_tcp_tcp_retransmit_skb *ctx)
{

    // Look up the tcp_sock data in the per-CPU array map

    if (!ctx->skaddr)
    {
        return 0;
    }

    int key = 0;
    struct tcp_sock *tp = bpf_map_lookup_elem(&tcp_sock_storage, &key);
    if (!tp)
    {
        return 0;
    }

    bpf_probe_read_kernel(tp, sizeof(struct tcp_sock), ctx->skaddr);

    /**
   - type: A field that indicates the type of the event, initialized to EVENT_TYPE_TCP_RETRANSMIT.

  - sport and dport: Fields that store the source and destination port numbers of the TCP connection,
     initialized to the corresponding fields (sport and dport) in the ctx variable, which is a pointer
     to an instance of the trace_event_raw_tp_tcp_tcp_retransmit_skb struct.
  - retrans: A field that stores the total number of retransmissions for the TCP connection,
     initialized to the total_retrans field in the tp variable, which is a pointer to a tcp_sock data
     structure retrieved from a BPF map.
  - rto: A field that stores the retransmission timeout (RTO) for the TCP connection, initialized to
     the frto field in the tp variable.
  - rtt: A field that stores the smoothed round-trip time (SRTT) for the TCP connection, initialized to
     the srtt_us field in the tp variable.
  - snd_cwnd: A field that stores the congestion window size for the TCP connection, initialized to the
     snd_cwnd field in the tp variable.
  - ssthresh: A field that stores the slow start threshold for the TCP connection, initialized to the
     snd_ssthresh field in the tp variable.

    */
    struct tcp_event e = {
        .type = EVENT_TYPE_TCP_RETRANSMIT,
        .sport = ctx->sport,
        .dport = ctx->dport,
        .retrans = tp->total_retrans,
        .rto = tp->frto,
        .rtt = tp->srtt_us,
        .snd_cwnd = tp->snd_cwnd,
        .ssthresh = tp->snd_ssthresh,
    };

    // Use __builtin_memcpy to copy data from the tracepoint context to the tcp_event struct
    // One of the key benefits of using __builtin_memcpy over memcpy is that it can be optimized
    // by the compiler to generate more efficient machine code.

    // 13-april, I found a bug where destination source is always 0.0.0.0.0. So had to add a condition to support both IPV4 * 6.
    //  commenting this out since the family field is only available in the trace_event_raw_tp_tcp_tcp_retransmit_skb struct for kernel version 5.12 and above.
    /** if (ctx->family == AF_INET)
      {
          __builtin_memcpy(&e.saddr, &ctx->saddr, sizeof(ctx->saddr));
          __builtin_memcpy(&e.daddr, &ctx->daddr, sizeof(ctx->daddr));
      }
      else if (ctx->family == AF_INET6)
      {
          __builtin_memcpy(&e.saddr, &ctx->saddr_v6, sizeof(ctx->saddr_v6));
          __builtin_memcpy(&e.daddr, &ctx->daddr_v6, sizeof(ctx->daddr_v6));
      }
      **/

    /**
     *
     * To handle this case, you can use the length of the saddr field in the trace_event_raw_tp_tcp_tcp_retransmit_skb
     *  struct as an alternative approach to determine if the connection is IPv4 or IPv6. You can do this by checking
     *  if the saddr field is all zeros, and if so, the connection is using IPv6. Otherwise, it's using IPv4.
     */

    bool is_ipv4 = true;
    for (int i = 0; i < sizeof(ctx->saddr); i++)
    {
        if (ctx->saddr[i] != 0)
        {
            is_ipv4 = false;
            break;
        }
    }

    if (is_ipv4)
    {
        __builtin_memcpy(&e.saddr, &ctx->saddr, sizeof(ctx->saddr));
        __builtin_memcpy(&e.daddr, &ctx->daddr, sizeof(ctx->daddr));
    }
    else
    {
        __builtin_memcpy(&e.saddr, &ctx->saddr_v6, sizeof(ctx->saddr_v6));
        __builtin_memcpy(&e.daddr, &ctx->daddr_v6, sizeof(ctx->daddr_v6));
    }

    // Access the fields of tp to extract the desired metrics
    // Output the tcp_event data to the perf_event_array
    bpf_perf_event_output(ctx, &tcp_retransmit_events, BPF_F_CURRENT_CPU, &e, sizeof(e));

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
