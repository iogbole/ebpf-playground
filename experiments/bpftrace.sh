#!/usr/bin/env bpftrace

// Attach to the tcp_retransmit_skb tracepoint
tracepoint:tcp:tcp_retransmit_skb
{
    // Print timestamp, process name, and process ID
    printf("%-9s %-6d %s\n", "TIME(s)", pid, comm);

    // Check if IPv4 or IPv6
    if (args->family == 2) { // AF_INET (IPv4)
        printf("  src: %d.%d.%d.%d:%d\n",
            args->saddr[0], args->saddr[1], args->saddr[2], args->saddr[3],
            ((args->sport & 0x00FF) << 8) | (args->sport >> 8));
        printf("  dest: %d.%d.%d.%d:%d\n",
            args->daddr[0], args->daddr[1], args->daddr[2], args->daddr[3],
            ((args->dport & 0x00FF) << 8) | (args->dport >> 8));
    } else if (args->family == 10) { // AF_INET6 (IPv6)
        printf("  src: %s:%d\n", ntop(6, args->saddr_v6), ((args->sport & 0x00FF) << 8) | (args->sport >> 8));
        printf("  dest: %s:%d\n", ntop(6, args->daddr_v6), ((args->dport & 0x00FF) << 8) | (args->dport >> 8));
    } else {
        printf("  Unsupported address family\n");
    }

    printf("  state: %d\n", args->state);
    printf("\n");
}
