#!/usr/bin/env bpftrace

tracepoint:tcp:tcp_retransmit_skb
{
    $sport = ((uint16)args->sport);
    $dport = ((uint16)args->dport);
    $sk = (struct sock *)args->skaddr;

    printf("TCP retransmit: sport=%u dport=%u\n", $sport, $dport);
}

