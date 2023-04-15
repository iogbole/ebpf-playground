# proj-9

##  Setting up 

Clone repo

```
cd tcp 

./clang.sh  # Compile C code 

go build main.go # Build go code  

./main # run go code 

```
## Simulate packet loss to cause TCP transmission 



Mess around with the network parket from kernel by using Traffic control (`tc`) 

To start
`sudo tc qdisc add dev lo root netem loss 10%` 

To stop 
sudo tc qdisc del dev lo root 

Note this might disconnct your SSH connection if you increase it any higher.  

See the `add_net_load.sh` script for details


## Output 

```
Event: Type=1, Source=[127 0 0 1]:1, Destination=[0 0 0 0]:0, Retrans=0, RTO=4294901760, RTT=16777343, SndCwnd=0, Ssthresh=0
Event: Type=1, Source=[127 0 0 1]:1, Destination=[0 0 0 0]:0, Retrans=0, RTO=4294901760, RTT=16777343, SndCwnd=0, Ssthresh=0
Event: Type=1, Source=[127 0 0 1]:1, Destination=[0 0 0 0]:0, Retrans=0, RTO=4294901760, RTT=16777343, SndCwnd=0, Ssthresh=0
Event: Type=1, Source=[127 0 0 1]:1, Destination=[0 0 0 0]:0, Retrans=0, RTO=4294901760, RTT=16777343, SndCwnd=0, Ssthresh=0
Event: Type=1, Source=[127 0 0 1]:1, Destination=[0 0 0 0]:0, Retrans=0, RTO=4294901760, RTT=16777343, SndCwnd=0, Ssthresh=0
Event: Type=1, Source=[86 30 33 20]:1, Destination=[0 0 0 0]:0, Retrans=0, RTO=4294901760, RTT=2418679724, SndCwnd=0, Ssthresh=0
```
The output

`Event: Type=1, Source=[127 0 0 1]:1, Destination=[0 0 0 0]:0, Retrans=0, RTO=4294901760, RTT=16777343, SndCwnd=0, Ssthresh=0`

represents a single event related to a TCP retransmission. Here's the meaning of each field:

- Type: The event type, where 1 indicates a TCP retransmission event.
- Source: The source IP address and port number. In this case, the source is [127 0 0 1]:1, which is localhost (127.0.0.1) with port number 1.
- Destination: The destination IP address and port number. In this case, the destination is [0 0 0 0]:0, which is an unspecified address and port.
- Retrans: The total number of retransmissions for the TCP connection. In this case, it is 0.
- RTO (Retransmission Timeout): The current retransmission timeout value in microseconds. In this case, it is 4294901760 µs.
- RTT (Round-Trip Time): The smoothed round-trip time in microseconds. In this case, it is 16777343 µs.
- SndCwnd (Send Congestion Window): The size of the TCP send congestion window, which controls the amount of data that can be in transit at any given time. In this case, the value is 0.
- Ssthresh (Slow Start Threshold): The slow-start threshold in the TCP congestion control algorithm. When the congestion window size is below this threshold, the slow-start phase is active. In this case, the value is 0.

This output indicates that a TCP retransmission event has been captured, and it provides detailed information about the TCP connection's state, such as the number of retransmissions, the round-trip time, and the congestion window size. 

-- 

## Tips 

1. Display tracepoint return fields 
`sudo cat /sys/kernel/debug/tracing/events/tcp/tcp_retransmit_skb/format`

2. To create the vmlinux.h file, you will need to use the BPF CO-RE (Compile Once, Run Everywhere) feature provided by bpftool. The vmlinux.h file is a generated header file that includes kernel structures and definitions required for BPF programs.

To generate the vmlinux.h file, follow these steps:

First, ensure you have bpftool installed on your system. You can usually find it in the linux-tools package or compile it from the kernel source.

```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Now you should have a vmlinux.h file in your current working directory. You can include this file in your eBPF C programs to access kernel structures and definitions.

Please note that the vmlinux.h file is specific to the kernel version and configuration, so it's recommended to generate it for each target system where you want to run your eBPF program.


## Refs
https://github.com/iovisor/bcc/blob/master/tools/tcpretrans_example.txt