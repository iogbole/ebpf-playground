# proj-9



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


