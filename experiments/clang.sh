#clang -O2 -target bpf -c tcp_retransmit_core.c -o tcp_retransmit_core.o
#Clang version must be > 13
clang -O2 -g -target bpf -c tcp_retransmit.c -o tcp_retransmit.o -I/usr/include -I/usr/src/linux-headers-$(uname -r)/include  -D __BPF_TRACING__



