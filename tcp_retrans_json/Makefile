CC := clang
CFLAGS := -O2 -g -target bpf -I/usr/include -I/usr/src/linux-headers-$(shell uname -r)/include -D__BPF_TRACING__
SRC := retrans.c
OBJ := retrans.o

all: build_ebpf build_go

build_ebpf: $(OBJ)

$(OBJ): $(SRC)
	$(CC) $(CFLAGS) -c $< -o $@

build_go:
	sudo go run retrans.go

clean:
	rm -f $(OBJ)

.PHONY: all build_ebpf build_go clean
