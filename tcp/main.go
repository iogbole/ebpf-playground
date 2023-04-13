package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	mapKey        = 0
	collectorProg = "tcp_retransmit.o"
)

type tcpEvent struct {
	Type     uint32
	Sport    uint16
	Dport    uint16
	SAddr    [4]byte
	DAddr    [4]byte
	Retrans  uint32
	RTO      uint32
	RTT      uint32
	SndCwnd  uint32
	Ssthresh uint32
}

func main() {
	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec(collectorProg)
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{}})
	if err != nil {
		panic(err)
	}
	defer coll.Close()

	prog := coll.Programs["tcp_retransmit_skb"]

	// Attach tracepoint
	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", prog, nil)
	if err != nil {
		panic(err)
	}
	defer tp.Close()

	// Set up perf event reader
	rd, err := perf.NewReader(coll.Maps["tcp_retransmit_events"], os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	// Set up signal handling to close the reader
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	// Start processing events
	for {
		record, err := rd.Read()
		if err != nil {
			if err == perf.ErrClosed {
				break
			}
			panic(err)
		}

		var event tcpEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			panic(err)
		}

		fmt.Printf("Event: Type=%d, Source=%v:%d, Destination=%v:%d, Retrans=%d, RTO=%d, RTT=%d, SndCwnd=%d, Ssthresh=%d\n",
			event.Type, event.SAddr, event.Sport, event.DAddr, event.Dport, event.Retrans, event.RTO, event.RTT, event.SndCwnd, event.Ssthresh)
	}
}
