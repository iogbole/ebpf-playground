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

// tcpEvent struct holds the data sent from the eBPF program.
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

	// Create a new eBPF collection with default options
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{}})
	if err != nil {
		panic(err)
	}
	defer coll.Close()

	// Get the "tcp_retransmit_skb" program from the collection
	prog := coll.Programs["tcp_retransmit_skb"]

	// Attach the tracepoint to the "tcp/tcp_retransmit_skb" event
	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", prog, nil)
	if err != nil {
		panic(err)
	}
	defer tp.Close()

	// Set up the perf event reader to read from the "tcp_retransmit_events" map
	rd, err := perf.NewReader(coll.Maps["tcp_retransmit_events"], os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	// Set up signal handling to gracefully close the reader when the program is interrupted
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	// Start processing events from the perf event reader
	for {
		record, err := rd.Read()
		if err != nil {
			if err == perf.ErrClosed {
				break
			}
			panic(err)
		}

		// Parse the raw sample data into a tcpEvent struct
		var event tcpEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			panic(err)
		}
		// Print the tcpEvent data to the console. I will do something else with this in the future instead of printing to console.
		fmt.Printf("Event: Type=%d, Source=%v:%d, Destination=%v:%d, Retrans=%d, RTO=%d, RTT=%d, SndCwnd=%d, Ssthresh=%d\n",
			event.Type, event.SAddr, event.Sport, event.DAddr, event.Dport, event.Retrans, event.RTO, event.RTT, event.SndCwnd, event.Ssthresh)
	}
}
