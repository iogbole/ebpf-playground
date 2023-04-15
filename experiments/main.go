package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	mapKey        = 0
	collectorProg = "tcp_retransmit.o"
)

type tcpEvent struct {
	Timestamp uint64
	Skbaddr   uint64
	Skaddr    uint64
	State     int32
	Sport     uint16
	Dport     uint16
	SAddr     [4]byte
	DAddr     [4]byte
	SaddrV6   [16]byte
	DaddrV6   [16]byte
	Family    uint16
}

func main() {
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
	if prog == nil {
		panic("Failed to find tcp_retransmit_skb program")
	}

	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", prog, nil)
	if err != nil {
		panic(err)
	}
	defer tp.Close()

	rd, err := perf.NewReader(coll.Maps["tcp_retransmit_events"], os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	fmt.Println("Monitoring TCP retransmissions...")
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsUnknownEvent(err) {
				continue
			}
			panic(err)
		}

		fmt.Printf("Record: %v\n", record)                          // Add this line
		fmt.Printf("RawSample length: %d\n", len(record.RawSample)) // Add this line

		event := tcpEvent{}

		if len(record.RawSample) < binary.Size(event) {
			fmt.Println("Insufficient data in RawSample")
			continue
		}

		err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
		if err != nil {
			panic(err)
		}

		timestamp := time.Unix(0, int64(event.Timestamp)).Format(time.RFC3339)
		var srcIP, dstIP string
		if event.Family == 2 { // AF_INET
			srcIP = fmt.Sprintf("%d.%d.%d.%d", event.SAddr[0], event.SAddr[1], event.SAddr[2], event.SAddr[3])
			dstIP = fmt.Sprintf("%d.%d.%d.%d", event.DAddr[0], event.DAddr[1], event.DAddr[2], event.DAddr[3])
		} else if event.Family == 10 { // AF_INET6
			srcIP = fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
				event.SaddrV6[0], event.SaddrV6[1], event.SaddrV6[2], event.SaddrV6[3],
				event.SaddrV6[4], event.SaddrV6[5], event.SaddrV6[6], event.SaddrV6[7],
				event.SaddrV6[8], event.SaddrV6[9], event.SaddrV6[10], event.SaddrV6[11],
				event.SaddrV6[12], event.SaddrV6[13], event.SaddrV6[14], event.SaddrV6[15])
			dstIP = fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x",
				event.DaddrV6[0], event.DaddrV6[1], event.DaddrV6[2], event.DaddrV6[3],
				event.DaddrV6[4], event.DaddrV6[5], event.DaddrV6[6], event.DaddrV6[7],
				event.DaddrV6[8], event.DaddrV6[9], event.DaddrV6[10], event.DaddrV6[11],
				event.DaddrV6[12], event.DaddrV6[13], event.DaddrV6[14], event.DaddrV6[15])
		}

		output := map[string]interface{}{
			"timestamp": timestamp,
			"pid":       event.PID,
			"state":     event.State,
			"family":    event.Family,
			"source": map[string]interface{}{
				"ip":   srcIP,
				"port": event.Sport,
			},
			"destination": map[string]interface{}{
				"ip":   dstIP,
				"port": event.Dport,
			},
		}
		jsonOutput, err := json.Marshal(output)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(jsonOutput))
	}
}
