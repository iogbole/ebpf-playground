package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

const (
	objFileName = "retrans1.o"
)

type tcpRetransmitEvent struct {
	Timestamp uint64
	PID       uint32
	Sport     uint16
	Dport     uint16
	Saddr     [4]byte
	Daddr     [4]byte
	SaddrV6   [16]byte
	DaddrV6   [16]byte
	Family    uint16
	State     int32
}

func main() {
	// Load eBPF program
	spec, err := ebpf.LoadCollectionSpec(objFileName)
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// Verbose to catch eBPF verifier issues
			LogLevel: 2,
			LogSize:  262144, // Increase the log size
		},
	})
	if err != nil {
		fmt.Printf("Error loading collection: %s\n", err)
		fmt.Printf("Verifier log: %s\n", coll.Programs["tracepoint__tcp__tcp_retransmit_skb"].VerifierLog)
		os.Exit(1)
	}

	prog := coll.Programs["tracepoint__tcp__tcp_retransmit_skb"]
	if prog == nil {
		panic("Failed to find tracepoint__tcp__tcp_retransmit_skb program")
	}

	// Attach the program to the tcp_retransmit_skb tracepoint
	tp, err := link.Tracepoint("tcp", "tcp_retransmit_skb", prog, nil)
	if err != nil {
		fmt.Printf("Error linking tracepoint: %s\n", err)
		panic(err)
	}
	defer tp.Close()

	// Set up the perf ring buffer to receive events
	events, err := perf.NewReader(coll.Maps["events"], os.Getpagesize())
	if err != nil {
		panic(err)
	}
	defer events.Close()

	// Set up signal handling
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	// Listen for events from the perf ring buffer
	fmt.Println("Monitoring TCP retransmissions...")
	for {
		select {
		case <-sig:
			fmt.Println("\nReceived signal, stopping...")
			events.Close()
			tp.Close()
			os.Exit(0)
			return
		default:
			record, err := events.Read()
			if err != nil {
				if perf.IsUnknownEvent(err) {
					continue
				}
				panic(err)
			}

			event := tcpRetransmitEvent{}
			err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
			if err != nil {
				panic(err)
			}

			timestamp := time.Unix(0, int64(event.Timestamp)).Format("15:04:05")
			src, dst := "", ""

			if event.Family == 2 { // AF_INET
				src = fmt.Sprintf("%d.%d.%d.%d:%d", event.Saddr[0], event.Saddr[1], event.Saddr[2], event.Saddr[3], event.Sport)
				dst = fmt.Sprintf("%d.%d.%d.%d:%d", event.Daddr[0], event.Daddr[1], event.Daddr[2], event.Daddr[3], event.Dport)
			} else if event.Family == 10 { // AF_INET6
				src = fmt.Sprintf("[%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x]:%d",
					event.SaddrV6[0], event.SaddrV6[1], event.SaddrV6[2], event.SaddrV6[3],
					event.SaddrV6[4], event.SaddrV6[5], event.SaddrV6[6], event.SaddrV6[7],
					event.SaddrV6[8], event.SaddrV6[9], event.SaddrV6[10], event.SaddrV6[11],
					event.SaddrV6[12], event.SaddrV6[13], event.SaddrV6[14], event.SaddrV6[15], event.Sport)
				dst = fmt.Sprintf("[%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x]:%d",
					event.DaddrV6[0], event.DaddrV6[1], event.DaddrV6[2], event.DaddrV6[3],
					event.DaddrV6[4], event.DaddrV6[5], event.DaddrV6[6], event.DaddrV6[7],
					event.DaddrV6[8], event.DaddrV6[9], event.DaddrV6[10], event.DaddrV6[11],
					event.DaddrV6[12], event.DaddrV6[13], event.DaddrV6[14], event.DaddrV6[15], event.Dport)
			}
			fmt.Printf("Timestamp=%s, PID=%d, IPFamily=%d, Source=%s, Destination=%s, State=%d\n", timestamp, event.PID, event.Family, src, dst, event.State)
		}
	}
}
