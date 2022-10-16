package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type write_bytes_event  bpf write.c -- -I../headers

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	{
		kp, err := link.Tracepoint("syscalls", "sys_enter_write", objs.SyscallEnterWrite, nil)
		if err != nil {
			log.Fatalf("opening tracepoint: %s", err)
		}
		defer kp.Close()

	}
	{
		kp, err := link.Tracepoint("syscalls", "sys_exit_write", objs.SyscallExitWrite, nil)
		if err != nil {
			log.Fatalf("opening tracepoint: %s", err)
		}
		defer kp.Close()

	}
	log.Println("waiting ctrl-c for stop...")
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	rd, err := perf.NewReader(objs.bpfMaps.WriteEvents, 4096*1024)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	writeEventChan := make(chan bpfWriteBytesEvent, 1024)
	go collectData(rd, writeEventChan)
	fmt.Printf("%8s %-16s %5s %5s %10s\n", "time", "cmd", "pid", "fd", "size(bytes)")
	for {
		select {
		case data := <-writeEventChan:
			fmt.Printf("%8s %-16s %5d %5d %10d\n", hhmmss(time.Now()), byteCmd2String(data.TaskCommand), data.Pid, data.Fd, data.Size)
		case <-stopper:
			return
		}
	}
}

func collectData(rd *perf.Reader, writeChan chan bpfWriteBytesEvent) {
	var event bpfWriteBytesEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		writeChan <- event
	}
}

func hhmmss(t time.Time) string {
	return fmt.Sprintf("%02d:%02d:%02d", t.Hour(), t.Minute(), t.Second())
}

func byteCmd2String(n [16]int8) string {
	n1 := []byte{}
	for i := 0; i < len(n); i++ {
		if n[i] != int8(0) {
			n1 = append(n1, byte(n[i]))
		}
	}
	return string(n1)
}
