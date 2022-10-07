package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type write_bytes_map_key  bpf write.c -- -I../headers

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

	tick := time.NewTicker(time.Second)
	fmt.Printf("%8s %-16s %5s %5s %10s\n", "time", "cmd", "pid", "fd", "size(bytes)")
	for {
		select {
		case <-tick.C:
			data := collectData(objs.WriteBytesMap)
			for k, v := range data {
				fmt.Printf("%8s %-16s %5d %5d %10d\n", hhmmss(time.Now()), byteCmd2String(k.TaskCommand), k.Pid, k.Fd, v)
			}
		case <-stopper:
			return
		}
	}
}

func collectData(bpfMap *ebpf.Map) map[bpfWriteBytesMapKey]uint64 {
	var keyRaw []byte
	var dataRaw []byte
	var keys [][]byte
	it := bpfMap.Iterate()
	inOutMap := map[bpfWriteBytesMapKey]uint64{}
	for it.Next(&keyRaw, &dataRaw) {
		var k bpfWriteBytesMapKey
		var data uint64
		err := binary.Read(bytes.NewBuffer(keyRaw), binary.LittleEndian, &k)
		if err != nil {
			fmt.Printf("failed to decode key data: %#v, err = %#v\n", keyRaw, err)
			continue
		}
		err = binary.Read(bytes.NewBuffer(dataRaw), binary.LittleEndian, &data)
		if err != nil {
			fmt.Printf("failed to decode value data: %#v, err = %#v\n", dataRaw, err)
			continue
		}
		if v, ok := inOutMap[k]; !ok {
			inOutMap[k] = data
		} else {
			inOutMap[k] = v + data
		}
		keys = append(keys, keyRaw)
	}
	if err2 := it.Err(); err2 != nil {
		log.Println("iter abbort err = ", err2)
	}
	for _, k := range keys {
		bpfMap.Delete(&k)
	}
	return inOutMap
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
