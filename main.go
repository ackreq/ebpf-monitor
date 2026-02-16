package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang gen_execve ./execve.bpf.c -- -I/usr/include/bpf -I.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

type exec_data_t struct {
	Pid    uint32
	F_name [32]byte
	Comm   [32]byte
}

func main() {
	// Remove the 64KB locked-memory limit so eBPF can allocate kernel memory.
	// On old kernels (< 5.11), we must raise this limit or eBPF loading fails.
	// On new kernels (≥ 5.11), this is a harmless no-op (uses cgroup accounting).
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Failed to remove memlock limit:", err)
	}

	objs := gen_execveObjects{}

	// Load eBPF program into kernel and fill the objs
	if err := loadGen_execveObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}

	// Attach the program to the execve hook - now it's watching!
	link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve)

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("reader err")
	}

	for {
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}

		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}

		b_arr := bytes.NewBuffer(ev.RawSample)

		var data exec_data_t
		if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		fmt.Printf("On cpu %02d %s ran : %d %s\n",
			ev.CPU, data.Comm, data.Pid, data.F_name)
	}
}
