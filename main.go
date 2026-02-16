package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang gen_execve ./execve.bpf.c -- -I/usr/include/bpf -I.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	colorReset  = "\033[0m"
	colorCyan   = "\033[36m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
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
	kp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.EnterExecve, nil)
	if err != nil {
		log.Fatal("Attaching tracepoint:", err)
	}
	defer kp.Close()

	// Create a reader that listens for events from the eBPF "events" map.
	// The second argument sets the per-CPU buffer size (here: one OS page).
	// The kernel writes execve events into this buffer, and we read them via rd.Read().
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating perf reader: %v", err)
	}

	// Print header
	fmt.Printf("\n%s╔═══════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║          Process Execution Monitor (eBPF Monitor)             ║%s\n", colorCyan, colorReset)
	fmt.Printf("%s╚═══════════════════════════════════════════════════════════════╝%s\n\n", colorCyan, colorReset)
	fmt.Printf("%sTIMESTAMP%s      %sCPU%s      %sPID%s          %sCOMMAND%s            %sPATH%s\n",
		colorCyan, colorReset,
		colorYellow, colorReset,
		colorGreen, colorReset,
		colorBlue, colorReset,
		colorPurple, colorReset)
	fmt.Println(strings.Repeat("─", 80))

	for {

		// Each event corresponds to one execve captured by the eBPF program.
		ev, err := rd.Read()
		if err != nil {
			log.Fatalf("Read fail")
		}

		// If LostSamples > 0, the kernel dropped some events because
		// our user-space reader was too slow or the buffer was too small.
		// We log this and skip parsing this event.
		if ev.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", ev.LostSamples)
			continue
		}

		// Wrap the raw bytes sent by the eBPF program in a buffer so we can decode them.
		b_arr := bytes.NewBuffer(ev.RawSample)

		// Prepare a Go struct matching the C struct layout to hold the decoded data.
		var data exec_data_t

		// Prepare a Go struct matching the C struct layout to hold the decoded data.
		if err := binary.Read(b_arr, binary.LittleEndian, &data); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}

		// Convert byte arrays to clean strings (remove null terminators).
		comm := strings.TrimRight(string(data.Comm[:]), "\x00")
		fname := strings.TrimRight(string(data.F_name[:]), "\x00")
		timestamp := time.Now().Format("15:04:05.000")

		// Print which CPU saw the execve, which command ran, its PID, and the filename.
		fmt.Printf("%s[%s]%s %sCPU:%02d%s │ %sPID:%-6d%s │ %s%-16s%s → %s%s%s\n",
			colorCyan, timestamp, colorReset,
			colorYellow, ev.CPU, colorReset,
			colorGreen, data.Pid, colorReset,
			colorBlue, comm, colorReset,
			colorPurple, fname, colorReset)

	}
}
