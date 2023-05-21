package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 bpf ../c/src/bpf.c -- -I../c/headers

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	rfOpen, err := link.AttachLSM(link.LSMOptions{Program: objs.bpfPrograms.RestrictedFileOpen})
	if err != nil {
		log.Fatalf("attach the BPF program to sys_enter_execve tracepoint: %s", err)
	}
	defer rfOpen.Close()

	log.Printf("Listening for events..")

	// /sys/kernel/debug/tracing/trace_pipe is a special file in the /sys/kernel/debug
	// filesystem that provides access to the trace data generated by the Linux kernel's
	// dynamic tracing facility
	tracePipeFile := "/sys/kernel/debug/tracing/trace_pipe"
	tracePipe, err := os.Open(tracePipeFile)
	if err != nil {
		log.Fatalf("open %s: %s\n", tracePipeFile, err)
	}
	defer tracePipe.Close()

	go func() {
		// Create a bufio.Scanner to read the trace data.
		scanner := bufio.NewScanner(tracePipe)
		// Read and print the trace data.
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
		if err := scanner.Err(); err != nil {
			if !errors.Is(err, fs.ErrClosed) {
				log.Println(err)
			}
		}
	}()

	<-ctx.Done()
	log.Println("Received signal, exiting program...")
}