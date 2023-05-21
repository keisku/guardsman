package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 -type file_open_audit_event bpf ../c/bpf.c -- -I../c

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
		log.Fatalf("load: %s", err)
	}
	defer objs.Close()

	rfOpen, err := link.AttachLSM(link.LSMOptions{Program: objs.bpfPrograms.RestrictedFileOpen})
	if err != nil {
		log.Fatalf("attach the LSM program: %s", err)
	}
	defer rfOpen.Close()

	log.Printf("Listening for events..")

	// Open a ringbuf reader from userspace RINGBUF map described in the
	// eBPF C program.
	rd, err := ringbuf.NewReader(objs.FileOpenAuditEvents)
	if err != nil {
		log.Fatalf("open ringbuf reader: %s", err)
	}
	defer rd.Close()

	var event bpfFileOpenAuditEvent
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				log.Printf("read from ringbuf reader: %s", err)
				continue
			}

			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("parse ringbuf event: %s", err)
				continue
			}

			log.Printf("pid: %d, cgroup: %d, task: %s, path: %s", event.Pid, event.Cgroup, event.Task, event.Path)
		}
	}()

	<-ctx.Done()
	log.Println("Received signal, exiting program...")
}
