package inode

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 -type file_open_event bpf ../c/bpf.c -- -I../c

type FileOpenEvent struct {
	Cgroup     uint64
	Pid        uint32
	Ret        int32
	Nodename   string
	Task       string
	ParentTask string
	Path       string
}

func convertBpfFileOpenEvent(e bpfFileOpenEvent) FileOpenEvent {
	return FileOpenEvent{
		Cgroup:     e.Cgroup,
		Pid:        e.Pid,
		Ret:        e.Ret,
		Nodename:   fmt.Sprintf("%s", e.Nodename),
		Task:       fmt.Sprintf("%s", e.Task),
		ParentTask: fmt.Sprintf("%s", e.ParentTask),
		Path:       fmt.Sprintf("%s", e.Path),
	}
}

// SubscribeFileOpenEvents subscribes LSM file_open events.
func SubscribeFileOpenEvents(ctx context.Context) (<-chan FileOpenEvent, error) {
	fileOpen, err := link.AttachLSM(link.LSMOptions{Program: objs.bpfPrograms.FileOpen})
	if err != nil {
		return nil, fmt.Errorf("attach a LSM file_open: %s", err)
	}
	rd, err := ringbuf.NewReader(objs.FileOpenEvents)
	if err != nil {
		return nil, fmt.Errorf("open ringbuf reader fo a LSM file_open: %s", err)
	}

	fileOpenEvents := make(chan FileOpenEvent)

	go func() {
		defer fileOpen.Close()
		defer rd.Close()
		defer close(fileOpenEvents)

		var event bpfFileOpenEvent
		for {
			select {
			case <-ctx.Done():
				return
			default:
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
				fileOpenEvents <- convertBpfFileOpenEvent(event)
			}
		}
	}()
	return fileOpenEvents, nil
}
