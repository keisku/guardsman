package inode

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/exp/slog"
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

func removeNullCharacter(b []byte) []byte {
	return bytes.Split(b, []byte("\u0000"))[0]
}

func convertBpfFileOpenEvent(e bpfFileOpenEvent) FileOpenEvent {
	return FileOpenEvent{
		Cgroup:     e.Cgroup,
		Pid:        e.Pid,
		Ret:        e.Ret,
		Nodename:   string(removeNullCharacter(e.Nodename[:])),
		Task:       string(removeNullCharacter(e.Task[:])),
		ParentTask: string(removeNullCharacter(e.ParentTask[:])),
		Path:       string(removeNullCharacter(e.Path[:])),
	}
}

type SubscribeFileOpenEventsOptions struct {
	Pid    int32
	Cgroup int32
}

// SubscribeFileOpenEvents subscribes LSM file_open events.
func SubscribeFileOpenEvents(ctx context.Context, opts *SubscribeFileOpenEventsOptions) (<-chan FileOpenEvent, error) {
	conf := bpfFilterConfig{
		Pid:    -1,
		Cgroup: -1,
	}
	if opts != nil {
		conf.Pid = opts.Pid
		conf.Cgroup = opts.Cgroup
	}
	if err := objs.FilterConfigMap.Put(uint32(0), conf); err != nil {
		return nil, fmt.Errorf("update filter_config: %s", err)
	}
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
					slog.Error("read from ringbuf reader", err)
					continue
				}

				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					slog.Error("parse ringbuf event", err)
					continue
				}
				fileOpenEvents <- convertBpfFileOpenEvent(event)
			}
		}
	}()
	return fileOpenEvents, nil
}
