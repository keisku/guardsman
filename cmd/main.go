package main

import (
	"context"
	"guardsman/pkg/inode"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println(err)
		return
	}

	closeInodeBPF, err := inode.LoadBPFObjects()
	if err != nil {
		log.Println(err)
		return
	}
	defer closeInodeBPF()
	fileOpenEvents, err := inode.SubscribeFileOpenEvents(ctx)
	if err != nil {
		log.Println(err)
		return
	}
	go func() {
		for e := range fileOpenEvents {
			log.Printf("pid: %d, cgroup: %d, task: %s, path: %s", e.Pid, e.Cgroup, e.Task, e.Path)
		}
	}()

	<-ctx.Done()
	log.Println("Received signal, exiting program...")
}
