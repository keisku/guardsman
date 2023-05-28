package main

import (
	"context"
	"guardsman/pkg/inode"
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
)

type Options struct {
	Pid          int32
	Cgroup       int32
	Output       string
	OutputFormat string
}

func (o *Options) Validate() error {
	logWriter := os.Stdout
	if o.Output != "" {
		f, err := os.Create(o.Output)
		if err != nil {
			return err
		}
		logWriter = f
	}
	var logHandler slog.Handler
	logHandler = slog.NewJSONHandler(logWriter, nil)
	if strings.ToLower(o.OutputFormat) == "text" {
		logHandler = slog.NewTextHandler(logWriter, nil)
	}
	slog.SetDefault(slog.New(logHandler))
	return nil
}

func (o *Options) Run(ctx context.Context) error {
	closeInodeBPF, err := inode.LoadBPFObjects()
	if err != nil {
		return err
	}
	defer closeInodeBPF()

	fileOpenEvents, err := inode.SubscribeFileOpenEvents(ctx, &inode.SubscribeFileOpenEventsOptions{
		Pid:    o.Pid,
		Cgroup: o.Cgroup,
	})
	if err != nil {
		return err
	}
	go func() {
		for e := range fileOpenEvents {
			slog.Info(
				"a lsm/file_open event",
				slog.Int("pid", int(e.Pid)),
				slog.Int("cgroup", int(e.Cgroup)),
				slog.String("nodename", e.Nodename),
				slog.String("parent_task", e.ParentTask),
				slog.String("task", e.Task),
				slog.String("path", e.Path),
			)
		}
	}()
	<-ctx.Done()
	slog.Info("Received signal, exiting program...")
	return nil
}

func NewCmd() *cobra.Command {
	o := &Options{
		Pid:          -1,
		Cgroup:       -1,
		Output:       "",
		OutputFormat: "json",
	}
	cmd := &cobra.Command{
		Use: "guardsman",
	}
	cmd.Flags().Int32VarP(&o.Pid, "pid", "p", o.Pid, "trace this PID only")
	cmd.Flags().Int32Var(&o.Cgroup, "cgroup", o.Cgroup, "trace this cgroup only")
	cmd.Flags().StringVarP(&o.Output, "output", "o", o.Output, "write output to this file instead of stdout")
	cmd.Flags().StringVar(&o.OutputFormat, "output-format", o.OutputFormat, "write output in this format")
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		if err := o.Validate(); err != nil {
			return err
		}
		return o.Run(c.Context())
	}
	return cmd
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Println(err)
		return
	}

	if err := NewCmd().ExecuteContext(ctx); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
