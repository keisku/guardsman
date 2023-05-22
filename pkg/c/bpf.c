// +build ignore

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define FILE_NAME_LEN 32
#define NAME_MAX 255

char LICENSE[] SEC("license") = "GPL";

struct file_open_event {
  u64 cgroup;
  u32 pid;
  int ret;
  unsigned char nodename[NEW_UTS_LEN + 1];
  unsigned char task[TASK_COMM_LEN];
  unsigned char parent_task[TASK_COMM_LEN];
  unsigned char path[NAME_MAX];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} file_open_events SEC(".maps");

// Force emitting struct event into the ELF.
const struct file_open_event *unused __attribute__((unused));

SEC("lsm/file_open")
int
BPF_PROG(file_open, struct file *file)
{
  struct file_open_event *event;

  event =
      bpf_ringbuf_reserve(&file_open_events, sizeof(struct file_open_event), 0);
  if (!event) {
    return 0;
  }

  event->cgroup = bpf_get_current_cgroup_id();
  event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  bpf_get_current_comm(&event->task, sizeof(event->task));
  if (bpf_d_path(&file->f_path, (char *)event->path, NAME_MAX) < 0) {
    bpf_ringbuf_discard(event, 0);
    return 0;
  }

  bpf_ringbuf_submit(event, 0);
  return 0;
}