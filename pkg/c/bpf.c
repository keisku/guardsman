// +build ignore

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define FILE_NAME_LEN 32
#define NAME_MAX 255

char LICENSE[] SEC("license") = "GPL";

struct filter_config {
  int pid;
  int cgroup;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct filter_config);
} filter_config_map SEC(".maps");

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
  u32 idx = 0;
  struct file_open_event *event;
  struct filter_config *conf;

  conf = bpf_map_lookup_elem(&filter_config_map, &idx);
  if (conf == NULL) {
    return 0;
  }
  event =
      bpf_ringbuf_reserve(&file_open_events, sizeof(struct file_open_event), 0);
  if (!event) {
    return 0;
  }

  event->cgroup = bpf_get_current_cgroup_id();
  if (-1 < conf->cgroup && event->cgroup != (u64)conf->cgroup) {
    goto filter_out;
  }
  event->pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  if (-1 < conf->pid && event->pid != (u32)conf->pid) {
    goto filter_out;
  }

  bpf_get_current_comm(&event->task, sizeof(event->task));
  if (bpf_d_path(&file->f_path, (char *)event->path, NAME_MAX) < 0) {
    bpf_ringbuf_discard(event, 0);
    return 0;
  }
  bpf_ringbuf_submit(event, 0);
  return 0;

filter_out:
  bpf_ringbuf_discard(event, 0);
  return 0;
}
