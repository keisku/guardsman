// +build ignore

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "common.h"
#include "vmlinux.h"

#define FILE_NAME_LEN 32
#define NAME_MAX 255

char LICENSE[] SEC("license") = "GPL";

struct file_open_audit_event {
  u64 cgroup;
  u32 pid;
  int ret;
  char nodename[NEW_UTS_LEN + 1];
  char task[TASK_COMM_LEN];
  char parent_task[TASK_COMM_LEN];
  unsigned char path[NAME_MAX];
};

SEC("lsm/file_open")
int BPF_PROG(restricted_file_open, struct file *file) {
  struct file_open_audit_event event = {};
  event.cgroup = bpf_get_current_cgroup_id();
  event.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
  bpf_get_current_comm(&event.task, sizeof(event.task));
  if (bpf_d_path(&file->f_path, (char *)event.path, NAME_MAX) < 0) {
    return 0;
  }
  bpf_printk("cgroup=%d, pid=%d ", event.cgroup, event.pid);
  bpf_printk("file path=%s, comm=%s\n", event.path, event.task);
  return 0;
}
