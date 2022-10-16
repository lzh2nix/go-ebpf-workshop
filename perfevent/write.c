// +build ignore

//#include <stddef.h>
#define __TARGET_ARCH_arm64 1
//##define __TARGET_ARCH_x86 1

#include "../headers/vmlinux.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_core_read.h"
#include "../headers/bpf_tracing.h"
#include "../headers/bpf_endian.h"


#define TASK_COMMAND_LEN  16
#define FILE_NAME_LEN  128

char __license[] SEC("license") = "Dual MIT/GPL";


struct bpf_map_def SEC("maps") write_fd_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64),
	.max_entries = 1024,
};

struct write_bytes_event {
    u32 pid;
    char task_command[TASK_COMMAND_LEN];
    u64 fd;
    u64 size;
    char file_name[FILE_NAME_LEN];
};
struct write_bytes_event *unused_write_bytes_event_event __attribute__((unused));

struct bpf_map_def SEC("maps") write_events = {
	.type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
};

// This struct is defined according to the following format file:
// //sys/kernel/debug/tracing/events/syscalls/sys_enter_write/format
struct write_in {
	/* The first 8 bytes is not allowed to read */
	unsigned long pad;

	int nr;
    unsigned long fd;
    unsigned long buf;
    unsigned long count;
};
SEC("tracepoint/syscalls/sys_enter_writ")
int syscall_enter_write(struct write_in *info) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 fd;
    bpf_probe_read(&fd, sizeof(u64), &info->fd);
    bpf_map_update_elem(&write_fd_map, &tid, &fd,BPF_NOEXIST);
    return 0;
}

// This struct is defined according to the following format file:
// //sys/kernel/debug/tracing/events/syscalls/sys_exit_write/format
struct write_out {
	/* The first 8 bytes is not allowed to read */
	unsigned long pad;

	int nr;
    long ret;
};

SEC("tracepoint/syscalls/sys_exit_write")
int syscall_exit_write(struct write_out *info) {
    u64 tid = bpf_get_current_pid_tgid();
    u64 *fdp =  bpf_map_lookup_elem(&write_fd_map,&tid);
    if (!fdp) {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct write_bytes_event event = {.pid = pid};
    bpf_probe_read(&event.fd, sizeof(event.pid), fdp);
    bpf_get_current_comm(&event.task_command, sizeof(event.task_command));
    long ret;
    bpf_probe_read(&ret, sizeof(ret), &info->ret);
    if (ret >0) {
        event.size = ret;
        bpf_perf_event_output(info, &write_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    }
    bpf_map_delete_elem(&write_fd_map,&tid);
    return 0;
}
