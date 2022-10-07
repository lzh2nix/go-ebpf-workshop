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

char __license[] SEC("license") = "Dual MIT/GPL";


struct bpf_map_def SEC("maps") write_fd_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u64),
	.value_size  = sizeof(u64),
	.max_entries = 1024,
};

struct write_bytes_map_key {
    u32 pid;
    char task_command[TASK_COMMAND_LEN];
    u64 fd;
};
struct write_bytes_map_key *unused_write_bytes_map_key_event __attribute__((unused));

struct bpf_map_def SEC("maps") write_bytes_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(struct write_bytes_map_key),
	.value_size  = sizeof(u64),
	.max_entries = 1024,
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
    //bpf_probe_read(&fd, sizeof(fd), val);
    struct write_bytes_map_key k = {.pid = pid};
    bpf_probe_read(&k.fd, sizeof(k.pid), fdp);
    bpf_get_current_comm(&k.task_command, sizeof(k.task_command));

    // record write bytes
    u64 *bytes = bpf_map_lookup_elem(&write_bytes_map,&k);
    long ret;
    bpf_probe_read(&ret, sizeof(ret), &info->ret);
    if (ret >0) {
        if (bytes) {
            *bytes += ret;
        } else {
            bpf_map_update_elem(&write_bytes_map,&k, &ret, BPF_NOEXIST);
        }
    }
    // write fd end, delete the key
    bpf_map_delete_elem(&write_fd_map,&tid);
    return 0;
}
