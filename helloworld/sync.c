// +build ignore

#define __TARGET_ARCH_arm64 1
//#define __TARGET_ARCH_x86 1

#include "../headers/common.h"



char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tracepoint/syscalls/sys_enter_sync")
int syscall_enter_sync(void *info) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    char cmd[16] = "";
    bpf_get_current_comm(&cmd, sizeof(cmd));
    bpf_printk("hello world from my pid = %d, cmd = %s\n", pid,cmd);
    return 0;
}
