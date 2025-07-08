#include "./../vmlinux.h"
// #include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if(pid & 1) bpf_trace_printk("Odd pid: %d\n", sizeof("Odd pid: %d\n"), pid);
    else bpf_trace_printk("Even pid: %d\n", sizeof("Even pid: %d\n"), pid);
    return 0;
}