#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";



SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
    bpf_trace_printk("Tracing execve\n", sizeof("Tracing execve\n"));
    return 0;
}