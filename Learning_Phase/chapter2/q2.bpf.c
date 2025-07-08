#include "../vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[16]);
    __type(value, u64);
} call_counts SEC(".maps");

static __always_inline void update_counter(const char *key)
{
    u64 count = 1;
    u64 *val = bpf_map_lookup_elem(&call_counts, key);
    if (!val)
        bpf_map_update_elem(&call_counts, key, &count, BPF_ANY);
    else
        (*val)++;
}



SEC("tp/syscalls/sys_enter_execve")
int handle_openat(void *ctx)
{

    char key[16] = "openat";
    bpf_printk("Logging openat\n");
    update_counter(key);
    return 0;
}

SEC("tp/syscalls/sys_enter_openat2")
int handle_openat2(void *ctx)
{
    char key[16] = "openat2";
    bpf_printk("Logging openat2\n");
    update_counter(key);
    return 0;
}

SEC("tp/syscalls/sys_enter_write")
int handle_write(void *ctx)
{
    char key[16] = "write";
    bpf_printk("Logging write");
    update_counter(key);
    return 0;
}