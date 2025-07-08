#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct data_t {
    u64 unused;
    u64 unused2;
    char * filename;
    int flags;
    umode_t mode;
};

SEC("tracepoint/syscalls/sys_enter_open")
int handle_sys_enter_open(struct data_t *ctx) {
    char filename[256];
    const char *user_filename = (const char *)ctx->filename;
    bpf_probe_read_user_str(filename, sizeof(filename), user_filename);

    if(__builtin_memcmp(filename, "/etc/shadow", 11) == 0) {
        bpf_printk("Opening file------------: %s\n", filename);    
    }

    bpf_printk("Opening file: %s\n", filename);
    return 0;
}
