#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    char command[16];
    char filename[256];
    int opcode;
};

struct openat_ctx {
    __u64 __unused_syscall_header1;
    __u64 __unused_syscall_header2;
    int syscall_nr;
    int dfd;
    const char *filename;
    int flags;
    __u16 mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct openat_ctx *ctx) {

    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;

    event->opcode = 0; // OPEN operation

    // Fill in event details
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->filename);

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;

}

