#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    __u32 pid;
    char command[16];
    char filename[256];
    int opcode;
};

struct fd_key {
    int fd;
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16 MB
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct fd_key);
    __type(value, char[256]);
} fd_to_filename SEC(".maps");

// Temporary map for passing filename from openat entry to exit, keyed by tid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // tid
    __type(value, char[256]);
} pending_open_files SEC(".maps");

// sys_enter_openat context
struct openat_ctx {
    __u64 __unused_syscall_header1;
    __u64 __unused_syscall_header2;
    int syscall_nr;
    int dfd;
    const char *filename;
    int flags;
    __u16 mode;
};

// sys_exit_openat context
struct exit_openat_ctx {
    __u64 pad;
    int syscall_nr;
    long ret;
};

// sys_enter_close context
struct close_ctx {
    __u64 __unused_syscall_header1;
    int syscall_nr;
    int fd;
};

// sys_enter_unlinkat context
struct unlinkat_ctx {
    __u64 __unused_syscall_header1;
    __u64 __unused_syscall_header2;
    int syscall_nr;
    int dfd;
    const char *pathname;
    int flags;
};

// sys_enter_renameat2 context
struct renameat2_ctx {
    __u64 __unused_syscall_header1;
    __u64 __unused_syscall_header2;
    int syscall_nr;
    int olddfd;
    const char *oldname;
    int newdfd;
    const char *newname;
    int flags;
};

// sys_enter_fchmodat context
struct fchmodat_ctx {
    __u64 __unused_syscall_header1;
    __u64 __unused_syscall_header2;
    int syscall_nr;
    int dfd;
    const char *filename;
    __u32 mode;
};

// sys_enter_fchownat context
struct fchownat_ctx {
    __u64 __unused_syscall_header1;
    __u64 __unused_syscall_header2;
    int syscall_nr;
    int dfd;
    const char *filename;
    __u32 uid;
    __u32 gid;
    int flags;
};

enum event_opcode {
    EVENT_OPEN = 0,
    EVENT_UNLINK = 1,
    EVENT_RENAME = 2,
    EVENT_RENAMED = 3,
    EVENT_FCHMODAT = 4,
    EVENT_FCHOWNAT = 5
};

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct openat_ctx *ctx) {
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    event->opcode = EVENT_OPEN;

    // Fill in event details
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->filename);

    // Save filename in pending_open_files keyed by tid
    __u64 tid = bpf_get_current_pid_tgid();
    char filename[256];
    bpf_probe_read_user_str(filename, sizeof(filename), ctx->filename);
    bpf_map_update_elem(&pending_open_files, &tid, filename, BPF_ANY);

    // Submit the event to the ring buffer
    bpf_ringbuf_submit(event, 0);

    return 0;

}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit_openat(struct exit_openat_ctx *ctx) {
    if (ctx->ret < 0) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    char *filename = bpf_map_lookup_elem(&pending_open_files, &tid);
    if (!filename) return 0;
    int pid = tid >> 32;
    struct fd_key key = {.fd = ctx->ret, .pid = pid};
    bpf_map_update_elem(&fd_to_filename, &key, filename, BPF_ANY);
    bpf_printk("fd_to_filename: fd=%d pid=%d name=%s\n", key.fd, key.pid, filename);
    bpf_map_delete_elem(&pending_open_files, &tid);
    return 0;
}

SEC("tp/syscalls/sys_enter_unlinkat")
int handle_unlinkat(struct unlinkat_ctx *ctx) {
    bpf_printk("handle_unlinkat called\n");
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    event->opcode = EVENT_UNLINK;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->pathname);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int handle_renameat2(struct renameat2_ctx *ctx) {
    bpf_printk("handle_renameat2 called\n");
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    event->opcode = EVENT_RENAME;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->oldname);
    bpf_ringbuf_submit(event, 0);
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    event->opcode = EVENT_RENAMED;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->newname);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct fchmodat_ctx *ctx) {
    bpf_printk("handle_fchmodat called\n");
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    event->opcode = EVENT_FCHMODAT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchownat")
int handle_fchownat(struct fchownat_ctx *ctx) {
    bpf_printk("handle_fchownat called\n");
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    event->opcode = EVENT_FCHOWNAT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), ctx->filename);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct close_ctx *ctx) {
    bpf_printk("handle_close called\n");
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct fd_key key = {.fd = ctx->fd, .pid = pid};
    bpf_map_delete_elem(&fd_to_filename, &key);
    return 0;
}

