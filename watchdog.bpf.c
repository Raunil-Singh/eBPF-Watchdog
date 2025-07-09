#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "event_header.h"

char LICENSE[] SEC("license") = "GPL";

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

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_OPEN;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    
    // For openat: args[0]=dfd, args[1]=filename, args[2]=flags, args[3]=mode
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[1]);

    // Save filename in pending_open_files keyed by tid
    __u64 tid = bpf_get_current_pid_tgid();
    char filename[256];
    bpf_probe_read_user_str(filename, sizeof(filename), (void *)ctx->args[1]);
    bpf_map_update_elem(&pending_open_files, &tid, filename, BPF_ANY);

    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_exit_openat(struct trace_event_raw_sys_exit *ctx) {
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
int handle_unlinkat(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("handle_unlinkat called\n");
    
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_UNLINK;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    
    // For unlinkat: args[0]=dfd, args[1]=pathname, args[2]=flags
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[1]);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_renameat2")
int handle_renameat2(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("handle_renameat2 called\n");
    
    // First event for old name
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_RENAME;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    
    // For renameat2: args[0]=olddfd, args[1]=oldname, args[2]=newdfd, args[3]=newname, args[4]=flags
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[1]);
    bpf_ringbuf_submit(event, 0);
    
    // Second event for new name
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_RENAMED;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[3]);
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

SEC("tp/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("handle_fchmodat called\n");
    
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_FCHMODAT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    
    // For fchmodat: args[0]=dfd, args[1]=filename, args[2]=mode
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[1]);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_fchownat")
int handle_fchownat(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("handle_fchownat called\n");
    
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_FCHOWNAT;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    
    // For fchownat: args[0]=dfd, args[1]=filename, args[2]=user, args[3]=group, args[4]=flags
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[1]);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("handle_close called\n");
    
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    // For close: args[0]=fd
    struct fd_key key = {.fd = ctx->args[0], .pid = pid};
    bpf_map_delete_elem(&fd_to_filename, &key);
    return 0;
}

// Additional handlers for common file operations that might be missing

SEC("tp/syscalls/sys_enter_unlink")
int handle_unlink(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("handle_unlink called\n");
    
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_UNLINK;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    
    // For unlink: args[0]=pathname
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[0]);
    
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tp/syscalls/sys_enter_rename")
int handle_rename(struct trace_event_raw_sys_enter *ctx) {
    bpf_printk("handle_rename called\n");
    
    // First event for old name
    struct event *event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_RENAME;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    
    // For rename: args[0]=oldname, args[1]=newname
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[0]);
    bpf_ringbuf_submit(event, 0);
    
    // Second event for new name
    event = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (!event) return 0;
    
    event->opcode = EVENT_RENAMED;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&event->command, sizeof(event->command));
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), (void *)ctx->args[1]);
    bpf_ringbuf_submit(event, 0);
    
    return 0;
}