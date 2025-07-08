// Trying to use ring buffer

BPF_PERF_OUTPUT(data_ring)

struct data_t {
    u64 pid;
    u64 uid;
    char cmd[16];
    char msg[12];
};


int hello(void *ctx)
{
    struct data_t data;

    // if(!data)
    // {
    //     bpf_trace_printk("Data reservation failed...\n");
    //     return 0; // reservation failed
    // }

    char message[12] = "execve called\n";
    
    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.cmd, sizeof(data.cmd));
    bpf_probe_read_kernel(&data.msg, sizeof(data.msg), message);

    bpf_perf_submit(ctx, );

    return 0;
}