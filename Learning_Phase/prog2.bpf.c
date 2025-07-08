BPF_HASH(counter_table);

int trace_execve(void *ctx)
{
    u64 uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    u64 count = 0;
    u64 *p = counter_table.lookup(&uid);
    if(p != 0)
        count = *p;
    count++;
    counter_table.update(&uid, &count);
    return 0;
}