# Learnings

In this directory, I'll store all the code I have written to learn about eBPF.

-----------

## Why eBPF instead of already existing kprobes?

| Feature            | kprobes                            | eBPF                                                                   |
| ------------------ | ---------------------------------- | ---------------------------------------------------------------------- |
| **Safety**         | Dangerous (can crash kernel)       | Verified bytecode → safe                                               |
| **Ease of Use**    | Requires kernel module development | User-space tools like `bcc`, `bpftrace`, `libbpf`                      |
| **Extensibility**  | Static probes only                 | Can be attached dynamically to kprobes, tracepoints, perf events, etc. |
| **Interactivity**  | No communication                   | eBPF maps allow interaction with user space                            |
| **Portability**    | Tight to kernel version            | Abstracted via CO-RE (Compile Once, Run Everywhere)                    |
| **Performance**    | Low overhead, but intrusive        | JIT-compiled, high performance                                         |
| **Security Model** | Root only, full control            | eBPF programs run in sandbox (restricted, verified)                    |

----

## eBPF programs cannot use libraries in userspace.

eBPF programs:

- Must be fully verifiable, safe, and deterministic.

- Run inside a restricted virtual machine in the kernel.

- Cannot make syscalls, file I/O, or use dynamic memory.

There’s no concept of printf, malloc, fopen, etc. inside the eBPF environment.

----
API names:

| Task              | Function Used                     |
| ----------------- | --------------------------------- |
| Get map FD        | `bpf_map__fd(skel->maps.mapname)` |
| Lookup key        | `bpf_map_lookup_elem()`           |
| Insert/update key | `bpf_map_update_elem()`           |
| Delete key        | `bpf_map_delete_elem()`           |
| Iterate keys      | `bpf_map_get_next_key()`          |

