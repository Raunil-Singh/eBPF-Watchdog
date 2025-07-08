#!/usr/bin/env python3
from bcc import BPF

program = '''

// This is the BPF program written in C and it runs in the kernel space.

// # include <stdio.h> this will not work, as it is not a valid BPF program
int hello(void *ctx) {
   bpf_trace_printk("Hello, World!\\n");
   // printf("Hello, World!\\n"); this is invalid.
   return 0;
}

'''

# This Python script uses the BCC (BPF Compiler Collection) library to load and attach a BPF program to a syscall event.
# The Python script runs in the user space.

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
print("Resolved syscall:", syscall)
b.attach_kprobe(event=syscall, fn_name='hello')

print("Attached kprobe to %s\n", syscall)
print("Press Ctrl-C to exit...\n")
b.trace_print()

try:
   while True: # Check the trace buffer for output
      # Either use b.trace_print() to print the output from the BPF trace buffer
      # or sudo cat /sys/kernel/debug/tracing/trace_pipe
      pass
except KeyboardInterrupt:
   print("\n\nExiting...")


# Note* : trace_pipe is a special file that provides a live view of the trace buffer.
   

# Learning points:
# 1. bpf_trace_printk is a helper function that allows you to print messages to the BPF trace buffer.
# 2. The BPF() constructor initializes the BPF program with the provided text.
   # Here, the following happens:
   # 1) Clang is invoked to compile the C program to eBPF bytecode of type .o
   # 2) The program is passed to the kernel via a BPF syscall.
   # 3) BPF Verifier checks the program for safety and correctness.
   # 4) The program is accepted and and get a program ID as it resides in the kernel.
# 3. get_syscall_fnname() resolves the correct kprobe event name for execve, depending on the kernel version and architecture.
# 4. attach_kprobe() attaches the BPF program to the specified syscall event.
# 5. trace_print() prints the output from the BPF trace buffer to the console.

# Note*: When running in python, detach_kprobe() is not needed, as the program will exit when the script ends.
   # The clean up handled by the garbage collector. So, when the script terminates, the GC will clean up the BPF object
   # automatically, and call the destructor, which will detach the kprobe.
# 6. The BPF program runs in the kernel space, while the Python script runs in user space.
# 7. The BPF program is written in C, but it can be loaded and executed from Python using the BCC library.
# 8. To load the BPF program, sudo is required, as it needs to access kernel resources.

# To check if the BPF program is loaded, you can use the command:
# sudo bpftool prog show


# Basically, bpf_trace_printk() writes to the kernel buffer, and trace_print() reads from it and prints it to the console.
