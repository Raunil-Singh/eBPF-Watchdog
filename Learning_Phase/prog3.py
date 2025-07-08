#!/usr/bin/python3
from bcc import BPF

program = ''

with open('prog3.bpf.c', 'r') as file:
    program=file.read()

b = BPF(text=program)
syscall = b.get_syscall_fnname('execve')
b.attach_kprobe(event=syscall, fn_name='hello')

