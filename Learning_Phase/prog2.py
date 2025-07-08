#!/usr/bin/python3
from bcc import BPF
import time as t

program = ''

with open("prog2.bpf.c", 'r') as file:
    program = file.read()

# print(program)

b = BPF(text=program)
syscall = b.get_syscall_fnname('execve')
b.attach_kprobe(event=syscall, fn_name='trace_execve')

time = 1
while True:
    s = f'Time = {time}s\t'
    t.sleep(1)
    for k, v in b['counter_table'].items():
        s += f'{k.value}: {v.value}\t'
    time += 1
    print(s)
