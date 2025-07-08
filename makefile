# File names
BPF_SRC       := watchdog.bpf.c
BPF_OBJ       := watchdog.bpf.o
SKEL_HEADER   := watchdog.skel.h
CONVENTION	:= watchdog
USER_SRC      := main.cpp
USER_BIN      := watchdog
VMLINUX        := vmlinux.h

# Compiler settings
CLANG         := clang
GPP           := g++
CFLAGS        := -O2 -g -Wall
BPF_CFLAGS    := -target bpf -O2 -g -mllvm -bpf-stack-size=512 -I/usr/include/bpf -I/usr/include/linux

# Libs
LDFLAGS       := -lbpf -lpthread -lstdc++fs

.PHONY: all clean

build: $(USER_BIN)

# Step 0: Generate vmlinux.h
$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

# Step 1: Compile BPF program
$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Step 2: Generate skeleton
$(SKEL_HEADER): $(BPF_OBJ)
	bpftool gen skeleton $< name $(CONVENTION) > $@

# Step 3: Build userspace binary
$(USER_BIN): $(USER_SRC) $(SKEL_HEADER)
	$(GPP) $(CFLAGS) $(USER_SRC) -o $@ $(LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(SKEL_HEADER) $(USER_BIN) $(VMLINUX)
