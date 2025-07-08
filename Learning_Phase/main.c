#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

#include "trace.bpf.h"

static int exiting = 0;

void handle_signal(int sig)
{
    printf("Recieved Signal = %d\n", sig);
    // exiting = 1;
}

int main()
{
    struct trace_bpf* skel;
    int err;

    // Handling signals
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = trace_bpf__open_and_load();

    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    err = trace_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        trace_bpf__destroy(skel);
        return 1;
    }

    printf("BPF programs are running :), press Ctrl+C to exit\n");

    while(!exiting)
        sleep(1);
    
    trace_bpf__destroy(skel);
    printf("Exiting cleanly.\n");

    return 0;
}