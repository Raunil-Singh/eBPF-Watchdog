#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include "q1.skel.h"

static volatile int exiting;

void handle_signal(int sig)
{
    printf("Recieved signal : %d\n", sig);
    exiting = 1;
}

int main()
{
    struct q1 * skel;
    int err;

    exiting = 0;

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    skel = q1__open_and_load();
    if(!skel)
    {
        printf("Oops! Something went wrong during opening and loading the BPF Function!\n");
        return 1;
    }

    if(q1__attach(skel))
    {
        printf("Oops! Something went wrong while attaching the BPF Function to tracepoint!\n");
        return 1;
    }

    FILE *fp = fopen("/sys/kernel/debug/tracing/trace_pipe", "r");
    if (!fp) {
        perror("Failed to open trace_pipe");
        return 1;
    }

    char buffer[512];
    
    while (fgets(buffer, sizeof(buffer), fp) && !exiting) {
        printf("%s", buffer);
    }
    


    q1__destroy(skel);
    fclose(fp);
    
    return 0;

}