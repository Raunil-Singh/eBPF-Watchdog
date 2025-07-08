#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "q2.skel.h"

static int exiting =  0;

void handle_signal(int sig)
{
    printf("Received %d\n", sig);
    exiting = 1;
}

int main()
{
    struct q2 *skel = q2__open_and_load();
    q2__attach(skel);

    signal(SIGINT, handle_signal);

    int map_fd = bpf_map__fd(skel->maps.call_counts);

    while(!exiting)
    {
        char key[16];
        memset(key, '\0', sizeof(key));
        char next_key[16];
        printf("Here1\n");
        while(bpf_map_get_next_key(map_fd, key, next_key) == 0)
        {
            int64_t val = 0;
            bpf_map_lookup_elem(map_fd, next_key, &val);
            printf("Value for key '%s' is: %lu\n", next_key, val);
            memcpy(key, next_key, sizeof(key));
        }
        printf("Here2\n");
        sleep(1);
        printf("Here3\n");
    }

    q2__destroy(skel);

    return 0;
}