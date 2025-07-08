#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include "exp.skel.h"

volatile int exiting = 0;

void handle_signal(int sig)
{
    exiting = 1;
}

int main()
{
    struct exp *skel = exp__open_and_load();
    exp__attach(skel);


    while(!exiting)
    {
        printf("blah blah blah :)\n");
        sleep(10);
    }

    exp__destroy(skel);

    return 0;
}