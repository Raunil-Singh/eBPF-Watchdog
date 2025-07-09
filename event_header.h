#ifndef EVENT_HEADER_H
#define EVENT_HEADER_H

struct event {
    unsigned int pid;
    char command[16];
    char filename[256];
    int opcode;
};

enum event_opcode {
    EVENT_OPEN = 0,
    EVENT_UNLINK = 1,
    EVENT_RENAME = 2,
    EVENT_RENAMED = 3,
    EVENT_FCHMODAT = 4,
    EVENT_FCHOWNAT = 5
};

#endif // EVENT_HEADER_H