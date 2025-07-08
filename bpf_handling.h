#ifndef BPF_HANDLING_H
#define BPF_HANDLING_H

#include <unordered_map>
#include <string>
#include <iostream>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include "watchdog.skel.h"
#include "file_logs.h"

struct event {
    unsigned int pid;
    char command[16];
    char filename[256];
    int opcode;
};
extern int running;
extern std::unordered_map<std::string, file_logs*> watchlist;

class BPF_Handler {
public:

    static int handle_event(void *ctx, void *data, size_t len) {
        struct event *event = (struct event *)data;

        std::string filename(event->filename);
        std::string command(event->command);

        for (auto& [watch_item, obj] : watchlist) {
            if (filename.substr(0, watch_item.size()) == watch_item) {
                obj->add_event(filename, event->pid, command, event->opcode);
            }
        }

        return 0;
    }

    static void polling_loop(struct watchdog *skel) {
        struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
        if (!rb) {
            fprintf(stderr, "Failed to create ring buffer\n");
            running = 0;
        }

        while(running) {
            int poll_res = ring_buffer__poll(rb, 100);
            // std::cout << "Polling ring buffer..." << std::endl;
            if (poll_res < 0) {
                std::cerr << "Error polling ring buffer: " << poll_res << std::endl;
                break;
            }
        }
        ring_buffer__free(rb);
        std::cout << "Ring buffer polling stopped." << std::endl;
    }

    static void load_and_attach_bpf() {
        struct watchdog *skel;
        int err;

        skel = watchdog__open_and_load();
        if (!skel) {
            std::cerr << "Failed to load BPF skeleton" << std::endl;
            running = 0;
            return;
        }

        err = watchdog__attach(skel);
        if (err) {
            std::cerr << "Failed to attach BPF program: " << err << std::endl;
            watchdog__destroy(skel);
            running = 0;
            return;
        }

        std::cout << "BPF program loaded and attached successfully." << std::endl;

        // Start the polling loop in a separate thread
        polling_loop(skel);
        watchdog__destroy(skel);
        std::cout << "BPF program destroyed safely." << std::endl;
    }
};
#endif // BPF_HANDLING_H