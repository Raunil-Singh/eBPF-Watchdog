// user space code for test.bpf.c

#include <unordered_map>
#include <iostream>
#include <string>
#include <csignal>

#include "file_logs.h"
#include "ui.h"
#include "bpf_handling.h"

std::unordered_map<std::string, file_logs*> watchlist;

int running = 1;

void handle_signal(int sig) {
    std::cout << "Received signal " << sig << ", shutting down..." << std::endl;
    watchlist.clear();
    running = 0;
}

int main() {

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    
    // Start the polling loop in a separate thread
    std::thread bpf_handler_thread(BPF_Handler::load_and_attach_bpf);
    // Start the UI loop
    std::thread ui_thread(UserInterface::game_loop);

    // Cleanup
    if (bpf_handler_thread.joinable()) {
        bpf_handler_thread.join();
    }
    if (ui_thread.joinable()) {
        ui_thread.join();
    }

    for (const auto& [path, logs] : watchlist) {
        logs->clear_logs();
        delete logs; // Free memory
    }
    
    watchlist.clear();
    std::cout << "Exiting Safely..." << std::endl;

    return 0;
}