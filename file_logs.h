#ifndef FILE_LOGS_H
#define FILE_LOGS_H

#include <string>
#include <vector>
#include <mutex>
#include <iostream>

struct logged_event {
    unsigned int pid;
    std::string command;
    std::string filename; // Added to store the filename
    std::string operation;
};

class file_logs {
    
    std::mutex mtx;
    std::string directory;
    std::vector<logged_event> event_queue;

    public:
    
        // Constructor to initialize with a filename
        file_logs(std::string fname) : directory(fname) {}

        // Add a new file_logs instance for a given filename
        void add_event(std::string filename, unsigned int pid, std::string command, std::string operation) {
            logged_event ev = {
                .pid = pid,
                .command = command,
                .filename = filename, // Store the filename in the event
                .operation = operation
            };
            std::lock_guard<std::mutex> lock(mtx);
            event_queue.push_back(ev);
        }

        // Print and empty the event queue for this file
        void print_logs() {
            std::cout << "Logs for directory: " << directory << std::endl;
            std::string output_string;
            {
                std::lock_guard<std::mutex> lock(mtx);
                for (logged_event ev : event_queue) {
                    output_string += "Event: filename : " + ev.filename 
                                    + "\n\t\tPID : " + std::to_string(ev.pid)  
                                    + "\n\t\tCommand : " + ev.command
                                    + "\n\t\tOpcode : " + ev.operation + "\n";

                }
            }
            std::cout << output_string << std::endl;
            std::cout << "End of logs for file: " << directory << std::endl;
        }

        void clear_logs() {
            std::lock_guard<std::mutex> lock(mtx);
            event_queue.clear();
        }
};

#endif // FILE_LOGS_H