#ifndef UI_H
#define UI_H

#include <iostream>
#include <string>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <mutex>
#include "file_logs.h"
extern int running;
extern std::unordered_map<std::string, file_logs*> watchlist;

class UserInterface {
public:
    // Display the main menu
    static void print_menu() {
        std::cout << "\n--- eBPF Watchdog Menu ---\n";
        std::cout << "1. Add directory to watchlist\n";
        std::cout << "2. Remove directory from watchlist\n";
        std::cout << "3. List watchlist\n";
        std::cout << "4. Get logs for a directory\n";
        std::cout << "5. clear logs for a directory\n";
        std::cout << "6. clear all logs\n";
        std::cout << "7. Exit\n";
        std::cout << "Enter choice: ";
    }

    // Print a single event
    static void game_loop() {
        std::cout << "Game loop running...\n";
        while(running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            print_menu();
            int menu_choice;
            std::cin >> menu_choice;
            std::cin.ignore();
            switch(menu_choice) {
                case 1: {
                    std::string path;
                    std::cout << "Enter directory path: ";
                    std::getline(std::cin, path);
                    if(path.back() != '/') {
                        path += '/'; // Ensure path ends with '/'
                        // this helps in differentiating between ./a/ and ./ab/
                    }
                    if (watchlist.find(path) == watchlist.end()) {
                        watchlist[path] = new file_logs(path);
                        std::cout << "Added to watchlist.\n";
                    } else {
                        std::cout << "Already in watchlist.\n";
                    }
                    break;
                }
                case 2: {
                    std::string path;
                    std::cout << "Enter directory path: ";
                    std::getline(std::cin, path);
                    if(path.back() != '/') {
                        path += '/'; // Ensure path ends with '/'
                        // this helps in differentiating between ./a/ and ./ab/
                    }
                    auto it = watchlist.find(path);
                    if (it != watchlist.end()) {
                        delete it->second; // Free memory
                        watchlist.erase(it);
                        std::cout << "Removed from watchlist.\n";
                    } else {
                        std::cout << "Not found in watchlist.\n";
                    }
                    break;
                }
                case 3: {
                    std::cout << "Watchlist:\n";
                    for (const auto& f : watchlist) {
                        std::cout << "  " << f.first << "\n";
                    }
                    break;
                }
                case 4: {
                    std::string path;
                    std::cout << "Enter directory path: ";
                    std::getline(std::cin, path);
                    auto it = watchlist.find(path);
                    if (it != watchlist.end()) {
                        it->second->print_logs();
                    } else {
                        std::cout << "Not found in watchlist.\n";
                    }
                    break;
                }
                case 5: {
                    std::string path;
                    std::cout << "Enter directory path: ";
                    std::getline(std::cin, path);
                    auto it = watchlist.find(path);
                    if (it != watchlist.end()) {
                        it->second->clear_logs();
                        std::cout << "Logs cleared for directory: " << path << "\n";
                    } else {
                        std::cout << "Not found in watchlist.\n";
                    }
                    break;
                }
                case 6: {
                    std::cout << "Clearing all logs for all directories in watchlist...\n";
                    for (auto& [path, logs] : watchlist) {
                        logs->clear_logs();
                    }
                    break;
                }
                case 7: {
                    running = 0;
                    std::cout << "Exiting...\n";
                    break;
                }
            }
        }
    }
};

#endif // UI_H