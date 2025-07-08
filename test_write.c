#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main() {
    const char *filename = "/tmp/ebpf_watchdog_test.txt";
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        perror("open");
        return 1;
    }
    const char *msg = "Hello from eBPF test!\n";
    ssize_t written = write(fd, msg, strlen(msg));
    if (written < 0) {
        perror("write");
        close(fd);
        return 1;
    }
    printf("Wrote %zd bytes to %s\n", written, filename);
    close(fd);
    return 0;
}
