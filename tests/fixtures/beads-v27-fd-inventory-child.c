#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

struct sf_linux_dirent64 {
    uint64_t inode;
    int64_t offset;
    unsigned short record_length;
    unsigned char type;
    char name[];
};

static int write_all(int descriptor, const void *value, size_t length) {
    const unsigned char *cursor = value;
    while (length > 0U) {
        ssize_t count = write(descriptor, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        cursor += (size_t)count;
        length -= (size_t)count;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[0], "sf-v27-child") != 0) return 90;
    int directory = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory != 3) return 91;
    int seen[4] = {0, 0, 0, 0};
    unsigned char buffer[4096];
    for (;;) {
        long length = syscall(SYS_getdents64, directory, buffer, sizeof(buffer));
        if (length < 0) {
            if (errno == EINTR) continue;
            return 92;
        }
        if (length == 0) break;
        long at = 0;
        while (at < length) {
            struct sf_linux_dirent64 *entry = (struct sf_linux_dirent64 *)(buffer + at);
            if (entry->record_length < offsetof(struct sf_linux_dirent64, name) + 2U ||
                at + entry->record_length > length)
                return 93;
            if ((entry->name[0] == '.' && entry->name[1] == '\0') ||
                (entry->name[0] == '.' && entry->name[1] == '.' && entry->name[2] == '\0')) {
                at += entry->record_length;
                continue;
            }
            if (entry->name[1] != '\0' || entry->name[0] < '0' || entry->name[0] > '3')
                return 94;
            int index = entry->name[0] - '0';
            if (seen[index]) return 95;
            seen[index] = 1;
            at += entry->record_length;
        }
    }
    if (!seen[0] || !seen[1] || !seen[2] || !seen[3] || close(directory) != 0)
        return 96;
    int output = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output != 3) return 97;
    char report[128];
    int length = snprintf(report, sizeof(report), "%ld\nfds=0,1,2\n", (long)getpid());
    if (length <= 0 || (size_t)length >= sizeof(report) ||
        write_all(output, report, (size_t)length) != 0 || fsync(output) != 0 || close(output) != 0)
        return 98;
    return 0;
}
