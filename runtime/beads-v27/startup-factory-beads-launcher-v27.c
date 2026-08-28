#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "startup-factory-v27-crypto.h"

#define PLAN_SOURCE 64
#define KEY_SOURCE 65
#define LOCK_SOURCE 66
#define PIDFD_SOURCE 67
#define SUPERVISOR_CGROUP_SOURCE 68
#define PAYLOAD_CGROUP_SOURCE 69
#define CONTROLLER_SOCKET_SOURCE 70
#define CHILD_SOCKET_SOURCE 71
#define RESULT_SOURCE 72
#define LAUNCHER_PROOF_SOURCE 73
#define EVIDENCE_SOURCE 74
#define EXEC_SOURCE 75
#define MAX_PLAN_BYTES 1048576U

#ifndef STARTUP_FACTORY_V27_PREEXEC_CONTEXT
#define STARTUP_FACTORY_V27_PREEXEC_CONTEXT ""
#endif
#ifndef STARTUP_FACTORY_V27_EXEC_CONTEXT
#define STARTUP_FACTORY_V27_EXEC_CONTEXT ""
#endif

static const unsigned char plan_domain[] = "startup-factory/beads/v27/plan\0";

static void fail(const char *message) {
    ssize_t ignored = write(STDERR_FILENO, message, strlen(message));
    ignored = write(STDERR_FILENO, "\n", 1U);
    (void)ignored;
    _exit(125);
}

static void read_exact_at(int descriptor, void *target, size_t length, off_t offset) {
    unsigned char *cursor = target;
    while (length > 0U) {
        ssize_t count = pread(descriptor, cursor, length, offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail("V27 launcher sealed input is truncated");
        cursor += (size_t)count;
        length -= (size_t)count;
        offset += count;
    }
}

static void verify_key_and_plan(int plan_fd, int key_fd) {
    unsigned char key[32], key_id[32], expected_key_id[32], observed_hmac[32], expected_hmac[32], extra;
    unsigned char header[76];
    int seals = fcntl(key_fd, F_GET_SEALS);
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    if (seals != required || lseek(key_fd, 0, SEEK_CUR) != 0) fail("V27 launcher key custody changed");
    read_exact_at(key_fd, key, sizeof(key), 0);
    if (pread(key_fd, &extra, 1U, 32) != 0 || lseek(key_fd, 0, SEEK_CUR) != 0)
        fail("V27 launcher key length/offset changed");
    read_exact_at(plan_fd, header, sizeof(header), 0);
    if (memcmp(header, "SFV27A1\0", 8U) != 0) fail("V27 launcher plan magic changed");
    memcpy(key_id, header + 8U, 32U);
    memcpy(observed_hmac, header + 40U, 32U);
    unsigned char length_raw[4];
    memcpy(length_raw, header + 72U, sizeof(length_raw));
    uint32_t network_length;
    memcpy(&network_length, length_raw, sizeof(network_length));
    uint32_t payload_length = ntohl(network_length);
    if (payload_length == 0U || payload_length > MAX_PLAN_BYTES) fail("V27 launcher plan length changed");
    unsigned char *payload = malloc(payload_length);
    if (payload == NULL) fail("V27 launcher allocation failed");
    read_exact_at(plan_fd, payload, payload_length, 76);
    if (pread(plan_fd, &extra, 1U, (off_t)76 + (off_t)payload_length) != 0)
        fail("V27 launcher plan has trailing bytes");
    sfv27_sha256(key, sizeof(key), expected_key_id);
    sfv27_hmac_sha256(key, plan_domain, sizeof(plan_domain)-1U, payload, payload_length, expected_hmac);
    if (!sfv27_equal(key_id, expected_key_id, 32U) || !sfv27_equal(observed_hmac, expected_hmac, 32U))
        fail("V27 launcher plan HMAC commitment failed");
    sfv27_secure_zero(key, sizeof(key));
    sfv27_secure_zero(expected_key_id, sizeof(expected_key_id));
    sfv27_secure_zero(expected_hmac, sizeof(expected_hmac));
    sfv27_secure_zero(payload, payload_length);
    free(payload);
}

static void verify_socket_source(int descriptor) {
    int socket_type = 0, passcred = 0, accepting = 0;
    socklen_t length = (socklen_t)sizeof(int);
    struct sockaddr_storage peer;
    socklen_t peer_length = (socklen_t)sizeof(peer);
    if (getsockopt(descriptor,SOL_SOCKET,SO_TYPE,&socket_type,&length)!=0 || socket_type!=SOCK_SEQPACKET ||
        getsockopt(descriptor,SOL_SOCKET,SO_PASSCRED,&passcred,&length)!=0 || passcred!=1 ||
        getsockopt(descriptor,SOL_SOCKET,SO_ACCEPTCONN,&accepting,&length)!=0 || accepting!=0 ||
        getpeername(descriptor,(struct sockaddr *)&peer,&peer_length)!=0 || peer.ss_family!=AF_UNIX)
        fail("V27 launcher source socket identity changed");
}

static int allowed_source_descriptor(long descriptor) {
    return descriptor >= 0 && descriptor <= 2
        ? 1
        : descriptor == PLAN_SOURCE || descriptor == KEY_SOURCE || descriptor == LOCK_SOURCE
        || descriptor == PIDFD_SOURCE || descriptor == SUPERVISOR_CGROUP_SOURCE
        || descriptor == PAYLOAD_CGROUP_SOURCE || descriptor == CONTROLLER_SOCKET_SOURCE
        || descriptor == CHILD_SOCKET_SOURCE || descriptor == RESULT_SOURCE
        || descriptor == LAUNCHER_PROOF_SOURCE || descriptor == EVIDENCE_SOURCE
        || descriptor == EXEC_SOURCE;
}

static void verify_source_inventory(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (directory == NULL) fail("V27 launcher cannot enumerate source descriptors");
    int inventory_fd = dirfd(directory);
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        char *end = NULL;
        long descriptor = strtol(entry->d_name, &end, 10);
        if (end != entry->d_name && *end == '\0' && descriptor != inventory_fd
            && !allowed_source_descriptor(descriptor))
            fail("V27 launcher inherited an unregistered source descriptor");
    }
    closedir(directory);
}

static long parse_stat_tid(const char *value) {
    char *end = NULL;
    errno = 0;
    long tid = strtol(value, &end, 10);
    if (errno != 0 || tid <= 1 || end == value || *end != ' ') fail("V27 launcher FD11 stat PID is invalid");
    return tid;
}

static void verify_launcher_proof(int proof_fd) {
    char path[128], observed[4096], reopened[4096];
    ssize_t count = pread(proof_fd, observed, sizeof(observed)-1U, 0);
    if (count <= 0 || (size_t)count >= sizeof(observed)) fail("V27 launcher FD11 proof is unreadable");
    observed[count] = '\0';
    long tid = parse_stat_tid(observed);
    int length = snprintf(path, sizeof(path), "/proc/%ld/task/%ld/stat", (long)getppid(), tid);
    if (length <= 0 || (size_t)length >= sizeof(path)) fail("V27 launcher proof path is oversized");
    int second = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (second < 0) fail("V27 launcher cannot reopen launcher proof");
    struct stat left, right;
    ssize_t second_count = pread(second, reopened, sizeof(reopened)-1U, 0);
    if (fstat(proof_fd,&left)!=0 || fstat(second,&right)!=0 || left.st_dev!=right.st_dev || left.st_ino!=right.st_ino ||
        second_count!=count || memcmp(observed,reopened,(size_t)count)!=0) fail("V27 launcher FD11 identity changed");
    close(second);
}

static void verify_pidfd(int pidfd) {
    struct pollfd value = {.fd=pidfd,.events=POLLIN};
    if (poll(&value,1,0)!=0 || value.revents!=0) fail("V27 launcher controller pidfd is terminal");
    char path[64], bytes[512];
    int length = snprintf(path,sizeof(path),"/proc/self/fdinfo/%d",pidfd);
    if (length<=0 || (size_t)length>=sizeof(path)) fail("V27 launcher pidfd path failed");
    int descriptor=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(descriptor<0) fail("V27 launcher pidfd info is unavailable");
    ssize_t count=read(descriptor,bytes,sizeof(bytes)-1U);close(descriptor);
    if(count<=0) fail("V27 launcher pidfd info is empty");
    bytes[count]='\0';
    char expected[64];length=snprintf(expected,sizeof(expected),"Pid:\t%ld\n",(long)getppid());
    if(length<=0 || strstr(bytes,expected)==NULL) fail("V27 launcher pidfd identity changed");
}

static void read_exact_proc_value(const char *path, const char *expected, const char *message) {
    unsigned char observed[512], trailing;
    size_t expected_length = strlen(expected);
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) fail(message);
    ssize_t length;
    do {
        length = read(descriptor, observed, sizeof(observed));
    } while (length < 0 && errno == EINTR);
    ssize_t extra;
    do {
        extra = read(descriptor, &trailing, 1U);
    } while (extra < 0 && errno == EINTR);
    close(descriptor);
    if (length < 0 || extra != 0 || (size_t)length != expected_length ||
        memcmp(observed, expected, expected_length) != 0)
        fail(message);
}

static void verify_preexec_selinux(void) {
    /* Empty compile-time values are restricted to the syscall/FD custody
     * fixture.  The production build requires and supplies both identities. */
    if (STARTUP_FACTORY_V27_PREEXEC_CONTEXT[0] == '\0' ||
        STARTUP_FACTORY_V27_EXEC_CONTEXT[0] == '\0')
        return;
    read_exact_proc_value(
        "/proc/self/attr/current",
        STARTUP_FACTORY_V27_PREEXEC_CONTEXT,
        "V27 launcher pre-exec SELinux current context changed"
    );
    read_exact_proc_value(
        "/proc/self/attr/exec",
        "",
        "V27 launcher pre-exec SELinux exec context is not empty"
    );
    unsigned char executable[512];
    ssize_t length = fgetxattr(
        13, "security.selinux", executable, sizeof(executable)
    );
    size_t expected_length = strlen(STARTUP_FACTORY_V27_EXEC_CONTEXT) + 1U;
    if (length < 0 || (size_t)length != expected_length ||
        memcmp(executable, STARTUP_FACTORY_V27_EXEC_CONTEXT, expected_length - 1U) != 0 ||
        executable[expected_length - 1U] != '\0')
        fail("V27 launcher executable SELinux xattr changed");
}

static void remap(int source, int target, int flags) {
    if (dup3(source, target, flags) != target) fail("V27 launcher descriptor remap failed");
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--startup-factory-launch-v27") != 0)
        fail("unknown V27 launcher invocation");
    pid_t expected_parent = getppid();
    if (expected_parent <= 1 || prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 ||
        getppid() != expected_parent)
        fail("V27 launcher parent-death binding failed");
    verify_source_inventory();
    verify_socket_source(CONTROLLER_SOCKET_SOURCE);
    verify_socket_source(CHILD_SOCKET_SOURCE);
    struct stat controller_socket, child_socket;
    if (fstat(CONTROLLER_SOCKET_SOURCE,&controller_socket)!=0 || fstat(CHILD_SOCKET_SOURCE,&child_socket)!=0 ||
        (controller_socket.st_dev==child_socket.st_dev && controller_socket.st_ino==child_socket.st_ino))
        fail("V27 launcher socket endpoints are not distinct");
    verify_pidfd(PIDFD_SOURCE);
    verify_launcher_proof(LAUNCHER_PROOF_SOURCE);
    verify_key_and_plan(PLAN_SOURCE, KEY_SOURCE);
    struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=0,.l_pid=0};
    if(fcntl(LOCK_SOURCE,F_OFD_SETLK,&lock)!=0) fail("V27 launcher shared OFD is not held");
    struct stat metadata;
    if(fstat(SUPERVISOR_CGROUP_SOURCE,&metadata)!=0 || !S_ISDIR(metadata.st_mode) ||
       fstat(PAYLOAD_CGROUP_SOURCE,&metadata)!=0 || !S_ISDIR(metadata.st_mode) ||
       fstat(RESULT_SOURCE,&metadata)!=0 || !S_ISDIR(metadata.st_mode) ||
       fstat(EVIDENCE_SOURCE,&metadata)!=0 || !S_ISREG(metadata.st_mode) ||
       fstat(EXEC_SOURCE,&metadata)!=0 || !S_ISREG(metadata.st_mode))
        fail("V27 launcher source descriptor type changed");
    remap(PLAN_SOURCE,3,0);remap(KEY_SOURCE,4,0);remap(LOCK_SOURCE,5,0);remap(CHILD_SOCKET_SOURCE,6,0);
    remap(PIDFD_SOURCE,7,0);remap(SUPERVISOR_CGROUP_SOURCE,8,0);remap(PAYLOAD_CGROUP_SOURCE,9,0);
    remap(RESULT_SOURCE,10,0);remap(LAUNCHER_PROOF_SOURCE,11,0);remap(EVIDENCE_SOURCE,12,0);remap(EXEC_SOURCE,13,O_CLOEXEC);
    if (close_range(14U, UINT_MAX, 0U) != 0) fail("V27 launcher forbidden descriptor close failed");
    for(int descriptor=0;descriptor<=13;++descriptor) if(fcntl(descriptor,F_GETFD)<0) fail("V27 launcher fixed descriptor table is incomplete");
    if((fcntl(13,F_GETFD)&FD_CLOEXEC)==0) fail("V27 launcher FD13 is not CLOEXEC");
    if (getppid() != expected_parent) fail("V27 launcher parent changed before exec");
    verify_pidfd(7);
    verify_launcher_proof(11);
    verify_preexec_selinux();
    verify_key_and_plan(3,4);
    if (lseek(3, 76, SEEK_SET) != 76) fail("V27 launcher cannot position the authenticated plan payload");
    char *const child_argv[]={argv[0],"--startup-factory-execute-v27",NULL};
    char *const environment[]={"BD_JSON_ENVELOPE=1","HOME=/nonexistent","LANG=C","LC_ALL=C","PATH=/usr/bin:/bin",NULL};
    execveat(13,"",child_argv,environment,AT_EMPTY_PATH);
    fail("V27 launcher same-inode execveat failed");
    return 125;
}
