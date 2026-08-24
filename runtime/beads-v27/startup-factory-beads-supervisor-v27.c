#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

/*
 * Native half of the closed V27 controller boundary.  The controller supplies
 * one sealed, digest-bound binary plan on FD3.  This helper never reads a
 * shell, ambient environment, Podman socket or caller-selected executable.
 */

#define PLAN_FD 3
#define MAX_FIELD 4096U
#define MAX_ARGC 64U
#define MAX_OUTPUT 1048576U
#define STAGE_TIMEOUT_SECONDS 120
#define PODMAN "/usr/bin/podman"

#ifndef STARTUP_FACTORY_V27_PROBE_JSON
#define STARTUP_FACTORY_V27_PROBE_JSON "{}"
#endif
#ifndef STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT
#define STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT ""
#endif
#ifndef STARTUP_FACTORY_V27_EXEC_CONTEXT
#define STARTUP_FACTORY_V27_EXEC_CONTEXT ""
#endif

struct bytes {
    unsigned char *data;
    size_t length;
};

struct plan {
    char *operation_id;
    char *plan_sha256;
    char *image;
    char *repository;
    uint32_t argc;
    char **argv;
};

static char host_home[8192];
static char host_user[512];
static char host_logname[512];
static char host_runtime[128];
static void die(const char *message);

static void initialize_host_environment(void) {
    struct passwd *account = getpwuid(geteuid());
    if (account == NULL || account->pw_dir == NULL || account->pw_name == NULL)
        die("V27 worker UID has no local account");
    if (snprintf(host_home, sizeof(host_home), "HOME=%s", account->pw_dir) >= (int)sizeof(host_home) ||
        snprintf(host_user, sizeof(host_user), "USER=%s", account->pw_name) >= (int)sizeof(host_user) ||
        snprintf(host_logname, sizeof(host_logname), "LOGNAME=%s", account->pw_name) >= (int)sizeof(host_logname) ||
        snprintf(host_runtime, sizeof(host_runtime), "XDG_RUNTIME_DIR=/run/user/%lu", (unsigned long)geteuid()) >= (int)sizeof(host_runtime))
        die("V27 worker account environment is oversized");
}

static void die(const char *message) {
    (void)write(STDERR_FILENO, message, strlen(message));
    (void)write(STDERR_FILENO, "\n", 1);
    _exit(125);
}

static void verify_selinux_transition(void) {
    char current[512];
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) die("V27 supervisor cannot read its SELinux context");
    ssize_t length = read(fd, current, sizeof(current));
    char extra;
    ssize_t trailing = read(fd, &extra, 1);
    close(fd);
    size_t expected_current = strlen(STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT);
    if (length < 0 || trailing != 0 || (size_t)length != expected_current ||
        memcmp(current, STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT, expected_current) != 0)
        die("V27 supervisor SELinux transition differs from the compiled manifest");

    char executable[512];
    ssize_t executable_length = getxattr(
        "/proc/self/exe", "security.selinux", executable, sizeof(executable));
    size_t expected_executable = strlen(STARTUP_FACTORY_V27_EXEC_CONTEXT) + 1U;
    if (executable_length < 0 || (size_t)executable_length != expected_executable ||
        memcmp(executable, STARTUP_FACTORY_V27_EXEC_CONTEXT, expected_executable - 1U) != 0 ||
        executable[expected_executable - 1U] != '\0')
        die("V27 supervisor executable SELinux label differs from the compiled manifest");
}

static void read_exact(int fd, void *destination, size_t length) {
    unsigned char *cursor = destination;
    while (length > 0) {
        ssize_t count = read(fd, cursor, length);
        if (count <= 0) die("V27 sealed plan is truncated");
        cursor += (size_t)count;
        length -= (size_t)count;
    }
}

static char *read_field(int fd) {
    uint32_t network_length;
    read_exact(fd, &network_length, sizeof(network_length));
    uint32_t length = ntohl(network_length);
    if (length == 0 || length > MAX_FIELD) die("V27 sealed plan field is invalid");
    char *value = calloc((size_t)length + 1U, 1U);
    if (value == NULL) die("V27 supervisor allocation failed");
    read_exact(fd, value, length);
    if (memchr(value, '\0', length) != NULL) die("V27 sealed plan contains NUL");
    return value;
}

static struct plan read_plan(void) {
    unsigned char magic[8];
    read_exact(PLAN_FD, magic, sizeof(magic));
    if (memcmp(magic, "SFV27P1\0", 8) != 0) die("V27 sealed plan magic differs");
    struct plan result = {0};
    result.operation_id = read_field(PLAN_FD);
    result.plan_sha256 = read_field(PLAN_FD);
    result.image = read_field(PLAN_FD);
    result.repository = read_field(PLAN_FD);
    uint32_t network_argc;
    read_exact(PLAN_FD, &network_argc, sizeof(network_argc));
    result.argc = ntohl(network_argc);
    if (result.argc == 0 || result.argc > MAX_ARGC) die("V27 sealed plan argc is invalid");
    result.argv = calloc((size_t)result.argc + 1U, sizeof(char *));
    if (result.argv == NULL) die("V27 supervisor argv allocation failed");
    for (uint32_t index = 0; index < result.argc; ++index) result.argv[index] = read_field(PLAN_FD);
    unsigned char extra;
    if (read(PLAN_FD, &extra, 1) != 0) die("V27 sealed plan contains trailing bytes");
    if (strlen(result.operation_id) != 64 || strncmp(result.plan_sha256, "sha256:", 7) != 0)
        die("V27 sealed plan identity is invalid");
    if (strcmp(result.argv[0], "/usr/local/bin/bd") != 0)
        die("V27 sealed plan executable differs from container bd");
    return result;
}

static long monotonic_seconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) die("V27 monotonic clock failed");
    return now.tv_sec;
}

static int append_bounded(struct bytes *target, const unsigned char *data, size_t length) {
    if (length > MAX_OUTPUT - target->length) return -1;
    unsigned char *grown = realloc(target->data, target->length + length + 1U);
    if (grown == NULL) die("V27 output allocation failed");
    target->data = grown;
    memcpy(target->data + target->length, data, length);
    target->length += length;
    target->data[target->length] = 0;
    return 0;
}

static int run_argv(char *const argv[], int capture, struct bytes *out, struct bytes *err) {
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    if (capture && (pipe2(stdout_pipe, O_CLOEXEC | O_NONBLOCK) != 0 ||
                    pipe2(stderr_pipe, O_CLOEXEC | O_NONBLOCK) != 0))
        die("V27 output pipe creation failed");
    pid_t child = fork();
    if (child < 0) die("V27 stage fork failed");
    if (child == 0) {
        if (setpgid(0, 0) != 0) _exit(126);
        if (capture) {
            if (dup2(stdout_pipe[1], STDOUT_FILENO) < 0 || dup2(stderr_pipe[1], STDERR_FILENO) < 0)
                _exit(126);
        } else {
            int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
            if (nullfd < 0 || dup2(nullfd, STDOUT_FILENO) < 0 || dup2(nullfd, STDERR_FILENO) < 0)
                _exit(126);
        }
        char *const environment[] = {host_home, "LANG=C", "LC_ALL=C", host_logname,
                                     "PATH=/usr/bin:/bin", host_runtime, host_user, NULL};
        execve(PODMAN, argv, environment);
        _exit(127);
    }
    (void)setpgid(child, child);
    if (capture) {
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
    }
    long deadline = monotonic_seconds() + STAGE_TIMEOUT_SECONDS;
    int status = 0;
    int finished = 0;
    while (!finished) {
        if (capture) {
            struct pollfd descriptors[2] = {
                {.fd = stdout_pipe[0], .events = POLLIN},
                {.fd = stderr_pipe[0], .events = POLLIN},
            };
            (void)poll(descriptors, 2, 50);
            unsigned char block[8192];
            for (int index = 0; index < 2; ++index) {
                for (;;) {
                    ssize_t count = read(descriptors[index].fd, block, sizeof(block));
                    if (count > 0) {
                        if (append_bounded(index == 0 ? out : err, block, (size_t)count) != 0) {
                            (void)kill(-child, SIGKILL);
                            (void)waitpid(child, &status, 0);
                            close(stdout_pipe[0]); close(stderr_pipe[0]);
                            return 125;
                        }
                    }
                    else break;
                }
            }
        }
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) finished = 1;
        else if (waited < 0) die("V27 stage wait failed");
        else if (monotonic_seconds() >= deadline) {
            (void)kill(-child, SIGKILL);
            (void)waitpid(child, &status, 0);
            if (capture) { close(stdout_pipe[0]); close(stderr_pipe[0]); }
            return 124;
        }
    }
    if (capture) {
        unsigned char block[8192];
        for (int index = 0; index < 2; ++index) {
            int fd = index == 0 ? stdout_pipe[0] : stderr_pipe[0];
            for (;;) {
                ssize_t count = read(fd, block, sizeof(block));
                if (count > 0) {
                    if (append_bounded(index == 0 ? out : err, block, (size_t)count) != 0) {
                        close(stdout_pipe[0]); close(stderr_pipe[0]);
                        return 125;
                    }
                }
                else break;
            }
            close(fd);
        }
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 125;
}

static char *base64(const unsigned char *data, size_t length) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t output_length = 4U * ((length + 2U) / 3U);
    char *result = calloc(output_length + 1U, 1U);
    if (result == NULL) die("V27 base64 allocation failed");
    size_t input = 0, output = 0;
    while (input < length) {
        uint32_t a = input < length ? data[input++] : 0;
        uint32_t b = input < length ? data[input++] : 0;
        uint32_t c = input < length ? data[input++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        result[output++] = alphabet[(triple >> 18) & 63U];
        result[output++] = alphabet[(triple >> 12) & 63U];
        result[output++] = alphabet[(triple >> 6) & 63U];
        result[output++] = alphabet[triple & 63U];
    }
    if (length % 3U == 1U) result[output_length - 2U] = result[output_length - 1U] = '=';
    else if (length % 3U == 2U) result[output_length - 1U] = '=';
    return result;
}

static int execute_plan(void) {
    struct plan plan = read_plan();
    char container[48];
    if (snprintf(container, sizeof(container), "sf-v27-%.32s", plan.operation_id) >= (int)sizeof(container))
        die("V27 container identity overflow");
    char mount[8192];
    if (snprintf(mount, sizeof(mount), "type=bind,src=%s,dst=/workspace,rw", plan.repository) >= (int)sizeof(mount))
        die("V27 repository mount is too long");

    size_t create_count = 48U + plan.argc;
    char **create = calloc(create_count, sizeof(char *));
    if (create == NULL) die("V27 create argv allocation failed");
    size_t at = 0;
    create[at++] = PODMAN; create[at++] = "create"; create[at++] = "--name"; create[at++] = container;
    create[at++] = "--pull"; create[at++] = "never"; create[at++] = "--network"; create[at++] = "none";
    create[at++] = "--cgroups"; create[at++] = "split";
    create[at++] = "--read-only"; create[at++] = "--userns"; create[at++] = "keep-id";
    create[at++] = "--security-opt"; create[at++] = "no-new-privileges";
    create[at++] = "--security-opt"; create[at++] = "label=type:beads_worker_t";
    create[at++] = "--cap-drop"; create[at++] = "all"; create[at++] = "--pids-limit"; create[at++] = "64";
    create[at++] = "--memory"; create[at++] = "536870912"; create[at++] = "--cpus"; create[at++] = "1";
    create[at++] = "--env"; create[at++] = "HOME=/run/startup-factory/home";
    create[at++] = "--env"; create[at++] = "LANG=C";
    create[at++] = "--env"; create[at++] = "LC_ALL=C";
    create[at++] = "--env"; create[at++] = "PATH=/usr/local/bin:/usr/bin:/bin";
    create[at++] = "--tmpfs"; create[at++] = "/run/startup-factory/home:rw,nodev,nosuid,noexec,mode=0700";
    create[at++] = "--mount"; create[at++] = mount; create[at++] = "--workdir"; create[at++] = "/workspace";
    create[at++] = plan.image;
    for (uint32_t index = 0; index < plan.argc; ++index) create[at++] = plan.argv[index];
    create[at] = NULL;

    struct bytes out = {0}, err = {0};
    int infrastructure = run_argv(create, 0, &out, &err);
    char *init[] = {PODMAN, "init", container, NULL};
    char *start[] = {PODMAN, "start", "--attach", container, NULL};
    char *terminal[] = {PODMAN, "wait", container, NULL};
    char *kill_container[] = {PODMAN, "kill", container, NULL};
    char *cleanup[] = {PODMAN, "container", "cleanup", container, NULL};
    char *remove[] = {PODMAN, "rm", "--force", container, NULL};
    if (infrastructure == 0) infrastructure = run_argv(init, 0, &out, &err);
    int effect_code = infrastructure;
    if (infrastructure == 0) effect_code = run_argv(start, 1, &out, &err);
    if (effect_code == 124 || effect_code == 125) (void)run_argv(kill_container, 0, &out, &err);
    if (infrastructure == 0 && effect_code != 124) infrastructure = run_argv(terminal, 0, &out, &err);
    int cleanup_code = run_argv(cleanup, 0, &out, &err);
    int remove_code = run_argv(remove, 0, &out, &err);
    if (infrastructure != 0 || cleanup_code != 0 || remove_code != 0)
        die("V27 Podman lifecycle or cgroup drain failed closed");

    char *stdout64 = base64(out.data, out.length);
    char *stderr64 = base64(err.data, err.length);
    printf("{\"exitCode\":%d,\"lifecycle\":[\"create\",\"init\",\"start-attach\",\"terminal\",\"cleanup\",\"rm\"],"
           "\"readBackBase64\":\"%s\",\"stderrBase64\":\"%s\",\"stdoutBase64\":\"%s\"}\n",
           effect_code, stdout64, stderr64, stdout64);
    return 0;
}

int main(int argc, char **argv) {
    initialize_host_environment();
    if (argc == 2 && strcmp(argv[1], "--startup-factory-probe-v27") == 0) {
        verify_selinux_transition();
        puts(STARTUP_FACTORY_V27_PROBE_JSON);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--startup-factory-execute-v27") == 0) {
        verify_selinux_transition();
        return execute_plan();
    }
    die("unknown V27 supervisor invocation");
    return 125;
}
