#define _GNU_SOURCE
#define PODMAN "/out/fd-inventory-child"
#define STARTUP_FACTORY_V27_TESTING 1
#define main startup_factory_supervisor_program_main
#include "../../runtime/beads-v27/startup-factory-beads-supervisor-v27.c"
#undef main

#include <sys/syscall.h>
#include <sys/prctl.h>

static int emit_creator_wire = 0;

static void emit_creator_observation(
    const char *label, const struct sf_creator_started_v1 *started,
    int readiness_observed
) {
    if (!emit_creator_wire) return;
    char observation[4096], plan_hex[65];
    hex_encode(plan_commitment, plan_hex);
    creator_creation_observation_v27(
        observation, sizeof(observation), started, readiness_observed
    );
    if (
        write_all_fd(STDOUT_FILENO, label, strlen(label)) != 0 ||
        write_all_fd(STDOUT_FILENO, "\t", 1U) != 0 ||
        write_all_fd(
            STDOUT_FILENO, creator_creation_nonce_sha256,
            strlen(creator_creation_nonce_sha256)
        ) != 0 ||
        write_all_fd(STDOUT_FILENO, "\t", 1U) != 0 ||
        write_all_fd(STDOUT_FILENO, "sha256:", 7U) != 0 ||
        write_all_fd(STDOUT_FILENO, plan_hex, 64U) != 0 ||
        write_all_fd(STDOUT_FILENO, "\t", 1U) != 0 ||
        write_all_fd(STDOUT_FILENO, observation, strlen(observation)) != 0 ||
        write_all_fd(STDOUT_FILENO, "\n", 1U) != 0
    ) die("liveness harness creator observation write failed");
}

static int make_fake_payload_cgroup(void) {
    char path[] = "/tmp/sf-v27-cgroup-XXXXXX";
    char *root = mkdtemp(path);
    if (root == NULL) {
        die("liveness harness mkdtemp failed");
    }
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0) {
        die("liveness harness cgroup directory failed");
    }
    int kill_fd = openat(
        directory,
        "cgroup.kill",
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        0600
    );
    if (kill_fd < 0) {
        die("liveness harness cgroup.kill failed");
    }
    close(kill_fd);
    int events_fd = openat(
        directory,
        "cgroup.events",
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
        0600
    );
    if (events_fd < 0) {
        die("liveness harness cgroup.events failed");
    }
    if (write_all_fd(events_fd, "populated 0\n", 12U) != 0 || close(events_fd) != 0) {
        die("liveness harness cgroup.events write failed");
    }
    return directory;
}

static void verify_drained(int directory) {
    if (dup2(directory, PAYLOAD_CGROUP_FD) < 0) {
        die("liveness harness payload FD failed");
    }
    payload_kill_fd = openat(
        PAYLOAD_CGROUP_FD, "cgroup.kill", O_WRONLY | O_CLOEXEC
    );
    payload_events_fd = openat(
        PAYLOAD_CGROUP_FD, "cgroup.events", O_RDONLY | O_CLOEXEC
    );
    if (payload_kill_fd < 0 || payload_events_fd < 0) {
        die("liveness harness preopened cgroup controls failed");
    }
    drain_payload_cgroup();
    int descriptor = openat(
        PAYLOAD_CGROUP_FD,
        "cgroup.kill",
        O_RDONLY | O_CLOEXEC
    );
    char value[3] = {0};
    if (
        descriptor < 0 ||
        read(descriptor, value, 2U) != 2 ||
        memcmp(value, "1\n", 2U) != 0
    ) {
        die("liveness harness cgroup drain was not observed");
    }
    close(descriptor);
}

struct closer {
    int descriptor;
};

static void *close_control(void *opaque) {
    struct closer *value = opaque;
    usleep(100000);
    close(value->descriptor);
    return NULL;
}

static int move_above_custody_range(int descriptor) {
    int moved = fcntl(descriptor, F_DUPFD_CLOEXEC, 32);
    if (moved < 0) {
        die("liveness harness coordination FD move failed");
    }
    close(descriptor);
    return moved;
}

static int control_loss(void) {
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0) {
        die("liveness harness socketpair failed");
    }
    if (dup2(channel[1], CONTROL_SOCKET_FD) < 0) {
        die("liveness harness control FD failed");
    }
    if (channel[1] != CONTROL_SOCKET_FD) {
        close(channel[1]);
    }
    int pidfd = (int)syscall(SYS_pidfd_open, getppid(), 0);
    if (pidfd < 0 || dup2(pidfd, CONTROLLER_PIDFD) < 0) {
        die("liveness harness pidfd failed");
    }
    if (pidfd != CONTROLLER_PIDFD) {
        close(pidfd);
    }
    int cgroup = make_fake_payload_cgroup();
    struct closer value = {.descriptor = channel[0]};
    pthread_t closer;
    if (pthread_create(&closer, NULL, close_control, &value) != 0) {
        die("liveness harness closer failed");
    }
    while (controller_runtime_live(20)) {
    }
    if (pthread_join(closer, NULL) != 0) {
        die("liveness harness closer join failed");
    }
    verify_drained(cgroup);
    return 0;
}

static int parent_loss(void) {
    int channel[2];
    int ready[2];
    int result[2];
    if (
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0 ||
        pipe2(ready, O_CLOEXEC) != 0 ||
        pipe2(result, O_CLOEXEC) != 0
    ) {
        die("liveness harness parent setup failed");
    }
    int cgroup = make_fake_payload_cgroup();
    channel[0] = move_above_custody_range(channel[0]);
    channel[1] = move_above_custody_range(channel[1]);
    ready[0] = move_above_custody_range(ready[0]);
    ready[1] = move_above_custody_range(ready[1]);
    result[0] = move_above_custody_range(result[0]);
    result[1] = move_above_custody_range(result[1]);
    cgroup = move_above_custody_range(cgroup);
    pid_t controller = fork();
    if (controller < 0) {
        die("liveness harness controller fork failed");
    }
    if (controller == 0) {
        pid_t monitor = fork();
        if (monitor < 0) {
            _exit(90);
        }
        if (monitor == 0) {
            close(channel[0]);
            close(ready[0]);
            close(result[0]);
            if (
                dup2(channel[1], CONTROL_SOCKET_FD) < 0 ||
                dup2(cgroup, PAYLOAD_CGROUP_FD) < 0
            ) {
                _exit(91);
            }
            if (channel[1] != CONTROL_SOCKET_FD) {
                close(channel[1]);
            }
            int pidfd = (int)syscall(SYS_pidfd_open, getppid(), 0);
            if (pidfd < 0 || dup2(pidfd, CONTROLLER_PIDFD) < 0) {
                _exit(92);
            }
            if (pidfd != CONTROLLER_PIDFD) {
                close(pidfd);
            }
            struct sigaction action = {0};
            action.sa_handler = mark_controller_loss;
            sigemptyset(&action.sa_mask);
            pid_t expected = getppid();
            if (
                sigaction(SIGTERM, &action, NULL) != 0 ||
                prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 ||
                getppid() != expected
            ) {
                _exit(93);
            }
            if (write_all_fd(ready[1], "R", 1U) != 0) {
                _exit(94);
            }
            while (controller_runtime_live(20)) {
            }
            verify_drained(cgroup);
            if (write_all_fd(result[1], "D", 1U) != 0) {
                _exit(95);
            }
            _exit(0);
        }
        close(channel[1]);
        close(ready[1]);
        close(result[0]);
        close(result[1]);
        char marker;
        if (read(ready[0], &marker, 1U) != 1 || marker != 'R') {
            _exit(96);
        }
        _exit(0);
    }
    close(channel[0]);
    close(channel[1]);
    close(ready[0]);
    close(ready[1]);
    close(result[1]);
    int status = 0;
    if (
        waitpid(controller, &status, 0) != controller ||
        !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0
    ) {
        die("liveness harness controller failed");
    }
    struct pollfd observed = {.fd = result[0], .events = POLLIN};
    if (poll(&observed, 1, 5000) != 1) {
        die("liveness harness monitor did not report drain");
    }
    char marker;
    if (read(result[0], &marker, 1U) != 1 || marker != 'D') {
        die("liveness harness parent-loss drain missing");
    }
    return 0;
}

static long read_decimal_file(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char value[64] = {0};
    ssize_t length = descriptor < 0 ? -1 : read(descriptor, value, sizeof(value)-1U);
    if (descriptor >= 0) close(descriptor);
    if (length <= 0) die("liveness harness marker read failed");
    char *tail = NULL; errno = 0; long parsed = strtol(value, &tail, 10);
    if (errno != 0 || tail == value || (*tail != '\0' && *tail != '\n'))
        die("liveness harness marker parse failed");
    return parsed;
}

static void require_exact_inventory_report(const char *path) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char value[128] = {0};
    ssize_t length = descriptor < 0 ? -1 : read(descriptor, value, sizeof(value)-1U);
    if (descriptor >= 0) close(descriptor);
    if (length <= 0 || strstr(value, "\nfds=0,1,2\n") == NULL)
        die("liveness harness child FD inventory changed");
}

static int child_placement(int deny_release) {
    char marker[128];
    if (snprintf(marker, sizeof(marker), "/tmp/sf-v27-child-marker-%ld", (long)getpid()) >= (int)sizeof(marker))
        die("liveness harness marker path failed");
    unlink(marker);
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0)
        die("liveness harness placement socket failed");
    int procs = open("/tmp/sf-v27-placement-procs", O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (procs < 0) die("liveness harness placement control failed");
    pid_t supervisor = fork();
    if (supervisor < 0) die("liveness harness placement supervisor fork failed");
    if (supervisor == 0) {
        close(channel[0]);
        if (dup2(channel[1], CONTROL_SOCKET_FD) < 0) _exit(90);
        int enabled = 1;
        if (setsockopt(CONTROL_SOCKET_FD, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) != 0) _exit(91);
        int pidfd = (int)syscall(SYS_pidfd_open, getppid(), 0);
        if (pidfd < 0 || dup2(pidfd, CONTROLLER_PIDFD) < 0) _exit(92);
        int protected = open("/dev/null", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        const int protected_fds[] = {3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15};
        if (protected < 0) _exit(93);
        for (size_t index = 0; index < sizeof(protected_fds)/sizeof(protected_fds[0]); ++index)
            if (dup2(protected, protected_fds[index]) < 0) _exit(94);
        char *arguments[] = {"sf-v27-child", marker, NULL};
        struct bytes output = {0}, errors = {0};
        int result = run_argv(arguments, 0, 0, &output, &errors);
        _exit(result == (deny_release ? 125 : 0) ? 0 : 95);
    }
    close(channel[1]);
    char request[256] = {0};
    ssize_t length = recv(channel[0], request, sizeof(request)-1U, 0);
    long child = 0; char start[32], nonce[65]; int ordinal = -1;
    if (length <= 0 || sscanf(request, "PLACE %ld %31s %d %64s", &child, start, &ordinal, nonce) != 4 || ordinal != 0)
        die("liveness harness placement request changed");
    if (deny_release) {
        close(channel[0]);
    } else {
        char placed[64]; int placed_length = snprintf(placed, sizeof(placed), "%ld\n", child);
        if (placed_length <= 0 || pwrite(procs, placed, (size_t)placed_length, 0) != placed_length)
            die("liveness harness controller placement failed");
        char response[192]; int response_length = snprintf(response, sizeof(response), "PLACED %ld %d %s\n", child, ordinal, nonce);
        if (response_length <= 0 || send(channel[0], response, (size_t)response_length, 0) != response_length)
            die("liveness harness placement authorization failed");
    }
    int status = 0;
    if (waitpid(supervisor, &status, 0) != supervisor || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        die("liveness harness placement supervisor failed");
    if (deny_release) {
        if (access(marker, F_OK) == 0) die("liveness harness child executed before placement");
    } else {
        long placed = read_decimal_file("/tmp/sf-v27-placement-procs");
        long executed = read_decimal_file(marker);
        require_exact_inventory_report(marker);
        if (placed != executed) die("liveness harness placement/release identity changed");
        close(channel[0]);
    }
    close(procs); unlink("/tmp/sf-v27-placement-procs"); unlink(marker);
    return 0;
}

static int proc_stat_parser(void) {
    char start[32];
    const char valid[] =
        "123 (comm ) with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 99\n";
    const char missing[] =
        "123 (comm with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18";
    const char nondigit[] =
        "123 (comm with spaces) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4x42\n";
    if (parse_child_start_time_stat(valid, start) != 0 || strcmp(start, "4242") != 0)
        die("liveness harness stat parser rejected comm spaces/right parenthesis");
    if (parse_child_start_time_stat(missing, start) == 0 ||
        parse_child_start_time_stat(nondigit, start) == 0 ||
        parse_child_start_time_stat("123 malformed", start) == 0)
        die("liveness harness stat parser accepted malformed input");

    int gate[2];
    if (pipe2(gate, O_CLOEXEC) != 0) die("liveness harness stat gate failed");
    pid_t child = fork();
    if (child < 0) die("liveness harness stat child fork failed");
    if (child == 0) {
        close(gate[1]);
        if (prctl(PR_SET_NAME, "comm ) spaces", 0, 0, 0) != 0) _exit(91);
        char release;
        _exit(read(gate[0], &release, 1U) == 1 ? 0 : 92);
    }
    close(gate[0]);
    if (child_start_time(child, start) != 0 || strcmp(start, "0") == 0)
        die("liveness harness real proc start-time parse failed");
    if (write_all_fd(gate[1], "x", 1U) != 0 || close(gate[1]) != 0)
        die("liveness harness stat child release failed");
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        die("liveness harness stat child failed");
    return 0;
}

static int rights_transfer(const char *mode) {
    int directory = make_fake_payload_cgroup();
    int events = openat(directory, "cgroup.events", O_RDONLY | O_CLOEXEC);
    int killfd = openat(directory, "cgroup.kill", O_WRONLY | O_CLOEXEC);
    int extra = open("/dev/null", O_RDONLY | O_CLOEXEC);
    int channel[2];
    if (events < 0 || killfd < 0 || extra < 0 || socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0)
        die("liveness harness rights setup failed");
    int passcred = 1;
    if (setsockopt(channel[1], SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred)) != 0)
        die("liveness harness rights passcred failed");
    events = move_above_custody_range(events); killfd = move_above_custody_range(killfd);
    extra = move_above_custody_range(extra); channel[0] = move_above_custody_range(channel[0]);
    channel[1] = move_above_custody_range(channel[1]);
    pid_t child = fork();
    if (child < 0) die("liveness harness rights fork failed");
    if (child == 0) {
        close(channel[0]);
        if (dup2(channel[1], CONTROL_SOCKET_FD) < 0 || dup2(directory, PAYLOAD_CGROUP_FD) < 0)
            _exit(91);
        int nullfd = open("/dev/null", O_RDWR | O_CLOEXEC);
        for (int fd = 3; fd <= 12; ++fd)
            if (fd != CONTROL_SOCKET_FD && fd != PAYLOAD_CGROUP_FD && dup2(nullfd, fd) < 0)
                _exit(92);
        for (int fd = 15; fd < 128; ++fd) close(fd);
        credentialed_control("RELEASE\n", 1);
        if (strcmp(mode, "rights-replayed") == 0)
            credentialed_control("ACK\n", 0);
        _exit(0);
    }
    close(channel[1]);
    int descriptors[3] = {events, killfd, extra};
    size_t count = strcmp(mode, "rights-missing") == 0 ? 1U : strcmp(mode, "rights-extra") == 0 ? 3U : 2U;
    char ancillary[CMSG_SPACE(3U * sizeof(int))]; struct iovec iov = {.iov_base = "RELEASE\n", .iov_len = 8U};
    struct msghdr message = {0}; message.msg_iov = &iov; message.msg_iovlen = 1;
    message.msg_control = ancillary; message.msg_controllen = CMSG_SPACE(count * sizeof(int));
    struct cmsghdr *item = CMSG_FIRSTHDR(&message); item->cmsg_level = SOL_SOCKET;
    item->cmsg_type = SCM_RIGHTS; item->cmsg_len = CMSG_LEN(count * sizeof(int));
    memcpy(CMSG_DATA(item), descriptors, count * sizeof(int));
    if (sendmsg(channel[0], &message, 0) != 8) die("liveness harness rights send failed");
    if (strcmp(mode, "rights-replayed") == 0) {
        iov.iov_base = "ACK\n"; iov.iov_len = 4U; message.msg_controllen = CMSG_SPACE(2U * sizeof(int));
        item = CMSG_FIRSTHDR(&message); item->cmsg_len = CMSG_LEN(2U * sizeof(int));
        memcpy(CMSG_DATA(item), descriptors, 2U * sizeof(int));
        if (sendmsg(channel[0], &message, 0) != 4) die("liveness harness replay send failed");
    }
    int status = 0; if (waitpid(child, &status, 0) != child) die("liveness harness rights wait failed");
    int expected = strcmp(mode, "rights-valid") == 0 ? 0 : 125;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != expected)
        die("liveness harness rights disposition changed");
    return 0;
}

static int native_event_protocol(int tamper_ack,int revoke_cutoff) {
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0)
        die("liveness harness native-event socket failed");
    int passcred = 1;
    if (setsockopt(channel[1], SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred)) != 0)
        die("liveness harness native-event passcred failed");
    pid_t child = fork();
    if (child < 0) die("liveness harness native-event fork failed");
    if (child == 0) {
        close(channel[0]);
        if (dup2(channel[1], CONTROL_SOCKET_FD) < 0) _exit(91);
        if (channel[1] != CONTROL_SOCKET_FD) close(channel[1]);
        for (size_t index = 0U; index < sizeof(request_key); ++index)
            request_key[index] = (unsigned char)index;
        for (size_t index = 0U; index < sizeof(plan_commitment); ++index)
            plan_commitment[index] = (unsigned char)(0xa0U + index);
        request_key_live = 1;
        native_event_sequence = 0U;
        struct plan plan = {
            .stage_plan_sha256 =
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        };
        const char *event=revoke_cutoff==1?"native-creator-created":
            revoke_cutoff==2?"release-consumed-current":"supervisor-running";
        const char *phase=revoke_cutoff==1?"after":"before";
        char observation[256];
        if(revoke_cutoff==1)
            strcpy(observation,"{\"creatorHandleCaptured\":true,\"creatorStarted\":true,\"fd11CloseRc\":0,\"fd11PreCloseIdentityRevalidated\":true,\"fd7CloseRc\":0,\"pidfdPreCloseTerminal\":false,\"proofFdsClosed\":true,\"pthreadCreateRc\":0}");
        else if(revoke_cutoff==2)
            strcpy(observation,"{\"futexWakeCount\":0,\"releaseStoreCount\":0}");
        else if(snprintf(
                    observation,sizeof(observation),
                    "{\"controlPeek\":\"eagain\",\"fd11IdentityRevalidated\":true,\"pidfdTerminal\":false,\"supervisorPid\":%ld}",
                    (long)getpid()
                )<=0)_exit(93);
        int observed_revoke=native_event(&plan,event,phase,observation);
        if(observed_revoke!=(revoke_cutoff!=0)||
            controller_revoke_authorized!=(revoke_cutoff!=0))_exit(92);
        sfv27_secure_zero(request_key, sizeof(request_key));
        request_key_live = 0;
        _exit(0);
    }
    close(channel[1]);
    unsigned char packet[4096] = {0};
    ssize_t length = recv(channel[0], packet, sizeof(packet)-1U, 0);
    unsigned int sequence = 0U; char phase[16], event[80], observation_hex[4097], evidence[65], observed_hmac[65];
    if (length <= 0 || sscanf(
            (char *)packet, "EVENT %u %15s %79s %4096s %64s %64s",
            &sequence, phase, event, observation_hex, evidence, observed_hmac
        ) != 6 || sequence != 1U ||
        strcmp(phase, revoke_cutoff==1?"after":"before") != 0 ||
        strcmp(event, revoke_cutoff==1?"native-creator-created":
            revoke_cutoff==2?"release-consumed-current":"supervisor-running") != 0)
        die("liveness harness native-event packet changed");
    size_t observation_hex_length=strlen(observation_hex);
    if(observation_hex_length==0U||(observation_hex_length&1U)!=0U||
       observation_hex_length>=1024U)
        die("liveness harness native-event observation size changed");
    char observation[513];
    for(size_t index=0U;index<observation_hex_length;index+=2U){
        int high=observation_hex[index]>='0'&&observation_hex[index]<='9'?
            observation_hex[index]-'0':
            observation_hex[index]>='a'&&observation_hex[index]<='f'?
            observation_hex[index]-'a'+10:-1;
        int low=observation_hex[index+1U]>='0'&&observation_hex[index+1U]<='9'?
            observation_hex[index+1U]-'0':
            observation_hex[index+1U]>='a'&&observation_hex[index+1U]<='f'?
            observation_hex[index+1U]-'a'+10:-1;
        if(high<0||low<0)die("liveness harness native-event observation encoding changed");
        observation[index/2U]=(char)((high<<4)|low);
    }
    observation[observation_hex_length/2U]='\0';
    unsigned char key[32];
    for (size_t index = 0U; index < sizeof(key); ++index) key[index] = (unsigned char)index;
    char evidence_body[2048]; int evidence_body_length=snprintf(
        evidence_body,sizeof(evidence_body),
        "{\"event\":\"%s\",\"eventObservation\":%s,\"phase\":\"%s\",\"schemaVersion\":27,\"sequence\":%u,\"stagePlanSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        event,observation,phase,sequence
    );
    if(evidence_body_length<=0||(size_t)evidence_body_length>=sizeof(evidence_body))
        die("liveness harness native-event evidence body overflow");
    size_t evidence_material_length=(sizeof(native_event_evidence_domain)-1U)+(size_t)evidence_body_length;
    unsigned char *evidence_material=malloc(evidence_material_length);
    if(evidence_material==NULL)die("liveness harness native-event evidence allocation failed");
    memcpy(evidence_material,native_event_evidence_domain,sizeof(native_event_evidence_domain)-1U);
    memcpy(evidence_material+sizeof(native_event_evidence_domain)-1U,evidence_body,(size_t)evidence_body_length);
    unsigned char expected_evidence[32];char expected_evidence_hex[65];
    sfv27_sha256(evidence_material,evidence_material_length,expected_evidence);
    free(evidence_material);hex_encode(expected_evidence,expected_evidence_hex);
    if(strcmp(evidence,expected_evidence_hex)!=0)
        die("liveness harness native-event evidence changed");
    char body[2048]; int body_length = snprintf(
        body, sizeof(body),
        "{\"event\":\"%s\",\"eventEvidenceSha256\":\"sha256:%s\",\"eventObservation\":%s,\"phase\":\"%s\",\"schemaVersion\":27,\"sequence\":%u,\"stagePlanSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        event, evidence, observation, phase, sequence
    );
    unsigned char expected[32]; char expected_hex[65];
    if (body_length <= 0 || (size_t)body_length >= sizeof(body))
        die("liveness harness native-event body overflow");
    sfv27_hmac_sha256(
        key, native_event_domain, sizeof(native_event_domain)-1U,
        (const unsigned char *)body, (size_t)body_length, expected
    );
    hex_encode(expected, expected_hex);
    if (strcmp(observed_hmac, expected_hex) != 0)
        die("liveness harness native-event HMAC changed");
    static const char authority[] =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    static const char control_authority[] =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const char *control_action=revoke_cutoff?"revoke":"continue";
    char control_json[80];
    if(revoke_cutoff)snprintf(control_json,sizeof(control_json),"\"sha256:%s\"",control_authority);
    else strcpy(control_json,"null");
    char ack_body[1024]; int ack_body_length = snprintf(
        ack_body, sizeof(ack_body),
        "{\"authorityRecordSha256\":\"sha256:%s\",\"controlAction\":\"%s\",\"controlAuthorityRecordSha256\":%s,\"creatorCaptureBinding\":null,\"event\":\"%s\",\"phase\":\"%s\",\"schemaVersion\":27,\"sequence\":%u,\"stagePlanSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
        authority,control_action,control_json,event,phase,sequence
    );
    unsigned char ack_hmac[32]; char ack_hex[65];
    if (ack_body_length <= 0 || (size_t)ack_body_length >= sizeof(ack_body))
        die("liveness harness native-event ACK body overflow");
    sfv27_hmac_sha256(
        key, native_event_ack_domain, sizeof(native_event_ack_domain)-1U,
        (const unsigned char *)ack_body, (size_t)ack_body_length, ack_hmac
    );
    hex_encode(ack_hmac, ack_hex);
    if (tamper_ack) ack_hex[0] = ack_hex[0] == '0' ? '1' : '0';
    char acknowledgement[512]; int acknowledgement_length = snprintf(
        acknowledgement, sizeof(acknowledgement),
        "EVENT-ACK %u %s %s %s %s %s %s - - -\n",
        sequence,phase,event,authority,ack_hex,control_action,
        revoke_cutoff?control_authority:"-"
    );
    if (acknowledgement_length <= 0 ||
        send(channel[0], acknowledgement, (size_t)acknowledgement_length, 0)
            != acknowledgement_length)
        die("liveness harness native-event ACK send failed");
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != (tamper_ack ? 125 : 0))
        die("liveness harness native-event child disposition changed");
    close(channel[0]);
    sfv27_secure_zero(key, sizeof(key));
    sfv27_secure_zero(expected_evidence, sizeof(expected_evidence));
    sfv27_secure_zero(expected, sizeof(expected));
    sfv27_secure_zero(ack_hmac, sizeof(ack_hmac));
    return 0;
}

static int native_failure_result(
    const char *result_kind, const char *predecessor_kind, const char *reason,
    int tamper_ack
) {
    char path[] = "/tmp/sf-v27-result-XXXXXX";
    char *root = mkdtemp(path);
    if (root == NULL) die("liveness harness native-result directory failed");
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    int evidence = openat(
        directory, "evidence", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600
    );
    int proof = open(
        "/proc/self/task/self/stat", O_RDONLY | O_CLOEXEC | O_NOFOLLOW
    );
    if (proof < 0) proof = open("/proc/self/stat", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int channel[2], output[2];
    if (directory < 0 || evidence < 0 || proof < 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0 ||
        pipe2(output, O_CLOEXEC) != 0)
        die("liveness harness native-result setup failed");
    int passcred = 1;
    if (setsockopt(channel[1], SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred)) != 0)
        die("liveness harness native-result passcred failed");
    directory = move_above_custody_range(directory);
    evidence = move_above_custody_range(evidence);
    proof = move_above_custody_range(proof);
    channel[0] = move_above_custody_range(channel[0]);
    channel[1] = move_above_custody_range(channel[1]);
    output[0] = move_above_custody_range(output[0]);
    output[1] = move_above_custody_range(output[1]);
    pid_t child = fork();
    if (child < 0) die("liveness harness native-result fork failed");
    if (child == 0) {
        close(channel[0]); close(output[0]);
        int pidfd = (int)syscall(SYS_pidfd_open, getppid(), 0);
        if (pidfd < 0 || dup2(channel[1], CONTROL_SOCKET_FD) < 0 ||
            dup2(pidfd, CONTROLLER_PIDFD) < 0 || dup2(directory, RESULT_FD) < 0 ||
            dup2(proof, LAUNCHER_PROOF_FD) < 0 || dup2(evidence, EVIDENCE_FD) < 0 ||
            dup2(output[1], STDOUT_FILENO) < 0)
            _exit(91);
        for (size_t index = 0U; index < sizeof(request_key); ++index)
            request_key[index] = (unsigned char)(index + 1U);
        sfv27_sha256(request_key, sizeof(request_key), request_key_id);
        for (size_t index = 0U; index < sizeof(plan_commitment); ++index)
            plan_commitment[index] = (unsigned char)(0x60U + index);
        request_key_live = 1; placement_mask = 0U;
        struct plan plan = {
            .stage_plan_sha256 =
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        };
        _exit(publish_authenticated_stage_result(
            &plan, NULL, result_kind, predecessor_kind, reason
        ));
    }
    close(channel[1]); close(output[1]);
    char offer[1024] = {0};
    ssize_t offer_length = recv(channel[0], offer, sizeof(offer)-1U, 0);
    char native_hex[65], observed_kind[80], observed_predecessor[112];
    char failure_hex[65], offer_hmac_hex[65]; unsigned int observed_mask = 1U;
    if (offer_length <= 0 || sscanf(
            offer, "RESULT-OFFER %64s %79s %111s %64s %u %64s",
            native_hex, observed_kind, observed_predecessor, failure_hex,
            &observed_mask, offer_hmac_hex
        ) != 6 || strcmp(observed_kind, result_kind) != 0 ||
        strcmp(observed_predecessor, predecessor_kind) != 0 ||
        observed_mask != 0U)
        die("liveness harness native result offer changed");
    char result_path[256];
    if (snprintf(result_path, sizeof(result_path), "%s/result.json", root) >= (int)sizeof(result_path))
        die("liveness harness native-result path overflow");
    struct stat before_ack;
    struct pollfd blocked_output = {.fd=output[0],.events=POLLIN|POLLHUP};
    if (lstat(result_path, &before_ack) == 0 || errno != ENOENT ||
        poll(&blocked_output,1,0) != 0)
        die("liveness harness result escaped before offer ACK");
    unsigned char key[32];
    for (size_t index = 0U; index < sizeof(key); ++index)
        key[index] = (unsigned char)(index + 1U);
    char failure_json[96];
    if (snprintf(failure_json,sizeof(failure_json),"\"sha256:%s\"",failure_hex) >= (int)sizeof(failure_json))
        die("liveness harness failure digest overflow");
    char offer_body[2048];int offer_body_length=snprintf(offer_body,sizeof(offer_body),
      "{\"failureEvidenceSha256\":%s,\"nativeResultSha256\":\"sha256:%s\",\"placementMask\":0,\"protocol\":\"startup-factory/beads-native-worker/v27\",\"resultKind\":\"%s\",\"resultPredecessorKind\":\"%s\",\"schemaVersion\":27,\"stagePlanSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"status\":\"result-offer\"}",
      failure_json,native_hex,result_kind,predecessor_kind);
    unsigned char expected_offer[32];char expected_offer_hex[65];
    if(offer_body_length<=0||(size_t)offer_body_length>=sizeof(offer_body))
        die("liveness harness offer body overflow");
    sfv27_hmac_sha256(key,result_offer_domain,sizeof(result_offer_domain)-1U,(const unsigned char*)offer_body,(size_t)offer_body_length,expected_offer);hex_encode(expected_offer,expected_offer_hex);
    if(strcmp(offer_hmac_hex,expected_offer_hex)!=0)
        die("liveness harness native result offer HMAC changed");
    static const char authorization_hex[] =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    char ack_body[1024];int ack_body_length=snprintf(ack_body,sizeof(ack_body),
      "{\"action\":\"ACK-RESULT-OFFER\",\"authorizationRecordSha256\":\"sha256:%s\",\"nativeResultSha256\":\"sha256:%s\",\"protocol\":\"startup-factory/beads-native-worker/v27\",\"schemaVersion\":27,\"stagePlanSha256\":\"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}",
      authorization_hex,native_hex);
    unsigned char ack_hmac[32];char ack_hmac_hex[65];
    if(ack_body_length<=0||(size_t)ack_body_length>=sizeof(ack_body))
        die("liveness harness result ACK body overflow");
    sfv27_hmac_sha256(key,result_offer_ack_domain,sizeof(result_offer_ack_domain)-1U,(const unsigned char*)ack_body,(size_t)ack_body_length,ack_hmac);hex_encode(ack_hmac,ack_hmac_hex);
    if(tamper_ack)ack_hmac_hex[0]=ack_hmac_hex[0]=='0'?'1':'0';
    char ack[512];int ack_length=snprintf(ack,sizeof(ack),"RESULT-OFFER-ACK %s %s %s\n",native_hex,authorization_hex,ack_hmac_hex);
    if(ack_length<=0||send(channel[0],ack,(size_t)ack_length,0)!=ack_length)
        die("liveness harness result ACK send failed");
    char terminal[64] = {0};
    ssize_t terminal_length = recv(channel[0], terminal, sizeof(terminal)-1U, 0);
    if (tamper_ack) {
        int status = 0;
        if (terminal_length != 0 || waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status) != 125 ||
            lstat(result_path,&before_ack) == 0 || errno != ENOENT)
            die("liveness harness tampered result ACK escaped");
        close(channel[0]);close(output[0]);close(directory);close(evidence);close(proof);
        return 0;
    }
    if (terminal_length != 15 || memcmp(terminal, "CONTROL-DONE 0\n", 15U) != 0)
        die("liveness harness native-result terminal mask changed");
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        die("liveness harness native-result child failed");
    char stdout_value[4096] = {0};
    ssize_t stdout_length = read(output[0], stdout_value, sizeof(stdout_value)-1U);
    int result_fd = open(result_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char stored[4096] = {0}; ssize_t stored_length = result_fd < 0 ? -1 : read(result_fd, stored, sizeof(stored)-1U);
    if (result_fd >= 0) close(result_fd);
    char kind_field[160];
    if (snprintf(kind_field, sizeof(kind_field), "\"resultKind\":\"%s\"", result_kind) >= (int)sizeof(kind_field) ||
        stdout_length <= 0 || stored_length != stdout_length ||
        memcmp(stored, stdout_value, (size_t)stored_length) != 0 ||
        strstr(stored, kind_field) == NULL ||
        strstr(stored, "\"failureEvidenceSha256\":\"sha256:") == NULL ||
        pread(evidence, stored, 32U, 0) != 32)
        die("liveness harness native-result envelope changed");
    close(channel[0]);close(output[0]);close(directory);close(evidence);close(proof);
    return 0;
}

static int native_failure_results(void) {
    if (native_failure_result(
            "precreate-failed", "supervisor-precreate-failed",
            "runtime-precreate-failed",0) != 0 ||
        native_failure_result(
            "create-failed-no-thread", "supervisor-create-failed-no-thread",
            "runtime-create-failed",0) != 0 ||
        native_failure_result(
            "controlled-abort-failed", "creator-abort-failure-lifetime",
            "runtime-controlled-abort-failed",0) != 0 ||
        native_failure_result(
            "revoke-verified-no-effect",
            "creator-lifetime-closed-revoke-verified-no-effect",
            "runtime-revoked-no-effect",0) != 0)
        die("liveness harness native failure result matrix changed");
    return 0;
}

static int abort_and_join_creator_fixture(
    struct creator_result *result, struct sf_creator_slot_v1 *slot,
    const struct sf_creator_started_v1 *started, int controller_channel
) {
    if (pthread_mutex_lock(&result->gate_mutex) != 0)
        die("liveness harness uncertain creator abort lock failed");
    result->abort_authorized = 1;
    result->creator_return_authorized = 1;
    if (
        pthread_cond_broadcast(&result->gate_condition) != 0 ||
        pthread_mutex_unlock(&result->gate_mutex) != 0
    )
        die("liveness harness uncertain creator abort wake failed");
    void *return_value = NULL;
    int join_rc = pthread_join(slot->pthread, &return_value);
    slot->handle_consumed = join_rc == 0;
    int identity_observed = started->creator_tid_present &&
        started->creator_start_ticks_present;
    if (
        join_rc != 0 || return_value != &creator_abort_sentinel ||
        !slot->handle_consumed ||
        (identity_observed && !wait_creator_task_absent(started->creator_tid))
    )
        die("liveness harness uncertain creator abort join changed");
    if (emit_creator_wire) {
        char start_json[64], tid_json[32], observation[1536], plan_hex[65];
        const char *start_value = creator_optional_json_string_v27(
            started->creator_start_ticks, started->creator_start_ticks_present,
            start_json, sizeof(start_json)
        );
        const char *tid_value = creator_optional_int_v27(
            started->creator_tid_present ? (int)started->creator_tid : -1,
            tid_json
        );
        hex_encode(plan_commitment, plan_hex);
        int length = snprintf(
            observation, sizeof(observation),
            "{\"creatorHandleConsumed\":true,\"creatorHandshakeStatus\":\"%s\",\"creatorStartTicks\":%s,\"creatorStartTicksPresent\":%s,\"creatorTaskAbsent\":%s,\"creatorTid\":%s,\"creatorTidPresent\":%s,\"failurePhase\":\"%s\",\"payloadReleaseCount\":0,\"pthreadJoinRc\":%d,\"returnSentinel\":\"creator-abort-sentinel\",\"slotGeneration\":%llu}",
            started->handshake_status, start_value,
            started->creator_start_ticks_present ? "true" : "false",
            identity_observed ? "true" : "null", tid_value,
            started->creator_tid_present ? "true" : "false",
            started->failure_phase, join_rc,
            (unsigned long long)creator_slot_generation
        );
        const char *label = strcmp(started->failure_phase, "attr-destroy") == 0
            ? "attr-destroy" : started->handshake_status;
        if (
            length <= 0 || (size_t)length >= sizeof(observation) ||
            write_all_fd(STDOUT_FILENO, "lifetime-", 9U) != 0 ||
            write_all_fd(STDOUT_FILENO, label, strlen(label)) != 0 ||
            write_all_fd(STDOUT_FILENO, "\t", 1U) != 0 ||
            write_all_fd(
                STDOUT_FILENO, creator_creation_nonce_sha256,
                strlen(creator_creation_nonce_sha256)
            ) != 0 ||
            write_all_fd(STDOUT_FILENO, "\tsha256:", 8U) != 0 ||
            write_all_fd(STDOUT_FILENO, plan_hex, 64U) != 0 ||
            write_all_fd(STDOUT_FILENO, "\t", 1U) != 0 ||
            write_all_fd(
                STDOUT_FILENO, observation, (size_t)length
            ) != 0 ||
            write_all_fd(STDOUT_FILENO, "\n", 1U) != 0
        ) die("liveness harness abort lifetime wire failed");
    }
    consume_join_owner_token();
    if (
        pthread_cond_destroy(&result->gate_condition) != 0 ||
        pthread_mutex_destroy(&result->gate_mutex) != 0
    )
        die("liveness harness uncertain creator gate cleanup failed");
    close(CONTROL_SOCKET_FD);
    close(controller_channel);
    return 0;
}

static int creator_abi_fast_exit_inner(int attr_failure_phase) {
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) != 0)
        die("liveness harness creator ABI socket failed");
    int controller_pidfd = (int)syscall(SYS_pidfd_open, getppid(), 0);
    char launcher_proof_path[96];
    int launcher_proof_length = snprintf(
        launcher_proof_path, sizeof(launcher_proof_path),
        "/proc/%ld/task/%ld/stat", (long)getppid(), (long)getppid()
    );
    int launcher_proof = launcher_proof_length <= 0 ||
        (size_t)launcher_proof_length >= sizeof(launcher_proof_path)
        ? -1 : open(
            launcher_proof_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW
        );
    if (controller_pidfd < 0 || launcher_proof < 0)
        die("liveness harness creator ABI proof setup failed");
    channel[0] = move_above_custody_range(channel[0]);
    channel[1] = move_above_custody_range(channel[1]);
    controller_pidfd = move_above_custody_range(controller_pidfd);
    launcher_proof = move_above_custody_range(launcher_proof);
    const char *artifact_directory = getenv(
        "STARTUP_FACTORY_V27_TEST_CREATOR_ARTIFACT_DIR"
    );
    int result_directory = artifact_directory == NULL
        ? make_fake_payload_cgroup()
        : open(
            artifact_directory,
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
        );
    if (result_directory < 0)
        die("liveness harness creator artifact directory failed");
    result_directory = move_above_custody_range(result_directory);
    if (
        dup2(channel[1], CONTROL_SOCKET_FD) < 0 ||
        dup2(controller_pidfd, CONTROLLER_PIDFD) < 0 ||
        dup2(launcher_proof, LAUNCHER_PROOF_FD) < 0 ||
        dup2(result_directory, RESULT_FD) < 0
    )
        die("liveness harness creator ABI fixed proof FDs failed");
    close(channel[1]);
    close(controller_pidfd);
    close(launcher_proof);
    close(result_directory);

    proof_fds_closed = 0;
    controller_loss_signal = 0;
    join_owner_tid = (pid_t)syscall(SYS_gettid);
    if (child_start_time(getpid(), join_owner_start_ticks) != 0)
        die("liveness harness supervisor start identity failed");
    struct plan plan = {
        .operation_id =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        .stage_plan_sha256 =
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        .stage_location = "5",
        .stage_key = "mutation",
    };
    struct creator_result result = {
        .plan = &plan,
        .test_fast_exit = 1,
    };
    initialize_creator_secrets();
    if (
        snprintf(
            capture_preparation_record_sha256,
            sizeof(capture_preparation_record_sha256),
            "sha256:%064x", 0xau
        ) != 71 ||
        snprintf(
            return_authorization_record_sha256,
            sizeof(return_authorization_record_sha256),
            "sha256:%064x", 0xbu
        ) != 71 ||
        snprintf(
            creator_return_current_record_sha256,
            sizeof(creator_return_current_record_sha256),
            "sha256:%064x", 0xcu
        ) != 71
    ) die("liveness harness capture authority roots failed");
    for (size_t index = 0U; index < sizeof(request_key); ++index)
        request_key[index] = (unsigned char)(index + 1U);
    sfv27_sha256(request_key, sizeof(request_key), request_key_id);
    request_key_live = 1;
    STARTUP_FACTORY_V27_TEST_ATTR_FAILURE_PHASE = attr_failure_phase;
    if (
        pthread_mutex_init(&result.gate_mutex, NULL) != 0 ||
        pthread_cond_init(&result.gate_condition, NULL) != 0
    )
        die("liveness harness creator ABI gate setup failed");
    struct sf_creator_slot_v1 slot = {
        .slot_id = "payload-terminal-creator",
        .generation = creator_slot_generation,
    };
    struct sf_creator_plan_v1 sealed_plan = {
        .result = &result,
        .plan_digest = plan_commitment,
        .plan_digest_length = sizeof(plan_commitment),
        .creation_nonce = creator_creation_nonce,
        .creation_nonce_length = sizeof(creator_creation_nonce),
        .creation_nonce_sha256 = creator_creation_nonce_sha256,
        .supervisor_pid = getpid(),
        .supervisor_start_ticks = join_owner_start_ticks,
    };
    struct sf_creator_started_v1 started = {0};
    int start_rc = sf_beads_creator_start_v1(&slot, &sealed_plan, &started);
    if (STARTUP_FACTORY_V27_TEST_CREATE_FAILURE_RC != 0) {
        if (
            start_rc != STARTUP_FACTORY_V27_TEST_CREATE_FAILURE_RC ||
            !started.create_called || started.slot_allocated || slot.allocated ||
            started.pthread_create_rc != STARTUP_FACTORY_V27_TEST_CREATE_FAILURE_RC ||
            started.failure_phase == NULL ||
            strcmp(started.failure_phase, "pthread-create") != 0 ||
            !proof_fds_closed
        )
            die("liveness harness real pthread_create failure union changed");
        if (
            pthread_cond_destroy(&result.gate_condition) != 0 ||
            pthread_mutex_destroy(&result.gate_mutex) != 0
        )
            die("liveness harness create failure gate cleanup failed");
        consume_join_owner_token();
        close(CONTROL_SOCKET_FD);
        close(channel[0]);
        return 0;
    }
    if (STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE != 0) {
        static const char *const statuses[10] = {
            NULL, "cancellation-disable-failed", "signal-mask-failed",
            "parent-identity-mismatch", "creation-nonce-echo-failed",
            "plan-digest-echo-failed", "handshake-timeout",
            "creator-tid-invalid", "creator-start-unreadable",
            "supervisor-start-unreadable",
        };
        int phase = STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE;
        if (
            start_rc == 0 || !started.create_called || !started.slot_allocated ||
            !slot.allocated || started.pthread_create_rc != 0 ||
            !join_owner_token_valid(&slot) || started.handshake_status == NULL ||
            strcmp(started.handshake_status, statuses[phase]) != 0 ||
            (phase == 6
                ? (started.handshake_reported ||
                   started.handshake_futex_wait_errno != ETIMEDOUT ||
                   started.handshake_futex_value != -1 ||
                   started.handshake_futex_wake_return != -1)
                : (!started.handshake_reported ||
                   started.handshake_futex_wait_return != 0 ||
                   started.handshake_futex_wait_errno != 0 ||
                   started.handshake_futex_value <= 0 ||
                   started.handshake_futex_wake_return < 0))
        )
            die("liveness harness creator handshake failure union changed");
        if (
            (phase == 1 &&
                (started.creator_cancel_disable_rc != EINVAL ||
                 started.creator_signal_mask_rc != -1)) ||
            (phase == 2 &&
                (started.creator_cancel_disable_rc != 0 ||
                 started.creator_signal_mask_rc != EINVAL)) ||
            (phase == 3 && started.parent_identity_verified) ||
            (phase == 4 &&
                strcmp(started.handshake_nonce_sha256,
                       creator_creation_nonce_sha256) == 0) ||
            (phase == 5 &&
                sfv27_equal(started.plan_digest, plan_commitment, 32U))
        )
            die("liveness harness creator handshake phase evidence changed");
        emit_creator_observation(statuses[phase], &started, 0);
        return abort_and_join_creator_fixture(
            &result, &slot, &started, channel[0]
        );
    }
    if (attr_failure_phase > 0 && attr_failure_phase < 6) {
        static const char *const expected_phase[6] = {
            NULL, "attr-init", "attr-setdetach", "attr-getdetach",
            "attr-guard", "attr-stack"
        };
        if (
            start_rc == 0 || started.create_called || started.slot_allocated ||
            slot.allocated || started.pthread_create_rc != -1 ||
            started.failure_phase == NULL ||
            strcmp(started.failure_phase, expected_phase[attr_failure_phase]) != 0 ||
            !proof_fds_closed || started.pidfd_close_rc != 0 ||
            started.stat_close_rc != 0 ||
            (attr_failure_phase == 1
                ? started.pthread_attr_destroy_rc != -1
                : started.pthread_attr_destroy_rc != 0) ||
            (attr_failure_phase >= 4 &&
                (started.pthread_attr_getdetachstate_rc != 0 ||
                 started.pthread_attr_detachstate_readback != PTHREAD_CREATE_JOINABLE))
        )
            die("liveness harness attr failure union changed");
        if (
            pthread_cond_destroy(&result.gate_condition) != 0 ||
            pthread_mutex_destroy(&result.gate_mutex) != 0
        )
            die("liveness harness attr failure gate cleanup failed");
        consume_join_owner_token();
        close(CONTROL_SOCKET_FD);
        close(channel[0]);
        return 0;
    }
    if (attr_failure_phase == 6) {
        if (
            start_rc == 0 || !started.create_called || !started.slot_allocated ||
            !slot.allocated || started.pthread_create_rc != 0 ||
            started.pthread_attr_destroy_rc != EINVAL ||
            started.failure_phase == NULL ||
            strcmp(started.failure_phase, "attr-destroy") != 0 ||
            !started.handshake_reported || !started.handshake_complete ||
            !proof_fds_closed || !join_owner_token_valid(&slot)
        )
            die("liveness harness attr destroy failure union changed");
        emit_creator_observation("attr-destroy", &started, 1);
        return abort_and_join_creator_fixture(
            &result, &slot, &started, channel[0]
        );
    }
    if (
        start_rc != 0 || started.pthread_create_rc != 0 ||
        started.pthread_attr_destroy_rc != 0 || !started.handshake_complete ||
        !slot.allocated || proof_fds_closed != 1 ||
        started.pidfd_close_rc != 0 || started.stat_close_rc != 0 ||
        result.creator_cancel_disable_rc != 0 ||
        result.creator_signal_mask_rc != 0 ||
        started.slot_id != slot.slot_id ||
        started.slot_generation != slot.generation ||
        started.creator_tid != result.creator_tid ||
        strcmp(started.creator_start_ticks, result.creator_start_ticks) != 0 ||
        strcmp(started.handshake_nonce_sha256, creator_creation_nonce_sha256) != 0 ||
        !sfv27_equal(started.plan_digest, plan_commitment, 32U) ||
        !join_owner_token_valid(&slot) ||
        !creator_task_matches(result.creator_tid, result.creator_start_ticks)
    )
        die("liveness harness creator ABI creation receipt changed");

    emit_creator_observation("valid", &started, 1);

    if (pthread_mutex_lock(&result.gate_mutex) != 0)
        die("liveness harness creator ABI release lock failed");
    if (result.release_known_live || result.creator_return_waiting)
        die("liveness harness creator escaped before release");
    result.release_authorized = 1;
    if (pthread_cond_broadcast(&result.gate_condition) != 0)
        die("liveness harness creator ABI release failed");
    while (!result.release_known_live)
        if (pthread_cond_wait(&result.gate_condition, &result.gate_mutex) != 0)
            die("liveness harness creator ABI known-live wait failed");
    if (
        result.creator_return_waiting ||
        !creator_task_matches(result.creator_tid, result.creator_start_ticks)
    )
        die("liveness harness creator passed the second ACK barrier early");
    result.release_live_ack = 1;
    if (pthread_cond_broadcast(&result.gate_condition) != 0)
        die("liveness harness creator ABI second ACK failed");
    while (!result.creator_return_waiting)
        if (pthread_cond_wait(&result.gate_condition, &result.gate_mutex) != 0)
            die("liveness harness creator ABI return-wait failed");
    if (!creator_task_matches(result.creator_tid, result.creator_start_ticks))
        die("liveness harness fast-exit creator was not retained for join");
    char capture_preparation[72];
    prepare_post_return_capture(result.creator_tid, capture_preparation);
    result.creator_return_authorized = 1;
    if (
        pthread_cond_broadcast(&result.gate_condition) != 0 ||
        pthread_mutex_unlock(&result.gate_mutex) != 0
    )
        die("liveness harness creator ABI return authorization failed");

    void *return_value = NULL;
    int join_rc = pthread_join(slot.pthread, &return_value);
    slot.handle_consumed = join_rc == 0;
    if (join_rc != 0)
        die("liveness harness creator ABI join return changed");
    if (return_value != &creator_positive_sentinel)
        die("liveness harness creator ABI return sentinel changed");
    if (!slot.handle_consumed)
        die("liveness harness creator ABI handle was not consumed");
    if (!wait_creator_task_absent(result.creator_tid)) {
        char diagnostic[192];
        int diagnostic_length = snprintf(
            diagnostic, sizeof(diagnostic),
            "liveness harness creator ABI task remained after join: "
            "creator=%ld main=%ld errno=%d",
            (long)result.creator_tid, (long)syscall(SYS_gettid), errno
        );
        if (diagnostic_length <= 0 ||
            (size_t)diagnostic_length >= sizeof(diagnostic))
            die("liveness harness creator ABI task diagnostic failed");
        die(diagnostic);
    }
    if (result.effect_code != 0)
        die("liveness harness creator ABI fast-exit result changed");
    struct sf_post_return_artifacts_v1 artifacts = {0};
    persist_post_return_artifacts_while_held_v27(
        &result, join_rc, "creator-positive-sentinel", capture_preparation,
        &artifacts
    );
    if (
        strncmp(capture_preparation, "sha256:", 7U) != 0 ||
        strncmp(artifacts.task_set_sha256, "sha256:", 7U) != 0 ||
        artifacts.fd7_getfd_errno != EBADF ||
        artifacts.fd11_getfd_errno != EBADF
    )
        die("liveness harness creator ABI capture evidence changed");
    release_post_return_capture();
    persist_allocation_gate_release_receipt_v27(
        &plan, &artifacts, capture_preparation,
        "creator-positive-sentinel"
    );
#ifdef STARTUP_FACTORY_V27_TESTING
    static const char *const artifact_names[5] = {
        ".native-creator-atomic-capture.v1",
        ".native-creator-join-result.v2",
        ".native-creator-post-return.v2",
        ".native-creator-lifetime.v4",
        ".native-allocation-gate-release.v1",
    };
    const char *const artifact_digests[5] = {
        artifacts.atomic_capture_sha256,
        artifacts.join_result_sha256,
        artifacts.post_return_observation_sha256,
        artifacts.lifetime_sha256,
        artifacts.gate_release_receipt_sha256,
    };
    for (size_t index = 0U; index < 5U; ++index)
        verify_creator_capture_artifact_bytes_v27(
            artifact_names[index], artifact_digests[index]
        );
#endif
    consume_join_owner_token();
    if (
        pthread_cond_destroy(&result.gate_condition) != 0 ||
        pthread_mutex_destroy(&result.gate_mutex) != 0
    )
        die("liveness harness creator ABI gate close failed");
    close(CONTROL_SOCKET_FD);
    close(channel[0]);
    return 0;
}

static int creator_abi_fast_exit(void) {
    pid_t child = fork();
    if (child < 0) die("liveness harness creator ABI wrapper fork failed");
    if (child == 0) _exit(creator_abi_fast_exit_inner(0));
    int status = 0;
    if (
        waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0
    )
        die("liveness harness creator ABI wrapper child failed");
    return 0;
}

static int creator_attr_failure_matrix(void) {
    for (int phase = 1; phase <= 6; ++phase) {
        pid_t child = fork();
        if (child < 0) die("liveness harness attr matrix fork failed");
        if (child == 0) _exit(creator_abi_fast_exit_inner(phase));
        int status = 0;
        if (
            waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0
        )
            die("liveness harness attr matrix child failed");
        if (phase == 6 && native_failure_result(
                "controlled-abort-failed", "creator-abort-failure-lifetime",
                "runtime-controlled-abort-failed", 0
            ) != 0)
            die("liveness harness attr-destroy FD10 result failed");
    }
    return 0;
}

static int creator_handshake_failure_matrix(void) {
    pid_t child = fork();
    if (child < 0) die("liveness harness create failure fork failed");
    if (child == 0) {
        STARTUP_FACTORY_V27_TEST_CREATE_FAILURE_RC = EAGAIN;
        _exit(creator_abi_fast_exit_inner(0));
    }
    int status = 0;
    if (
        waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0
    )
        die("liveness harness create failure child failed");
    for (int phase = 1; phase <= 9; ++phase) {
        child = fork();
        if (child < 0) die("liveness harness handshake matrix fork failed");
        if (child == 0) {
            STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE = phase;
            _exit(creator_abi_fast_exit_inner(0));
        }
        status = 0;
        if (
            waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0
        )
            die("liveness harness handshake matrix child failed");
        if (native_failure_result(
                "controlled-abort-failed", "creator-abort-failure-lifetime",
                "runtime-controlled-abort-failed", 0
            ) != 0)
            die("liveness harness handshake FD10 result failed");
    }
    return 0;
}

static int creator_handshake_wire_matrix(void) {
    for (int variant = 0; variant <= 10; ++variant) {
        pid_t child = fork();
        if (child < 0) die("liveness harness handshake wire fork failed");
        if (child == 0) {
            emit_creator_wire = 1;
            if (variant == 1)
                _exit(creator_abi_fast_exit_inner(6));
            if (variant >= 2)
                STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE = variant - 1;
            _exit(creator_abi_fast_exit_inner(0));
        }
        int status = 0;
        if (
            waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
            WEXITSTATUS(status) != 0
        ) die("liveness harness handshake wire child failed");
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[0], "sf-v27-child") == 0) {
        int marker = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        char value[64]; int length = snprintf(value, sizeof(value), "%ld\n", (long)getpid());
        if (marker < 0 || length <= 0 || write_all_fd(marker, value, (size_t)length) != 0 || close(marker) != 0)
            return 93;
        return 0;
    }
    if (argc != 2) {
        die("liveness harness mode missing");
    }
    if (strcmp(argv[1], "control-loss") == 0) {
        return control_loss();
    }
    if (strcmp(argv[1], "parent-loss") == 0) {
        return parent_loss();
    }
    if (strcmp(argv[1], "child-placement") == 0) {
        return child_placement(0);
    }
    if (strcmp(argv[1], "early-exec-denied") == 0) {
        return child_placement(1);
    }
    if (strcmp(argv[1], "proc-stat-parser") == 0) {
        return proc_stat_parser();
    }
    if (strncmp(argv[1], "rights-", 7U) == 0) {
        return rights_transfer(argv[1]);
    }
    if (strcmp(argv[1], "native-event") == 0) {
        return native_event_protocol(0,0);
    }
    if (strcmp(argv[1], "native-event-ack-tampered") == 0) {
        return native_event_protocol(1,0);
    }
    if (strcmp(argv[1], "native-event-revoke") == 0) {
        return native_event_protocol(0,1);
    }
    if (strcmp(argv[1], "native-event-revoke-at-release") == 0) {
        return native_event_protocol(0,2);
    }
    if (strcmp(argv[1], "native-failure-results") == 0) {
        return native_failure_results();
    }
    if (strcmp(argv[1], "creator-abi-fast-exit") == 0) {
        return creator_abi_fast_exit();
    }
    if (strcmp(argv[1], "creator-attr-failure-matrix") == 0) {
        return creator_attr_failure_matrix();
    }
    if (strcmp(argv[1], "creator-handshake-failure-matrix") == 0) {
        return creator_handshake_failure_matrix();
    }
    if (strcmp(argv[1], "creator-handshake-wire-matrix") == 0) {
        return creator_handshake_wire_matrix();
    }
    if (strcmp(argv[1], "native-result-offer-ack-tampered") == 0) {
        return native_failure_result(
            "precreate-failed", "supervisor-precreate-failed",
            "runtime-precreate-failed", 1
        );
    }
    die("liveness harness mode changed");
    return 125;
}
