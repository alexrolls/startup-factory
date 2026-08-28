#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "startup-factory-v27-crypto.h"

/* Closed V27 native supervisor. The worker supplies fixed FD custody 0..13,
 * then this executable re-enters through execveat(FD13, AT_EMPTY_PATH).
 * Release/SetupReady/ACK is credentialed SOCK_SEQPACKET on FD6. One sealed
 * P2 plan owns exactly one literal payload-terminal container lifecycle; the
 * protected controller schedules mutation and four distinct reads separately. */

#define PLAN_FD 3
#define REQUEST_KEY_FD 4
#define OPERATION_LOCK_FD 5
#define CONTROL_SOCKET_FD 6
#define CONTROLLER_PIDFD 7
#define SUPERVISOR_CGROUP_FD 8
#define PAYLOAD_CGROUP_FD 9
#define RESULT_FD 10
#define LAUNCHER_PROOF_FD 11
#define EVIDENCE_FD 12
#define SUPERVISOR_EXEC_FD 13
#define FIRST_FORBIDDEN_FD 14
#define MAX_FIELD 4096U
#define MAX_ARGC 64U
#define MAX_OUTPUT 1048576U
#define MAX_EXECUTABLE_BYTES 67108864U
#define STAGE_TIMEOUT_SECONDS 120
#define REGISTERED_CREATOR_STACK_SIZE 1048576U
#define REGISTERED_CREATOR_GUARD_SIZE 65536U
#ifndef PODMAN
#define PODMAN "/usr/bin/podman"
#endif
#ifndef OCI_RUNTIME
#define OCI_RUNTIME "/usr/bin/crun"
#endif
#define AT_EMPTY_PATH 0x1000
#define PROC_SUPER_MAGIC 0x9fa0
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE 129
#endif
#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE 128
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif

#ifndef STARTUP_FACTORY_V27_PROBE_JSON
#define STARTUP_FACTORY_V27_PROBE_JSON "{}"
#endif
#ifndef STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT
#define STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT ""
#endif
#ifndef STARTUP_FACTORY_V27_EXEC_CONTEXT
#define STARTUP_FACTORY_V27_EXEC_CONTEXT ""
#endif

struct bytes { unsigned char *data; size_t length; };
struct plan {
    char *operation_id; char *effect_plan_sha256; char *stage_plan_sha256;
    char *stage_location; char *stage_key; char *stage_kind; char *action_kind;
    char *image; char *repository; char *repository_custody_sha256;
    uint32_t argc; char **argv;
};
struct creator_result {
    struct plan *plan; int effect_code; struct bytes stdout_bytes;
    struct bytes stderr_bytes; int failure; pthread_mutex_t gate_mutex;
    pthread_cond_t gate_condition; int release_authorized; int abort_authorized;
    int creator_waiting; int release_known_live; int release_live_ack;
    int creator_return_waiting; int creator_return_authorized;
    int creator_handle_consumed; int creator_handshake_reported;
    int creator_handshake_complete; int parent_identity_verified;
    int creator_cancel_disable_present; int creator_signal_mask_present;
    int creator_tid_present; int creator_start_ticks_present;
    int child_supervisor_pid_present; int child_supervisor_start_ticks_present;
    int parent_identity_present; int child_creation_nonce_present;
    int child_plan_digest_present; int creator_handshake_futex_present;
    int creator_cancel_disable_rc; int creator_signal_mask_rc;
    pid_t creator_tid; char creator_start_ticks[32]; int gate_word;
    int creator_handshake_futex_word; int creator_handshake_futex_wake_return;
    pid_t child_supervisor_pid; char child_supervisor_start_ticks[32];
    char child_creation_nonce_sha256[72];
    unsigned char child_plan_digest[32];
    const char *creator_handshake_status;
    int test_fast_exit;
};
struct sf_creator_thread_args_v1 {
    struct creator_result *result; unsigned char creation_nonce[32];
    unsigned char plan_digest[32]; pid_t supervisor_pid;
    char supervisor_start_ticks[32];
};
struct sf_creator_slot_v1 {
    pthread_t pthread; const char *slot_id; uint64_t generation;
    int allocated; int handle_consumed; struct sf_creator_thread_args_v1 thread_args;
};
struct sf_creator_plan_v1 {
    struct creator_result *result; const unsigned char *plan_digest;
    size_t plan_digest_length; const unsigned char *creation_nonce;
    size_t creation_nonce_length; const char *creation_nonce_sha256;
    pid_t supervisor_pid; const char *supervisor_start_ticks;
};
struct sf_creator_started_v1 {
    int pthread_attr_init_rc; int pthread_attr_setdetachstate_rc;
    int pthread_attr_getdetachstate_rc; int pthread_attr_detachstate_readback;
    int pthread_attr_setguardsize_rc; int pthread_attr_setstacksize_rc;
    int pthread_attr_destroy_rc; int pthread_create_rc;
    int create_called; int slot_allocated; const char *failure_phase;
    int pidfd_close_rc; int stat_close_rc; int handshake_reported;
    int handshake_complete; int parent_identity_verified;
    int parent_identity_observed; int creator_cancel_disable_present;
    int creator_signal_mask_present; int creator_tid_present;
    int creator_start_ticks_present; int child_supervisor_pid_present;
    int child_supervisor_start_ticks_present; int child_creation_nonce_present;
    int child_plan_digest_present; int handshake_futex_present;
    int creator_cancel_disable_rc;
    int creator_signal_mask_rc; int handshake_futex_value;
    int handshake_futex_wake_return; int handshake_futex_wait_return;
    int handshake_futex_wait_errno;
    const char *slot_id; uint64_t slot_generation; pid_t creator_tid;
    char creator_start_ticks[32]; char handshake_nonce_sha256[72];
    unsigned char plan_digest[32]; pid_t child_supervisor_pid;
    char child_supervisor_start_ticks[32]; const char *handshake_status;
};
struct sf_join_owner_token_v1 {
    struct sf_creator_slot_v1 *slot; uint64_t generation;
    unsigned char process_nonce[32]; unsigned char owner_token_nonce[32];
    unsigned char mac[32]; int live;
};

static char host_home[8192], host_user[512], host_logname[512], host_runtime[128];
static unsigned char request_key[32], request_key_id[32], plan_commitment[32];
static int request_key_live = 0;
static int payload_events_fd = -1, payload_kill_fd = -1;
static int payload_drained_receipt = 0, cgroup_control_close_receipt = 0;
static unsigned int placement_mask = 0U;
static unsigned int native_event_sequence = 6U;
static volatile sig_atomic_t controller_loss_signal = 0;
static volatile sig_atomic_t revoke_signal = 0;
static int controller_revoke_authorized = 0;
static int proof_fds_closed = 0;
static int creation_proof_identity_captured = 0;
static struct stat controller_pidfd_identity,launcher_proof_identity;
static pid_t controller_identity_pid=0,launcher_identity_tid=0;
static char controller_identity_start_ticks[32],launcher_identity_start_ticks[32];
static const uint64_t creator_slot_generation = 1U;
static char creator_creation_nonce_sha256[72];
static char join_owner_token_sha256[72];
static char capture_preparation_record_sha256[72];
static char return_authorization_record_sha256[72];
static char creator_return_current_record_sha256[72];
static unsigned char supervisor_ephemeral_key[32];
static unsigned char supervisor_process_nonce[32];
static unsigned char creator_creation_nonce[32];
static struct sf_join_owner_token_v1 join_owner_token;
static pthread_mutex_t native_allocation_gate=PTHREAD_MUTEX_INITIALIZER;
static int creator_task_directory_fd=-1;
static int creator_task_identity_fd=-1;
static int creator_capture_writers[5]={-1,-1,-1,-1,-1};
static char creator_task_bytes_sha256[72];
static char creator_boot_id_sha256[72];
static char creator_result_fd_identity_sha256[72];
static char creator_capture_writers_sha256[72];
static unsigned long long creator_capture_prepare_monotonic_ns=0U;
static pid_t join_owner_tid = 0;
static char join_owner_start_ticks[32];
static char creator_positive_sentinel;
static char creator_abort_sentinel;
#ifdef STARTUP_FACTORY_V27_TESTING
static int STARTUP_FACTORY_V27_TEST_ATTR_FAILURE_PHASE=0;
static int STARTUP_FACTORY_V27_TEST_CREATE_FAILURE_RC=0;
static int STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE=0;
#endif
static const unsigned char plan_domain[] = "startup-factory/beads/v27/plan\0";
static const unsigned char evidence_domain[] = "startup-factory/beads/v27/evidence\0";
static const unsigned char result_domain[] = "startup-factory/beads/v27/result\0";
static const unsigned char disposition_domain[] = "startup-factory/beads/v27/disposition\0";
static const unsigned char native_event_domain[] = "startup-factory/beads/v27/native-event\0";
static const unsigned char native_event_evidence_domain[] = "startup-factory/beads/v27/native-event-evidence/v2\0";
static const unsigned char native_event_ack_domain[] = "startup-factory/beads/v27/native-event-ack\0";
static const unsigned char result_offer_domain[] = "startup-factory/beads/v27/worker-result-offer\0";
static const unsigned char result_offer_ack_domain[] = "startup-factory/beads/v27/worker-result-offer-ack\0";
static const unsigned char native_creator_artifact_domain[] =
    "startup-factory/beads/v27/native-creator-artifact/v1\0";
static void die(const char *message);
static void hex_encode(const unsigned char input[32], char output[65]);
static void *sf_beads_creator_thread_main_v1(void *opaque);
static int parse_child_start_time_stat(const char *raw,char output[32]);
static int child_start_time(pid_t child,char output[32]);

static void mark_controller_loss(int signal_number) {
    (void)signal_number;
    controller_loss_signal = 1;
}

static void mark_revoke(int signal_number) {
    (void)signal_number;
    revoke_signal = 1;
}

static void close_creation_proof_fds(int *pidfd_close_rc,int *stat_close_rc){
    *pidfd_close_rc=close(CONTROLLER_PIDFD);
    *stat_close_rc=close(LAUNCHER_PROOF_FD);
    proof_fds_closed=*pidfd_close_rc==0&&*stat_close_rc==0;
}

static int write_all_fd(int fd, const void *value, size_t length) {
    const unsigned char *cursor = value;
    while (length > 0) {
        ssize_t count = write(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return -1;
        cursor += (size_t)count; length -= (size_t)count;
    }
    return 0;
}

static void die(const char *message) {
    if (request_key_live) {
        sfv27_secure_zero(request_key, sizeof(request_key));
        request_key_live = 0;
    }
    (void)write_all_fd(STDERR_FILENO, message, strlen(message));
    (void)write_all_fd(STDERR_FILENO, "\n", 1U); _exit(125);
}

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

static void read_exact(int fd, void *destination, size_t length) {
    unsigned char *cursor = destination;
    while (length > 0) {
        ssize_t count = read(fd, cursor, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) die("V27 sealed input is truncated");
        cursor += (size_t)count; length -= (size_t)count;
    }
}

static void verify_authenticated_plan(void) {
    unsigned char header[76], expected_key_id[32], expected_hmac[32], extra;
    if (pread(PLAN_FD, header, sizeof(header), 0) != (ssize_t)sizeof(header)
        || memcmp(header, "SFV27A1\0", 8U) != 0)
        die("V27 authenticated plan envelope is invalid");
    uint32_t network_length;
    memcpy(&network_length, header + 72U, sizeof(network_length));
    uint32_t payload_length = ntohl(network_length);
    if (payload_length == 0U || payload_length > 1048576U)
        die("V27 authenticated plan payload length is invalid");
    unsigned char *payload = malloc(payload_length);
    if (payload == NULL) die("V27 authenticated plan allocation failed");
    if (pread(PLAN_FD, payload, payload_length, 76) != (ssize_t)payload_length
        || pread(PLAN_FD, &extra, 1U, (off_t)76 + (off_t)payload_length) != 0)
        die("V27 authenticated plan payload is truncated or extended");
    sfv27_sha256(request_key, sizeof(request_key), expected_key_id);
    sfv27_hmac_sha256(
        request_key, plan_domain, sizeof(plan_domain)-1U,
        payload, payload_length, expected_hmac
    );
    memcpy(plan_commitment, header + 40U, sizeof(plan_commitment));
    memcpy(request_key_id, header + 8U, sizeof(request_key_id));
    if (!sfv27_equal(header + 8U, expected_key_id, sizeof(expected_key_id))
        || !sfv27_equal(plan_commitment, expected_hmac, sizeof(expected_hmac)))
        die("V27 authenticated plan HMAC commitment failed");
    sfv27_secure_zero(expected_key_id, sizeof(expected_key_id));
    sfv27_secure_zero(expected_hmac, sizeof(expected_hmac));
    sfv27_secure_zero(payload, payload_length);
    free(payload);
    if (lseek(PLAN_FD, 76, SEEK_SET) != 76)
        die("V27 authenticated plan payload offset changed");
}

static void verify_fd_table(void) {
    for (int fd = 0; fd < SUPERVISOR_EXEC_FD; ++fd)
        if (fcntl(fd, F_GETFD) < 0) die("V27 fixed descriptor table is incomplete");
    errno = 0;
    if (fcntl(SUPERVISOR_EXEC_FD, F_GETFD) >= 0 || errno != EBADF)
        die("V27 pre-exec FD13 did not close across execveat");
    struct stat metadata;
    if (fstat(RESULT_FD, &metadata) != 0 || !S_ISDIR(metadata.st_mode))
        die("V27 result descriptor is not a directory");
    if (fstat(SUPERVISOR_CGROUP_FD, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        fstat(PAYLOAD_CGROUP_FD, &metadata) != 0 || !S_ISDIR(metadata.st_mode))
        die("V27 delegated cgroup descriptors are invalid");
    if (fstat(EVIDENCE_FD, &metadata) != 0 || !S_ISREG(metadata.st_mode))
        die("V27 evidence descriptor is invalid");
    char launcher[256];
    if (pread(LAUNCHER_PROOF_FD, launcher, sizeof(launcher), 0) <= 0)
        die("V27 launcher TID proof is unreadable");
    int seals = fcntl(REQUEST_KEY_FD, F_GET_SEALS);
    int required = F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL;
    unsigned char extra;
    if (seals != required || lseek(REQUEST_KEY_FD,0,SEEK_CUR)!=0
        || pread(REQUEST_KEY_FD, request_key, sizeof(request_key), 0) != 32
        || pread(REQUEST_KEY_FD, &extra, 1U, 32) != 0
        || lseek(REQUEST_KEY_FD,0,SEEK_CUR)!=0)
        die("V27 request key is not an exact sealed 32-byte memfd");
    request_key_live = 1;
    verify_authenticated_plan();
    struct flock lock = {.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=0,.l_pid=0};
    if (fcntl(OPERATION_LOCK_FD, F_OFD_SETLK, &lock) != 0)
        die("V27 shared OFD operation lock is not held");
    struct stat shared_lock_metadata, independent_lock_metadata;
    if (fstat(OPERATION_LOCK_FD, &shared_lock_metadata) != 0 ||
        !S_ISREG(shared_lock_metadata.st_mode))
        die("V27 shared OFD operation lock identity is invalid");
    /* /proc/self/fd entries are kernel magic links. Reopening this fixed
     * descriptor path intentionally follows that one link to obtain a
     * distinct open-file-description; the fstat identity check below binds
     * the result back to the already-custodied FD5 inode. */
    int independent = open("/proc/self/fd/5", O_RDWR | O_CLOEXEC);
    if (independent < 0)
        die("V27 cannot create the independent operation-lock OFD proof");
    if (fstat(independent, &independent_lock_metadata) != 0 ||
        independent_lock_metadata.st_dev != shared_lock_metadata.st_dev ||
        independent_lock_metadata.st_ino != shared_lock_metadata.st_ino ||
        independent_lock_metadata.st_mode != shared_lock_metadata.st_mode ||
        independent_lock_metadata.st_uid != shared_lock_metadata.st_uid ||
        independent_lock_metadata.st_nlink != shared_lock_metadata.st_nlink) {
        close(independent);
        die("V27 independent operation-lock OFD identity changed");
    }
    errno = 0;
    int lock_result = fcntl(independent, F_OFD_SETLK, &lock);
    int lock_errno = errno;
    close(independent);
    if (lock_result == 0 || (lock_errno != EAGAIN && lock_errno != EACCES))
        die("V27 operation lock is not one shared durable OFD");
}

static void verify_selinux_transition(void) {
    char current[512]; int fd = open("/proc/self/attr/current", O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if (fd < 0) die("V27 supervisor cannot read its SELinux context");
    ssize_t length = read(fd, current, sizeof(current)); char extra;
    ssize_t trailing = read(fd, &extra, 1); close(fd);
    size_t expected_current = strlen(STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT);
    if (length < 0 || trailing != 0 || (size_t)length != expected_current ||
        memcmp(current, STARTUP_FACTORY_V27_SUPERVISOR_CONTEXT, expected_current) != 0)
        die("V27 supervisor SELinux transition differs from compiled manifest");
}

static int parse_proc_stat_pid(const char *raw,pid_t *output){
    if(raw==NULL||output==NULL||raw[0]<'1'||raw[0]>'9')return -1;
    errno=0;char *tail=NULL;long value=strtol(raw,&tail,10);
    if(errno!=0||tail==raw||tail==NULL||*tail!=' '||value<=1||value>INT32_MAX)
      return -1;
    *output=(pid_t)value;return 0;
}

static void capture_creation_proof_identities(void){
    char proof[4096];
    ssize_t proof_length=pread(LAUNCHER_PROOF_FD,proof,sizeof(proof)-1U,0);
    if(proof_length<=0||(size_t)proof_length>=sizeof(proof)||
       fstat(CONTROLLER_PIDFD,&controller_pidfd_identity)!=0||
       fstat(LAUNCHER_PROOF_FD,&launcher_proof_identity)!=0)
      die("V27 creation proof identity capture failed");
    proof[proof_length]='\0';
    if(parse_proc_stat_pid(proof,&launcher_identity_tid)!=0||
       parse_child_start_time_stat(proof,launcher_identity_start_ticks)!=0)
      die("V27 launcher proof identity parse failed");
    controller_identity_pid=getppid();
    if(controller_identity_pid<=1||
       child_start_time(controller_identity_pid,controller_identity_start_ticks)!=0)
      die("V27 controller process identity capture failed");
    creation_proof_identity_captured=1;
}

static void verify_controller_liveness(int require_empty_control) {
    if(proof_fds_closed){
        unsigned char byte;errno=0;ssize_t peek=recv(CONTROL_SOCKET_FD,&byte,1U,MSG_PEEK|MSG_DONTWAIT);
        char observed_controller_start[32];
        if(!creation_proof_identity_captured||getppid()!=controller_identity_pid||
           child_start_time(controller_identity_pid,observed_controller_start)!=0||
           strcmp(observed_controller_start,controller_identity_start_ticks)!=0||
           peek!= -1||(errno!=EAGAIN&&errno!=EWOULDBLOCK))
          die("V27 post-ACK controller channel liveness changed");
        (void)require_empty_control;return;
    }
    if(!creation_proof_identity_captured)capture_creation_proof_identities();
    struct stat pidfd_identity,proof_identity;
    struct pollfd controller = {.fd=CONTROLLER_PIDFD,.events=POLLIN};
    if (poll(&controller,1,0) != 0 || controller.revents != 0 ||
        fstat(CONTROLLER_PIDFD,&pidfd_identity)!=0||
        fstat(LAUNCHER_PROOF_FD,&proof_identity)!=0||
        pidfd_identity.st_dev!=controller_pidfd_identity.st_dev||
        pidfd_identity.st_ino!=controller_pidfd_identity.st_ino||
        pidfd_identity.st_mode!=controller_pidfd_identity.st_mode||
        proof_identity.st_dev!=launcher_proof_identity.st_dev||
        proof_identity.st_ino!=launcher_proof_identity.st_ino||
        proof_identity.st_mode!=launcher_proof_identity.st_mode)
        die("V27 controller pidfd became terminal");
    char launcher[4096];
    ssize_t launcher_length = pread(
        LAUNCHER_PROOF_FD, launcher, sizeof(launcher)-1U, 0
    );
    if (launcher_length <= 0 || (size_t)launcher_length >= sizeof(launcher))
        die("V27 launcher proof became unreadable");
    launcher[launcher_length]='\0';pid_t observed_launcher=0;
    char observed_launcher_start[32],observed_controller_start[32];
    if(parse_proc_stat_pid(launcher,&observed_launcher)!=0||
       parse_child_start_time_stat(launcher,observed_launcher_start)!=0||
       observed_launcher!=launcher_identity_tid||
       strcmp(observed_launcher_start,launcher_identity_start_ticks)!=0||
       getppid()!=controller_identity_pid||
       child_start_time(controller_identity_pid,observed_controller_start)!=0||
       strcmp(observed_controller_start,controller_identity_start_ticks)!=0)
      die("V27 controller/launcher process identity changed");
    if (require_empty_control) {
        unsigned char value;
        errno = 0;
        ssize_t count = recv(
            CONTROL_SOCKET_FD, &value, 1U, MSG_PEEK | MSG_DONTWAIT
        );
        if (count != -1 || (errno != EAGAIN && errno != EWOULDBLOCK))
            die("V27 controller channel is EOF, errored, or has an extra packet");
    }
}

static int controller_runtime_live(int timeout_ms) {
    if (controller_loss_signal != 0 || getppid() <= 1) return 0;
    struct pollfd watched[2] = {
        {.fd=CONTROLLER_PIDFD,.events=POLLIN|POLLHUP|POLLERR},
        {.fd=CONTROL_SOCKET_FD,.events=POLLIN|POLLHUP|POLLERR},
    };
    int observed;
    do { observed=poll(watched,2,timeout_ms); } while(observed<0&&errno==EINTR&&controller_loss_signal==0);
    if(observed<0 || controller_loss_signal!=0 || watched[0].revents!=0 || watched[1].revents!=0)return 0;
    unsigned char value;errno=0;ssize_t count=recv(CONTROL_SOCKET_FD,&value,1U,MSG_PEEK|MSG_DONTWAIT);
    return count==-1 && (errno==EAGAIN || errno==EWOULDBLOCK);
}

static char *read_field(int fd) {
    uint32_t network_length; read_exact(fd, &network_length, sizeof(network_length));
    uint32_t length = ntohl(network_length);
    if (length == 0 || length > MAX_FIELD) die("V27 sealed plan field is invalid");
    char *value = calloc((size_t)length+1U, 1U);
    if (value == NULL) die("V27 supervisor allocation failed");
    read_exact(fd, value, length);
    if (memchr(value, '\0', length) != NULL) die("V27 sealed plan contains NUL");
    return value;
}

static struct plan read_plan(void) {
    unsigned char magic[8]; read_exact(PLAN_FD, magic, sizeof(magic));
    if (memcmp(magic, "SFV27P2\0", 8) != 0) die("V27 sealed stage plan magic differs");
    struct plan result={0}; result.operation_id=read_field(PLAN_FD);
    result.effect_plan_sha256=read_field(PLAN_FD); result.stage_plan_sha256=read_field(PLAN_FD);
    result.stage_location=read_field(PLAN_FD); result.stage_key=read_field(PLAN_FD);
    result.stage_kind=read_field(PLAN_FD); result.action_kind=read_field(PLAN_FD);
    result.image=read_field(PLAN_FD); result.repository=read_field(PLAN_FD);
    result.repository_custody_sha256=read_field(PLAN_FD); uint32_t network_argc;
    read_exact(PLAN_FD,&network_argc,sizeof(network_argc)); result.argc=ntohl(network_argc);
    if(result.argc==0 || result.argc>MAX_ARGC) die("V27 sealed plan argc is invalid");
    result.argv=calloc((size_t)result.argc+1U,sizeof(char*));
    if(result.argv==NULL) die("V27 supervisor argv allocation failed");
    for(uint32_t index=0;index<result.argc;++index) result.argv[index]=read_field(PLAN_FD);
    unsigned char extra; if(read(PLAN_FD,&extra,1)!=0) die("V27 sealed plan contains trailing bytes");
    if(strlen(result.operation_id)!=64 || strncmp(result.effect_plan_sha256,"sha256:",7)!=0 ||
       strncmp(result.stage_plan_sha256,"sha256:",7)!=0 ||
       strncmp(result.repository_custody_sha256,"sha256:",7)!=0 ||
       strcmp(result.stage_kind,"payload-terminal")!=0 ||
       strcmp(result.argv[0],"/usr/local/bin/bd")!=0) die("V27 sealed plan identity/executable is invalid");
    return result;
}

static long monotonic_seconds(void) { struct timespec now; if(clock_gettime(CLOCK_MONOTONIC,&now)!=0) die("V27 monotonic clock failed"); return now.tv_sec; }
static int append_bounded(struct bytes *target,const unsigned char *data,size_t length){
    if(length>MAX_OUTPUT-target->length)return -1;
    unsigned char *grown=realloc(target->data,target->length+length+1U);
    if(grown==NULL)return -1;
    target->data=grown; memcpy(target->data+target->length,data,length);
    target->length+=length; target->data[target->length]=0; return 0;
}

static int parse_child_start_time_stat(const char *raw,char output[32]){
    const char *closing=strrchr(raw,')');if(closing==NULL)return -1;
    const char *cursor=closing+1;int field=3;
    while(*cursor!='\0'&&field<=22){
        while(*cursor==' ')cursor++;
        const char *start=cursor;while(*cursor!='\0'&&*cursor!=' '&&*cursor!='\n')cursor++;
        if(field==22){
            size_t count=(size_t)(cursor-start);if(count==0||count>=32U)return -1;
            memcpy(output,start,count);output[count]='\0';
            for(size_t index=0;index<count;++index)if(output[index]<'0'||output[index]>'9')return -1;
            return 0;
        }
        if(cursor==start)return -1;
        field++;
    }
    return -1;
}

static int child_start_time(pid_t child,char output[32]){
    char path[64],raw[4096];int width=snprintf(path,sizeof(path),"/proc/%ld/stat",(long)child);
    if(width<=0||(size_t)width>=sizeof(path))return -1;
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return -1;
    ssize_t length=read(fd,raw,sizeof(raw)-1U);if(close(fd)!=0||length<=0||length==(ssize_t)(sizeof(raw)-1U))return -1;raw[length]='\0';
    return parse_child_start_time_stat(raw,output);
}

static int creator_task_matches(pid_t tid,const char expected_start[32]){
    char observed[32];
    return tid>1&&child_start_time(tid,observed)==0&&strcmp(observed,expected_start)==0;
}

static int creator_task_absent(pid_t tid){
    char path[64];int width=snprintf(path,sizeof(path),"/proc/self/task/%ld/stat",(long)tid);
    if(width<=0||(size_t)width>=sizeof(path))return 0;
    errno=0;int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(fd>=0){(void)close(fd);return 0;}
    return errno==ENOENT;
}

static int wait_creator_task_absent(pid_t tid){
    const struct timespec interval={.tv_sec=0,.tv_nsec=1000000L};
    for(unsigned int attempt=0U;attempt<5000U;++attempt){
      if(creator_task_absent(tid))return 1;
      if(nanosleep(&interval,NULL)!=0&&errno!=EINTR)return 0;
    }
    return creator_task_absent(tid);
}

static void random_exact(unsigned char *destination,size_t length){
    size_t offset=0U;while(offset<length){
      ssize_t count=syscall(SYS_getrandom,destination+offset,length-offset,0U);
      if(count<0&&errno==EINTR)continue;
      if(count<=0)die("V27 supervisor entropy failed");
      offset+=(size_t)count;
    }
}

static void initialize_creator_secrets(void){
    random_exact(supervisor_ephemeral_key,sizeof(supervisor_ephemeral_key));
    random_exact(supervisor_process_nonce,sizeof(supervisor_process_nonce));
    random_exact(creator_creation_nonce,sizeof(creator_creation_nonce));
    unsigned char digest[32];char hex[65];
    sfv27_sha256(creator_creation_nonce,sizeof(creator_creation_nonce),digest);
    hex_encode(digest,hex);
    if(snprintf(creator_creation_nonce_sha256,sizeof(creator_creation_nonce_sha256),"sha256:%s",hex)!=71)
      die("V27 creator creation nonce digest failed");
    sfv27_secure_zero(digest,sizeof(digest));sfv27_secure_zero(hex,sizeof(hex));
}

static void create_join_owner_token(struct sf_creator_slot_v1 *slot){
    static const unsigned char token_domain[]=
      "startup-factory/beads/native-join-owner-token/v1\0";
    if(slot==NULL||!slot->allocated||join_owner_token.live)
      die("V27 join-owner token creation state changed");
    join_owner_token.slot=slot;join_owner_token.generation=slot->generation;
    memcpy(join_owner_token.process_nonce,supervisor_process_nonce,32U);
    random_exact(join_owner_token.owner_token_nonce,32U);
    unsigned char private_body[sizeof(uintptr_t)+sizeof(uint64_t)+64U];
    uintptr_t pointer=(uintptr_t)slot;
    memcpy(private_body,&pointer,sizeof(pointer));
    memcpy(private_body+sizeof(pointer),&slot->generation,sizeof(slot->generation));
    memcpy(private_body+sizeof(pointer)+sizeof(slot->generation),supervisor_process_nonce,32U);
    memcpy(private_body+sizeof(pointer)+sizeof(slot->generation)+32U,join_owner_token.owner_token_nonce,32U);
    sfv27_hmac_sha256(
      supervisor_ephemeral_key,token_domain,sizeof(token_domain)-1U,
      private_body,sizeof(private_body),join_owner_token.mac
    );
    unsigned char durable_body[32U+32U+8U+32U],digest[32];char hex[65];
    static const unsigned char slot_id[32]="payload-terminal-creator";
    memcpy(durable_body,slot_id,32U);
    uint64_t generation=slot->generation;
    for(size_t index=0U;index<8U;++index)
      durable_body[32U+index]=(unsigned char)(generation>>(56U-(8U*index)));
    memcpy(durable_body+40U,supervisor_process_nonce,32U);
    memcpy(durable_body+72U,join_owner_token.owner_token_nonce,32U);
    sfv27_sha256(durable_body,sizeof(durable_body),digest);hex_encode(digest,hex);
    if(snprintf(join_owner_token_sha256,sizeof(join_owner_token_sha256),"sha256:%s",hex)!=71)
      die("V27 join-owner token digest failed");
    join_owner_token.live=1;
    sfv27_secure_zero(private_body,sizeof(private_body));
    sfv27_secure_zero(durable_body,sizeof(durable_body));
    sfv27_secure_zero(digest,sizeof(digest));sfv27_secure_zero(hex,sizeof(hex));
}

static int join_owner_token_valid(const struct sf_creator_slot_v1 *slot){
    static const unsigned char token_domain[]=
      "startup-factory/beads/native-join-owner-token/v1\0";
    if(slot==NULL||!join_owner_token.live||join_owner_token.slot!=slot||
       join_owner_token.generation!=slot->generation||
       !sfv27_equal(join_owner_token.process_nonce,supervisor_process_nonce,32U))
      return 0;
    unsigned char private_body[sizeof(uintptr_t)+sizeof(uint64_t)+64U],expected[32];
    uintptr_t pointer=(uintptr_t)slot;
    memcpy(private_body,&pointer,sizeof(pointer));
    memcpy(private_body+sizeof(pointer),&slot->generation,sizeof(slot->generation));
    memcpy(private_body+sizeof(pointer)+sizeof(slot->generation),supervisor_process_nonce,32U);
    memcpy(private_body+sizeof(pointer)+sizeof(slot->generation)+32U,join_owner_token.owner_token_nonce,32U);
    sfv27_hmac_sha256(supervisor_ephemeral_key,token_domain,sizeof(token_domain)-1U,private_body,sizeof(private_body),expected);
    int valid=sfv27_equal(expected,join_owner_token.mac,sizeof(expected));
    sfv27_secure_zero(private_body,sizeof(private_body));sfv27_secure_zero(expected,sizeof(expected));
    return valid;
}

static void consume_join_owner_token(void){
    join_owner_token.live=0;
    sfv27_secure_zero(&join_owner_token,sizeof(join_owner_token));
    sfv27_secure_zero(supervisor_ephemeral_key,sizeof(supervisor_ephemeral_key));
    sfv27_secure_zero(supervisor_process_nonce,sizeof(supervisor_process_nonce));
    sfv27_secure_zero(creator_creation_nonce,sizeof(creator_creation_nonce));
}

static int creator_attr_failure_v27(int phase){
#ifdef STARTUP_FACTORY_V27_TESTING
    return STARTUP_FACTORY_V27_TEST_ATTR_FAILURE_PHASE==phase?EINVAL:0;
#else
    (void)phase;return 0;
#endif
}

static int creator_handshake_token_v27(const unsigned char nonce[32]){
    unsigned char digest[32];sfv27_sha256(nonce,32U,digest);
    uint32_t raw=((uint32_t)digest[0]<<24)|((uint32_t)digest[1]<<16)|
      ((uint32_t)digest[2]<<8)|(uint32_t)digest[3];
    sfv27_secure_zero(digest,sizeof(digest));
    raw&=0x7fffffffU;return raw==0U?1:(int)raw;
}

static int wait_creator_handshake_v27(
    struct creator_result *result,int expected,int *wait_errno
){
    struct timespec now,deadline;
    if(result==NULL||wait_errno==NULL||expected<=0||
       clock_gettime(CLOCK_MONOTONIC,&deadline)!=0)return -1;
#ifdef STARTUP_FACTORY_V27_TESTING
    deadline.tv_nsec+=100000000L;
    if(deadline.tv_nsec>=1000000000L){deadline.tv_sec++;deadline.tv_nsec-=1000000000L;}
#else
    deadline.tv_sec+=5;
#endif
    for(;;){
      int observed=__atomic_load_n(
        &result->creator_handshake_futex_word,__ATOMIC_ACQUIRE);
      if(observed==expected){*wait_errno=0;return 0;}
      if(observed!=0){*wait_errno=EPROTO;return -1;}
      if(clock_gettime(CLOCK_MONOTONIC,&now)!=0){*wait_errno=errno;return -1;}
      if(now.tv_sec>deadline.tv_sec||
         (now.tv_sec==deadline.tv_sec&&now.tv_nsec>=deadline.tv_nsec)){
        *wait_errno=ETIMEDOUT;return -1;
      }
      struct timespec remaining={
        .tv_sec=deadline.tv_sec-now.tv_sec,
        .tv_nsec=deadline.tv_nsec-now.tv_nsec
      };
      if(remaining.tv_nsec<0){remaining.tv_sec--;remaining.tv_nsec+=1000000000L;}
      errno=0;long waited=syscall(
        SYS_futex,&result->creator_handshake_futex_word,FUTEX_WAIT_PRIVATE,0,
        &remaining,NULL,0);
      if(waited==0||errno==EAGAIN||errno==EINTR)continue;
      if(errno==ETIMEDOUT){*wait_errno=ETIMEDOUT;return -1;}
      *wait_errno=errno;return -1;
    }
}

static int sf_beads_creator_start_v1(
    struct sf_creator_slot_v1 *slot,
    const struct sf_creator_plan_v1 *sealed_plan,
    struct sf_creator_started_v1 *started_out
){
    if(slot==NULL||sealed_plan==NULL||started_out==NULL||sealed_plan->result==NULL||
       ((uintptr_t)slot%_Alignof(struct sf_creator_slot_v1))!=0U||
       ((uintptr_t)sealed_plan%_Alignof(struct sf_creator_plan_v1))!=0U||
       ((uintptr_t)started_out%_Alignof(struct sf_creator_started_v1))!=0U||
       slot->allocated||slot->handle_consumed||slot->generation!=creator_slot_generation||
       slot->slot_id==NULL||strcmp(slot->slot_id,"payload-terminal-creator")!=0||
       sealed_plan->plan_digest==NULL||sealed_plan->plan_digest_length!=32U||
       !sfv27_equal(sealed_plan->plan_digest,plan_commitment,32U)||
       sealed_plan->creation_nonce==NULL||sealed_plan->creation_nonce_length!=32U||
       sealed_plan->creation_nonce_sha256==NULL||sealed_plan->supervisor_pid<=1||
       sealed_plan->supervisor_start_ticks==NULL||
       strcmp(sealed_plan->creation_nonce_sha256,creator_creation_nonce_sha256)!=0)
      return EINVAL;
    const unsigned char *started_bytes=(const unsigned char *)started_out;
    for(size_t index=0U;index<sizeof(*started_out);++index)
      if(started_bytes[index]!=0U)return EINVAL;
    started_out->pthread_attr_init_rc=-1;
    started_out->pthread_attr_setdetachstate_rc=-1;
    started_out->pthread_attr_getdetachstate_rc=-1;
    started_out->pthread_attr_detachstate_readback=-1;
    started_out->pthread_attr_setguardsize_rc=-1;
    started_out->pthread_attr_setstacksize_rc=-1;
    started_out->pthread_attr_destroy_rc=-1;
    started_out->pthread_create_rc=-1;
    started_out->creator_cancel_disable_rc=-1;
    started_out->creator_signal_mask_rc=-1;
    started_out->handshake_futex_value=-1;
    started_out->handshake_futex_wake_return=-1;
    started_out->handshake_futex_wait_return=-1;
    started_out->handshake_futex_wait_errno=0;
    pthread_attr_t attr;int attr_live=0;int rc=creator_attr_failure_v27(1);
    if(rc==0)rc=pthread_attr_init(&attr);
    started_out->pthread_attr_init_rc=rc;
    if(rc!=0){started_out->failure_phase="attr-init";goto no_thread;}
    attr_live=1;
    rc=creator_attr_failure_v27(2);
    if(rc==0)rc=pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_JOINABLE);
    started_out->pthread_attr_setdetachstate_rc=rc;
    if(rc!=0){started_out->failure_phase="attr-setdetach";goto attr_failure;}
    int detachstate=-1;rc=creator_attr_failure_v27(3);
    if(rc==0)rc=pthread_attr_getdetachstate(&attr,&detachstate);
    started_out->pthread_attr_getdetachstate_rc=rc;
    started_out->pthread_attr_detachstate_readback=detachstate;
    if(rc!=0||detachstate!=PTHREAD_CREATE_JOINABLE){
      if(rc==0)rc=EPROTO;
      started_out->failure_phase="attr-getdetach";goto attr_failure;}
    rc=creator_attr_failure_v27(4);
    if(rc==0)rc=pthread_attr_setguardsize(&attr,REGISTERED_CREATOR_GUARD_SIZE);
    started_out->pthread_attr_setguardsize_rc=rc;
    if(rc!=0){started_out->failure_phase="attr-guard";goto attr_failure;}
    rc=creator_attr_failure_v27(5);
    if(rc==0)rc=pthread_attr_setstacksize(&attr,REGISTERED_CREATOR_STACK_SIZE);
    started_out->pthread_attr_setstacksize_rc=rc;
    if(rc!=0){started_out->failure_phase="attr-stack";goto attr_failure;}
    slot->thread_args.result=sealed_plan->result;
    memcpy(slot->thread_args.creation_nonce,sealed_plan->creation_nonce,32U);
    memcpy(slot->thread_args.plan_digest,sealed_plan->plan_digest,32U);
    slot->thread_args.supervisor_pid=sealed_plan->supervisor_pid;
    if(strlen(sealed_plan->supervisor_start_ticks)>=sizeof(slot->thread_args.supervisor_start_ticks)){
      rc=EOVERFLOW;started_out->failure_phase="attr-stack";goto attr_failure;}
    memcpy(slot->thread_args.supervisor_start_ticks,sealed_plan->supervisor_start_ticks,
      strlen(sealed_plan->supervisor_start_ticks)+1U);
    /* Round45 final check is deliberately inside the sole creator API.  No
     * allocation, controller callback, current write, or user code separates
     * its final FD6 peek from pthread_create. */
    verify_controller_liveness(1);
    started_out->create_called=1;
#ifdef STARTUP_FACTORY_V27_TESTING
    if(STARTUP_FACTORY_V27_TEST_CREATE_FAILURE_RC!=0)
      rc=STARTUP_FACTORY_V27_TEST_CREATE_FAILURE_RC;
    else
#endif
    rc=pthread_create(&slot->pthread,&attr,sf_beads_creator_thread_main_v1,&slot->thread_args);
    started_out->pthread_create_rc=rc;
    if(rc==0){slot->allocated=1;started_out->slot_allocated=1;create_join_owner_token(slot);}
    int destroy_fault=creator_attr_failure_v27(6);
    started_out->pthread_attr_destroy_rc=destroy_fault==0?pthread_attr_destroy(&attr):destroy_fault;
    attr_live=0;
    if(rc!=0)started_out->failure_phase="pthread-create";
    else if(started_out->pthread_attr_destroy_rc!=0)started_out->failure_phase="attr-destroy";
    close_creation_proof_fds(&started_out->pidfd_close_rc,&started_out->stat_close_rc);
    if(rc!=0)return started_out->pthread_attr_destroy_rc==0&&proof_fds_closed?rc:EPROTO;
    int expected_handshake=creator_handshake_token_v27(sealed_plan->creation_nonce);
    int wait_errno=0;int wait_rc=wait_creator_handshake_v27(
      sealed_plan->result,expected_handshake,&wait_errno);
    started_out->handshake_futex_wait_return=wait_rc;
    started_out->handshake_futex_wait_errno=wait_errno;
    if(pthread_mutex_lock(&sealed_plan->result->gate_mutex)!=0)return EPROTO;
    started_out->handshake_reported=sealed_plan->result->creator_handshake_reported;
    started_out->handshake_complete=sealed_plan->result->creator_handshake_complete;
    started_out->parent_identity_verified=sealed_plan->result->parent_identity_verified;
    started_out->parent_identity_observed=sealed_plan->result->parent_identity_present;
    started_out->creator_cancel_disable_present=
      sealed_plan->result->creator_cancel_disable_present;
    started_out->creator_signal_mask_present=
      sealed_plan->result->creator_signal_mask_present;
    started_out->creator_tid_present=sealed_plan->result->creator_tid_present;
    started_out->creator_start_ticks_present=
      sealed_plan->result->creator_start_ticks_present;
    started_out->child_supervisor_pid_present=
      sealed_plan->result->child_supervisor_pid_present;
    started_out->child_supervisor_start_ticks_present=
      sealed_plan->result->child_supervisor_start_ticks_present;
    started_out->child_creation_nonce_present=
      sealed_plan->result->child_creation_nonce_present;
    started_out->child_plan_digest_present=
      sealed_plan->result->child_plan_digest_present;
    started_out->handshake_futex_present=
      sealed_plan->result->creator_handshake_futex_present;
    started_out->slot_id=slot->slot_id;
    started_out->slot_generation=slot->generation;
    started_out->creator_tid=sealed_plan->result->creator_tid;
    memcpy(started_out->creator_start_ticks,sealed_plan->result->creator_start_ticks,sizeof(started_out->creator_start_ticks));
    memcpy(started_out->handshake_nonce_sha256,sealed_plan->result->child_creation_nonce_sha256,sizeof(started_out->handshake_nonce_sha256));
    memcpy(started_out->plan_digest,sealed_plan->result->child_plan_digest,sizeof(started_out->plan_digest));
    started_out->child_supervisor_pid=sealed_plan->result->child_supervisor_pid;
    memcpy(started_out->child_supervisor_start_ticks,sealed_plan->result->child_supervisor_start_ticks,sizeof(started_out->child_supervisor_start_ticks));
    started_out->handshake_status=sealed_plan->result->creator_handshake_status;
    started_out->creator_cancel_disable_rc=
      sealed_plan->result->creator_cancel_disable_rc;
    started_out->creator_signal_mask_rc=sealed_plan->result->creator_signal_mask_rc;
    if(started_out->handshake_futex_present){
      started_out->handshake_futex_value=sealed_plan->result->creator_handshake_futex_word;
      started_out->handshake_futex_wake_return=
        sealed_plan->result->creator_handshake_futex_wake_return;
    }
    if(pthread_mutex_unlock(&sealed_plan->result->gate_mutex)!=0)return EPROTO;
    if(wait_rc!=0||!started_out->handshake_reported){
      started_out->failure_phase="creator-handshake-timeout";
      started_out->handshake_status="handshake-timeout";
      return wait_errno==ETIMEDOUT?ETIMEDOUT:EPROTO;
    }
    if(!started_out->handshake_complete&&started_out->failure_phase==NULL)
      started_out->failure_phase="creator-handshake";
    if(!proof_fds_closed||started_out->pthread_attr_destroy_rc!=0||
       !started_out->handshake_complete||!started_out->parent_identity_verified||
       started_out->child_supervisor_pid!=sealed_plan->supervisor_pid||
       strcmp(started_out->child_supervisor_start_ticks,sealed_plan->supervisor_start_ticks)!=0||
       strcmp(started_out->handshake_nonce_sha256,sealed_plan->creation_nonce_sha256)!=0||
       !sfv27_equal(started_out->plan_digest,sealed_plan->plan_digest,32U))return EPROTO;
    return 0;

attr_failure:
    if(attr_live){
      int cleanup_destroy_fault=creator_attr_failure_v27(6);
      started_out->pthread_attr_destroy_rc=cleanup_destroy_fault==0?pthread_attr_destroy(&attr):cleanup_destroy_fault;
      attr_live=0;
      if(started_out->pthread_attr_destroy_rc!=0)rc=EPROTO;
    }
no_thread:
    close_creation_proof_fds(&started_out->pidfd_close_rc,&started_out->stat_close_rc);
    return proof_fds_closed?rc:EPROTO;
}

static int request_controller_placement(pid_t child,int ordinal){
    char start[32],nonce[65],request[192],expected[192];unsigned char material[40];
    if(child_start_time(child,start)!=0)return -1;
    memcpy(material,plan_commitment,32U);uint64_t identity=(uint64_t)child^((uint64_t)(unsigned int)ordinal<<32);for(size_t index=0;index<8U;++index)material[32U+index]=(unsigned char)(identity>>(56U-8U*index));
    unsigned char digest[32];sfv27_hmac_sha256(request_key,plan_domain,sizeof(plan_domain)-1U,material,sizeof(material),digest);hex_encode(digest,nonce);sfv27_secure_zero(digest,sizeof(digest));
    int count=snprintf(request,sizeof(request),"PLACE %ld %s %d %s\n",(long)child,start,ordinal,nonce);
    if(count<=0||(size_t)count>=sizeof(request)||send(CONTROL_SOCKET_FD,request,(size_t)count,MSG_NOSIGNAL)!=count)return -1;
    unsigned char buffer[256],control[CMSG_SPACE(sizeof(struct ucred))];struct iovec iov={.iov_base=buffer,.iov_len=sizeof(buffer)};struct msghdr message={0};message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);ssize_t received;
    do{received=recvmsg(CONTROL_SOCKET_FD,&message,0);}while(received<0&&errno==EINTR&&controller_loss_signal==0);
    int credentials=0;for(struct cmsghdr *item=CMSG_FIRSTHDR(&message);item!=NULL;item=CMSG_NXTHDR(&message,item)){if(item->cmsg_level!=SOL_SOCKET||item->cmsg_type!=SCM_CREDENTIALS||item->cmsg_len!=CMSG_LEN(sizeof(struct ucred)))return -1;struct ucred observed;memcpy(&observed,CMSG_DATA(item),sizeof(observed));if(observed.pid!=getppid()||observed.uid!=geteuid()||observed.gid!=getegid())return -1;credentials++;}
    int expected_length=snprintf(expected,sizeof(expected),"PLACED %ld %d %s\n",(long)child,ordinal,nonce);
    if(received!=expected_length||expected_length<=0||credentials!=1||(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0||memcmp(buffer,expected,(size_t)received)!=0)return -1;
    placement_mask|=1U<<(unsigned int)ordinal;return 0;
}

struct sf_linux_dirent64 {
    uint64_t inode;
    int64_t offset;
    unsigned short record_length;
    unsigned char type;
    char name[];
};

static void sha256_string_v27(
    const unsigned char *value,size_t length,char output[72]
){
    unsigned char digest[32];char hex[65];sfv27_sha256(value,length,digest);
    hex_encode(digest,hex);
    if(snprintf(output,72U,"sha256:%s",hex)!=71)
      die("V27 native artifact digest failed");
    sfv27_secure_zero(digest,sizeof(digest));sfv27_secure_zero(hex,sizeof(hex));
}

static void persist_creator_capture_artifact_v27(
    size_t ordinal,const struct plan *plan,const char *body,size_t length,
    const char *predecessor_kind,const char predecessor_sha256[72],
    const char capture_preparation_sha256[72],
    const char task_set_sha256[72],const char *return_sentinel,
    char output[72]
){
    static const char *const artifact_kinds[5]={
      "NativePostReturnAtomicCaptureV1","CreatorJoinResultV2",
      "CreatorPostReturnObservationV2","CreatorThreadLifetimeReceiptV4",
      "NativeAllocationGateReleaseReceiptV1"
    };
    if(ordinal>=5U||plan==NULL||body==NULL||predecessor_kind==NULL||
       predecessor_sha256==NULL||creator_capture_writers[ordinal]<0||
       length==0U||length>2048U||strlen(predecessor_sha256)!=71U||
       strncmp(predecessor_sha256,"sha256:",7U)!=0||
       capture_preparation_sha256==NULL||task_set_sha256==NULL||
       return_sentinel==NULL||capture_preparation_record_sha256[0]=='\0'||
       return_authorization_record_sha256[0]=='\0'||
       creator_return_current_record_sha256[0]=='\0')
      die("V27 creator capture writer changed");
    char request_key_hex[65];hex_encode(request_key_id,request_key_hex);
    char artifact[4096];int artifact_length=snprintf(
      artifact,sizeof(artifact),
      "{\"artifactKind\":\"%s\",\"capturePreparationRecordSha256\":\"%s\",\"capturePreparationSha256\":\"%s\",\"creationNonceSha256\":\"%s\",\"creatorHandleConsumed\":true,\"creatorReturnCurrentRecordSha256\":\"%s\",\"joinOwnerTokenSha256\":\"%s\",\"operationId\":\"%s\",\"payload\":%.*s,\"predecessorKind\":\"%s\",\"predecessorSha256\":\"%s\",\"requestKeyId\":\"sha256:%s\",\"returnAuthorizationRecordSha256\":\"%s\",\"returnSentinel\":\"%s\",\"schemaVersion\":27,\"sequence\":%zu,\"slotGeneration\":%llu,\"stageLocation\":%s,\"stagePlanSha256\":\"%s\",\"taskSetSha256\":\"%s\"}",
      artifact_kinds[ordinal],capture_preparation_record_sha256,
      capture_preparation_sha256,creator_creation_nonce_sha256,
      creator_return_current_record_sha256,join_owner_token_sha256,
      plan->operation_id,(int)length,body,
      predecessor_kind,predecessor_sha256,request_key_hex,
      return_authorization_record_sha256,return_sentinel,ordinal,
      (unsigned long long)creator_slot_generation,
      plan->stage_location,plan->stage_plan_sha256
      ,task_set_sha256
    );
    if(artifact_length<=0||(size_t)artifact_length>=sizeof(artifact))
      die("V27 creator capture artifact overflow");
    unsigned char artifact_hmac[32];char artifact_hmac_hex[65];
    sfv27_hmac_sha256(
      request_key,native_creator_artifact_domain,
      sizeof(native_creator_artifact_domain)-1U,
      (const unsigned char *)artifact,(size_t)artifact_length,artifact_hmac
    );
    hex_encode(artifact_hmac,artifact_hmac_hex);
    char envelope[4608];int envelope_length=snprintf(
      envelope,sizeof(envelope),
      "{\"artifact\":%s,\"artifactHmac\":\"hmac-sha256:%s\"}\n",
      artifact,artifact_hmac_hex
    );
    if(envelope_length<=0||(size_t)envelope_length>=sizeof(envelope))
      die("V27 creator capture artifact envelope overflow");
    if(write_all_fd(creator_capture_writers[ordinal],envelope,
         (size_t)envelope_length)!=0||
       fsync(creator_capture_writers[ordinal])!=0)
      die("V27 creator capture artifact persistence failed");
    sha256_string_v27(
      (const unsigned char *)envelope,(size_t)envelope_length,output
    );
    sfv27_secure_zero(artifact_hmac,sizeof(artifact_hmac));
    sfv27_secure_zero(artifact_hmac_hex,sizeof(artifact_hmac_hex));
    sfv27_secure_zero(request_key_hex,sizeof(request_key_hex));
}

#ifdef STARTUP_FACTORY_V27_TESTING
static void verify_creator_capture_artifact_bytes_v27(
    const char *name,const char expected_sha256[72]
){
    int descriptor=openat(RESULT_FD,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    struct stat identity;
    if(descriptor<0||fstat(descriptor,&identity)!=0||!S_ISREG(identity.st_mode)||
       identity.st_nlink!=1||identity.st_size<=0||identity.st_size>4096)
      die("V27 creator capture artifact byte identity changed");
    unsigned char bytes[4096];size_t offset=0U;
    while(offset<(size_t)identity.st_size){
      ssize_t count=pread(descriptor,bytes+offset,
        (size_t)identity.st_size-offset,(off_t)offset);
      if(count<0&&errno==EINTR)continue;
      if(count<=0)die("V27 creator capture artifact byte read failed");
      offset+=(size_t)count;
    }
    char observed_sha256[72];sha256_string_v27(bytes,offset,observed_sha256);
    if(close(descriptor)!=0||strcmp(observed_sha256,expected_sha256)!=0)
      die("V27 creator capture artifact byte digest changed");
    sfv27_secure_zero(bytes,sizeof(bytes));
    sfv27_secure_zero(observed_sha256,sizeof(observed_sha256));
}
#endif

static void prepare_post_return_capture(pid_t creator_tid,char output[72]){
    if(creator_task_directory_fd>=0||pthread_mutex_lock(&native_allocation_gate)!=0)
      die("V27 NativeAllocationGateV1 acquisition failed");
    int opened=open("/proc/self/task",O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(opened<0)die("V27 post-return task directory open failed");
    creator_task_directory_fd=fcntl(opened,F_DUPFD_CLOEXEC,32);
    int duplicate_errno=errno;
    if(close(opened)!=0||creator_task_directory_fd<32){errno=duplicate_errno;die("V27 post-return task directory reservation failed");}
    struct stat identity;struct statfs filesystem;
    if(fstat(creator_task_directory_fd,&identity)!=0||
       syscall(SYS_fstatfs,creator_task_directory_fd,&filesystem)!=0||
       !S_ISDIR(identity.st_mode)||filesystem.f_type!=PROC_SUPER_MAGIC)
      die("V27 post-return task directory identity changed");
    char creator_name[32];if(creator_tid<=1||snprintf(creator_name,sizeof(creator_name),"%ld",(long)creator_tid)<=0)
      die("V27 creator task identity name failed");
    /* Reserve the exact creator task before its return barrier can move. */
    int owner_dir=openat(creator_task_directory_fd,creator_name,
      O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(owner_dir<0)die("V27 creator task directory reservation failed");
    creator_task_identity_fd=openat(owner_dir,"stat",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    if(close(owner_dir)!=0||creator_task_identity_fd<0)
      die("V27 creator task stat reservation failed");
    unsigned char task_bytes[4096];ssize_t task_length=pread(
      creator_task_identity_fd,task_bytes,sizeof(task_bytes),0);
    if(task_length<=0||(size_t)task_length==sizeof(task_bytes))
      die("V27 creator task bytes are invalid");
    sha256_string_v27(task_bytes,(size_t)task_length,creator_task_bytes_sha256);
    int boot=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    unsigned char boot_bytes[128];ssize_t boot_length=boot<0?-1:read(boot,boot_bytes,sizeof(boot_bytes));
    if(boot<0||boot_length<=0||(size_t)boot_length==sizeof(boot_bytes)||close(boot)!=0)
      die("V27 boot identity capture failed");
    sha256_string_v27(boot_bytes,(size_t)boot_length,creator_boot_id_sha256);
    struct stat result_identity;if(fstat(RESULT_FD,&result_identity)!=0||
      !S_ISDIR(result_identity.st_mode))die("V27 result directory identity changed");
    char result_body[256];int result_length=snprintf(result_body,sizeof(result_body),
      "{\"device\":%llu,\"gid\":%lu,\"inode\":%llu,\"mode\":%u,\"uid\":%lu}",
      (unsigned long long)result_identity.st_dev,(unsigned long)result_identity.st_gid,
      (unsigned long long)result_identity.st_ino,(unsigned int)(result_identity.st_mode&07777U),
      (unsigned long)result_identity.st_uid);
    if(result_length<=0||(size_t)result_length>=sizeof(result_body))
      die("V27 result identity capture overflow");
    sha256_string_v27((const unsigned char *)result_body,(size_t)result_length,
      creator_result_fd_identity_sha256);
    static const char *const writer_names[5]={
      ".native-creator-atomic-capture.v1",
      ".native-creator-join-result.v2",
      ".native-creator-post-return.v2",
      ".native-creator-lifetime.v4",
      ".native-allocation-gate-release.v1"
    };
    char writer_body[1024];size_t writer_offset=0U;
    for(size_t index=0U;index<5U;++index){
      int opened_writer=openat(RESULT_FD,writer_names[index],
        O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
      if(opened_writer<0)die("V27 creator capture writer reservation failed");
      creator_capture_writers[index]=fcntl(opened_writer,F_DUPFD_CLOEXEC,32);
      int writer_duplicate_errno=errno;
      if(close(opened_writer)!=0||creator_capture_writers[index]<32){
        errno=writer_duplicate_errno;
        die("V27 creator capture writer high-FD reservation failed");
      }
      struct stat writer;if(
         fstat(creator_capture_writers[index],&writer)!=0||!S_ISREG(writer.st_mode)||
         writer.st_nlink!=1||writer.st_size!=0)
        die("V27 creator capture writer reservation failed");
      int wrote=snprintf(writer_body+writer_offset,sizeof(writer_body)-writer_offset,
        "%zu:%llu:%llu:%u;",index,(unsigned long long)writer.st_dev,
        (unsigned long long)writer.st_ino,(unsigned int)(writer.st_mode&07777U));
      if(wrote<=0||(size_t)wrote>=sizeof(writer_body)-writer_offset)
        die("V27 creator capture writer identity overflow");
      writer_offset+=(size_t)wrote;
    }
    if(fsync(RESULT_FD)!=0)die("V27 creator capture writer directory fsync failed");
    sha256_string_v27((const unsigned char *)writer_body,writer_offset,
      creator_capture_writers_sha256);
    struct timespec monotonic;if(clock_gettime(CLOCK_MONOTONIC,&monotonic)!=0||
      monotonic.tv_sec<0||monotonic.tv_nsec<0)
      die("V27 capture preparation monotonic clock failed");
    creator_capture_prepare_monotonic_ns=
      (unsigned long long)monotonic.tv_sec*1000000000ULL+
      (unsigned long long)monotonic.tv_nsec;
    char body[1024];int length=snprintf(body,sizeof(body),
      "{\"allocationGate\":\"exclusive\",\"bootIdSha256\":\"%s\",\"capturePrepareMonotonicNs\":%llu,\"captureWritersSha256\":\"%s\",\"creatorTaskBytesSha256\":\"%s\",\"creatorTaskDirectory\":{\"device\":%llu,\"fd\":%d,\"inode\":%llu,\"mode\":%u},\"joinOwnerTid\":%ld,\"proofFd11Expected\":\"closed\",\"proofFd7Expected\":\"closed\",\"resultFdIdentitySha256\":\"%s\"}",
      creator_boot_id_sha256,creator_capture_prepare_monotonic_ns,
      creator_capture_writers_sha256,creator_task_bytes_sha256,
      (unsigned long long)identity.st_dev,creator_task_directory_fd,
      (unsigned long long)identity.st_ino,(unsigned int)(identity.st_mode&07777U),
      (long)join_owner_tid,creator_result_fd_identity_sha256);
    if(length<=0||(size_t)length>=sizeof(body))die("V27 post-return capture preparation overflow");
    unsigned char digest[32];char hex[65];sfv27_sha256((const unsigned char *)body,(size_t)length,digest);hex_encode(digest,hex);
    if(snprintf(output,72U,"sha256:%s",hex)!=71)die("V27 post-return capture preparation digest failed");
    sfv27_secure_zero(digest,sizeof(digest));sfv27_secure_zero(hex,sizeof(hex));
}

static void capture_post_return_task_set(
    pid_t creator_tid,char task_set_sha256[72],int *fd7_errno,int *fd11_errno
){
    if(creator_task_directory_fd<32||fd7_errno==NULL||fd11_errno==NULL)
      die("V27 post-return capture was not prepared");
    struct stat before,after;struct statfs filesystem;
    if(fstat(creator_task_directory_fd,&before)!=0||
       syscall(SYS_fstatfs,creator_task_directory_fd,&filesystem)!=0||
       filesystem.f_type!=PROC_SUPER_MAGIC||lseek(creator_task_directory_fd,0,SEEK_SET)!=0)
      die("V27 post-return task directory rebound");
    struct sfv27_sha256_ctx context;sfv27_sha256_init(&context);
    unsigned char buffer[8192];int main_seen=0,creator_seen=0;
    for(;;){
      long count=syscall(SYS_getdents64,creator_task_directory_fd,buffer,sizeof(buffer));
      if(count<0&&errno==EINTR)continue;
      if(count<0)die("V27 post-return task enumeration failed");
      if(count==0)break;
      sfv27_sha256_update(&context,buffer,(size_t)count);
      long offset=0;while(offset<count){
        struct sf_linux_dirent64 *entry=(struct sf_linux_dirent64 *)(buffer+offset);
        if(entry->record_length<offsetof(struct sf_linux_dirent64,name)+2U||
           offset+entry->record_length>count)
          die("V27 post-return task entry framing changed");
        if(!((entry->name[0]=='.'&&entry->name[1]=='\0')||
             (entry->name[0]=='.'&&entry->name[1]=='.'&&entry->name[2]=='\0'))){
          errno=0;char *tail=NULL;long tid=strtol(entry->name,&tail,10);
          if(errno!=0||tail==entry->name||*tail!='\0'||tid<=1)
            die("V27 post-return task entry name changed");
          if(tid==(long)join_owner_tid)main_seen++;
          if(tid==(long)creator_tid)creator_seen++;
        }
        offset+=entry->record_length;
      }
    }
    if(fstat(creator_task_directory_fd,&after)!=0||
       before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||
       before.st_mode!=after.st_mode||main_seen!=1||creator_seen!=0)
      die("V27 post-return task-set proof changed");
    unsigned char digest[32];char hex[65];sfv27_sha256_final(&context,digest);hex_encode(digest,hex);
    if(snprintf(task_set_sha256,72U,"sha256:%s",hex)!=71)
      die("V27 post-return task-set digest failed");
    errno=0;int fd7_result=fcntl(CONTROLLER_PIDFD,F_GETFD);*fd7_errno=errno;
    errno=0;int fd11_result=fcntl(LAUNCHER_PROOF_FD,F_GETFD);*fd11_errno=errno;
    if(fd7_result!=-1||*fd7_errno!=EBADF||fd11_result!=-1||*fd11_errno!=EBADF)
      die("V27 closed creator proof descriptor was reused");
    sfv27_secure_zero(digest,sizeof(digest));sfv27_secure_zero(hex,sizeof(hex));
}

struct sf_post_return_artifacts_v1 {
    char atomic_capture_sha256[72]; char join_result_sha256[72];
    char post_return_observation_sha256[72]; char lifetime_sha256[72];
    char gate_release_receipt_sha256[72]; char task_set_sha256[72];
    int fd7_getfd_errno; int fd11_getfd_errno;
    unsigned long long capture_monotonic_ns; unsigned long long release_monotonic_ns;
};

static void persist_post_return_artifacts_while_held_v27(
    const struct creator_result *result,int pthread_join_rc,
    const char *return_sentinel,const char capture_preparation_sha256[72],
    struct sf_post_return_artifacts_v1 *artifacts
){
    if(result==NULL||artifacts==NULL||pthread_join_rc!=0||
       return_sentinel==NULL||creator_task_directory_fd<32)
      die("V27 post-return artifact inputs changed");
    capture_post_return_task_set(
      result->creator_tid,artifacts->task_set_sha256,
      &artifacts->fd7_getfd_errno,&artifacts->fd11_getfd_errno);
    struct timespec monotonic;if(clock_gettime(CLOCK_MONOTONIC,&monotonic)!=0||
      monotonic.tv_sec<0||monotonic.tv_nsec<0)
      die("V27 atomic capture monotonic clock failed");
    artifacts->capture_monotonic_ns=
      (unsigned long long)monotonic.tv_sec*1000000000ULL+
      (unsigned long long)monotonic.tv_nsec;
    if(artifacts->capture_monotonic_ns<creator_capture_prepare_monotonic_ns)
      die("V27 atomic capture monotonic order changed");
    char atomic_body[2048];int atomic_length=snprintf(atomic_body,sizeof(atomic_body),
      "{\"allocationGateHeld\":true,\"bootIdSha256\":\"%s\",\"captureMonotonicNs\":%llu,\"capturePreparationSha256\":\"%s\",\"capturePrepareMonotonicNs\":%llu,\"captureWritersSha256\":\"%s\",\"creatorStartTicks\":\"%s\",\"creatorTaskBytesSha256\":\"%s\",\"creatorTid\":%ld,\"fd11GetfdErrno\":%d,\"fd7GetfdErrno\":%d,\"joinOwnerTokenSha256\":\"%s\",\"pthreadJoinRc\":%d,\"resultFdIdentitySha256\":\"%s\",\"returnSentinel\":\"%s\",\"slotGeneration\":%llu,\"taskSetSha256\":\"%s\"}",
      creator_boot_id_sha256,artifacts->capture_monotonic_ns,
      capture_preparation_sha256,creator_capture_prepare_monotonic_ns,
      creator_capture_writers_sha256,result->creator_start_ticks,
      creator_task_bytes_sha256,(long)result->creator_tid,
      artifacts->fd11_getfd_errno,artifacts->fd7_getfd_errno,
      join_owner_token_sha256,pthread_join_rc,creator_result_fd_identity_sha256,
      return_sentinel,(unsigned long long)creator_slot_generation,
      artifacts->task_set_sha256);
    if(atomic_length<=0||(size_t)atomic_length>=sizeof(atomic_body))
      die("V27 atomic capture body overflow");
    persist_creator_capture_artifact_v27(
      0U,result->plan,atomic_body,(size_t)atomic_length,
      "NativePostReturnCapturePreparationV1",capture_preparation_record_sha256,
      capture_preparation_sha256,artifacts->task_set_sha256,return_sentinel,
      artifacts->atomic_capture_sha256
    );
    char join_body[1024];int join_length=snprintf(join_body,sizeof(join_body),
      "{\"atomicCaptureSha256\":\"%s\",\"creatorHandleConsumed\":true,\"joinOwnerTokenSha256\":\"%s\",\"pthreadJoinCount\":1,\"pthreadJoinRc\":%d,\"returnSentinel\":\"%s\",\"slotGeneration\":%llu}",
      artifacts->atomic_capture_sha256,join_owner_token_sha256,pthread_join_rc,
      return_sentinel,(unsigned long long)creator_slot_generation);
    if(join_length<=0||(size_t)join_length>=sizeof(join_body))
      die("V27 join result body overflow");
    persist_creator_capture_artifact_v27(
      1U,result->plan,join_body,(size_t)join_length,
      "NativePostReturnAtomicCaptureV1",artifacts->atomic_capture_sha256,
      capture_preparation_sha256,artifacts->task_set_sha256,return_sentinel,
      artifacts->join_result_sha256
    );
    char post_body[1024];int post_length=snprintf(post_body,sizeof(post_body),
      "{\"atomicCaptureSha256\":\"%s\",\"capturePreparationSha256\":\"%s\",\"creatorHandleConsumed\":true,\"joinResultSha256\":\"%s\",\"taskSetSha256\":\"%s\"}",
      artifacts->atomic_capture_sha256,capture_preparation_sha256,
      artifacts->join_result_sha256,artifacts->task_set_sha256);
    if(post_length<=0||(size_t)post_length>=sizeof(post_body))
      die("V27 post-return observation body overflow");
    persist_creator_capture_artifact_v27(
      2U,result->plan,post_body,(size_t)post_length,
      "CreatorJoinResultV2",artifacts->join_result_sha256,
      capture_preparation_sha256,artifacts->task_set_sha256,return_sentinel,
      artifacts->post_return_observation_sha256
    );
    char lifetime_body[1024];int lifetime_length=snprintf(
      lifetime_body,sizeof(lifetime_body),
      "{\"allocationGateHeld\":true,\"atomicCaptureSha256\":\"%s\",\"creatorHandleConsumed\":true,\"creatorTaskAbsent\":true,\"joinResultSha256\":\"%s\",\"postReturnObservationSha256\":\"%s\",\"proofFd11Closed\":true,\"proofFd7Closed\":true,\"pthreadJoinRc\":%d,\"returnSentinel\":\"%s\"}",
      artifacts->atomic_capture_sha256,artifacts->join_result_sha256,
      artifacts->post_return_observation_sha256,pthread_join_rc,return_sentinel);
    if(lifetime_length<=0||(size_t)lifetime_length>=sizeof(lifetime_body))
      die("V27 creator lifetime body overflow");
    persist_creator_capture_artifact_v27(
      3U,result->plan,lifetime_body,(size_t)lifetime_length,
      "CreatorPostReturnObservationV2",
      artifacts->post_return_observation_sha256,capture_preparation_sha256,
      artifacts->task_set_sha256,return_sentinel,artifacts->lifetime_sha256
    );
    if(fsync(RESULT_FD)!=0)die("V27 held creator artifacts directory fsync failed");
}

static void persist_allocation_gate_release_receipt_v27(
    const struct plan *plan,struct sf_post_return_artifacts_v1 *artifacts,
    const char capture_preparation_sha256[72],const char *return_sentinel
){
    struct timespec monotonic;if(clock_gettime(CLOCK_MONOTONIC,&monotonic)!=0||
      monotonic.tv_sec<0||monotonic.tv_nsec<0)
      die("V27 allocation-gate release monotonic clock failed");
    artifacts->release_monotonic_ns=
      (unsigned long long)monotonic.tv_sec*1000000000ULL+
      (unsigned long long)monotonic.tv_nsec;
    if(artifacts->release_monotonic_ns<artifacts->capture_monotonic_ns)
      die("V27 allocation-gate release order changed");
    char body[512];int length=snprintf(body,sizeof(body),
      "{\"allocationGateHeld\":false,\"allocationGateReleaseCount\":1,\"lifetimeSha256\":\"%s\",\"releaseMonotonicNs\":%llu}",
      artifacts->lifetime_sha256,artifacts->release_monotonic_ns);
    if(length<=0||(size_t)length>=sizeof(body))
      die("V27 allocation-gate release receipt overflow");
    persist_creator_capture_artifact_v27(
      4U,plan,body,(size_t)length,"CreatorThreadLifetimeReceiptV4",
      artifacts->lifetime_sha256,capture_preparation_sha256,
      artifacts->task_set_sha256,return_sentinel,
      artifacts->gate_release_receipt_sha256
    );
    for(size_t index=0U;index<5U;++index){
      if(close(creator_capture_writers[index])!=0)
        die("V27 creator capture writer close failed");
      creator_capture_writers[index]=-1;
    }
    if(fsync(RESULT_FD)!=0)
      die("V27 allocation-gate release receipt directory fsync failed");
}

static void release_post_return_capture(void){
    if(creator_task_directory_fd<32||creator_task_identity_fd<0||
       close(creator_task_identity_fd)!=0||close(creator_task_directory_fd)!=0)
      die("V27 post-return task directory close failed");
    creator_task_directory_fd=-1;creator_task_identity_fd=-1;
    if(pthread_mutex_unlock(&native_allocation_gate)!=0)
      die("V27 NativeAllocationGateV1 release failed");
}

static int child_fd_name_is(const char *name, char expected) {
    return name[0] == expected && name[1] == '\0';
}

static void child_close_inherited_fds(int release_read, int capture, int stdout_write, int stderr_write) {
    if (setpgid(0, 0) != 0) _exit(126);
    if (capture) {
        if (dup2(stdout_write, STDOUT_FILENO) < 0 || dup2(stderr_write, STDERR_FILENO) < 0)
            _exit(126);
    } else {
        int nullfd = open("/dev/null", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (nullfd < 0 || dup2(nullfd, STDOUT_FILENO) < 0 || dup2(nullfd, STDERR_FILENO) < 0)
            _exit(126);
    }
    if (syscall(SYS_dup3, release_read, 3, O_CLOEXEC) < 0)
        _exit(126);
    if (syscall(SYS_close_range, 4U, ~0U, 0U) < 0)
        _exit(126);
}

static void child_require_stdio_only(void) {
    int directory = open("/proc/self/fd", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory != 3) _exit(126);
    struct statfs filesystem;
    if (syscall(SYS_fstatfs, directory, &filesystem) != 0 || filesystem.f_type != PROC_SUPER_MAGIC)
        _exit(126);
    unsigned char buffer[4096];
    int seen[4] = {0, 0, 0, 0};
    for (;;) {
        long length = syscall(SYS_getdents64, directory, buffer, sizeof(buffer));
        if (length < 0) {
            if (errno == EINTR) continue;
            _exit(126);
        }
        if (length == 0) break;
        long at = 0;
        while (at < length) {
            struct sf_linux_dirent64 *entry = (struct sf_linux_dirent64 *)(buffer + at);
            if (entry->record_length < offsetof(struct sf_linux_dirent64, name) + 2U || at + entry->record_length > length)
                _exit(126);
            if ((entry->name[0] == '.' && entry->name[1] == '\0') ||
                (entry->name[0] == '.' && entry->name[1] == '.' && entry->name[2] == '\0')) {
                at += entry->record_length;
                continue;
            }
            int index = -1;
            for (int candidate = 0; candidate <= 3; ++candidate)
                if (child_fd_name_is(entry->name, (char)('0' + candidate))) index = candidate;
            if (index < 0 || seen[index]) _exit(126);
            seen[index] = 1;
            at += entry->record_length;
        }
    }
    if (!seen[0] || !seen[1] || !seen[2] || !seen[3] || close(directory) != 0)
        _exit(126);
}

static int run_argv(char *const argv[],int capture,int ordinal,struct bytes *out,struct bytes *err){
    int stdout_pipe[2]={-1,-1},stderr_pipe[2]={-1,-1},release_pipe[2]={-1,-1};
    if(!controller_runtime_live(0))return 123;
    if(pipe2(release_pipe,O_CLOEXEC)!=0||
      (capture && (pipe2(stdout_pipe,O_CLOEXEC|O_NONBLOCK)!=0 || pipe2(stderr_pipe,O_CLOEXEC|O_NONBLOCK)!=0)))return 125;
    pid_t child=fork(); if(child<0)return 125;
    if(child==0){child_close_inherited_fds(release_pipe[0],capture,stdout_pipe[1],stderr_pipe[1]);char release;ssize_t released;do{released=read(3,&release,1U);}while(released<0&&errno==EINTR);if(released!=1||release!='R'||close(3)!=0)_exit(126);child_require_stdio_only();
      char *const environment[]={host_home,"LANG=C","LC_ALL=C",host_logname,"PATH=/usr/bin:/bin",host_runtime,host_user,NULL};
      execve(PODMAN,argv,environment);_exit(127);}
    close(release_pipe[0]);(void)setpgid(child,child);if(request_controller_placement(child,ordinal)!=0||write_all_fd(release_pipe[1],"R",1U)!=0){close(release_pipe[1]);(void)kill(-child,SIGKILL);(void)waitpid(child,NULL,0);return 125;}close(release_pipe[1]);
    if(capture){close(stdout_pipe[1]);close(stderr_pipe[1]);} long deadline=monotonic_seconds()+STAGE_TIMEOUT_SECONDS;int status=0,finished=0;
    while(!finished){if(capture){struct pollfd descriptors[2]={ {.fd=stdout_pipe[0],.events=POLLIN},{.fd=stderr_pipe[0],.events=POLLIN} };
      (void)poll(descriptors,2,50);unsigned char block[8192];for(int index=0;index<2;++index)for(;;){ssize_t count=read(descriptors[index].fd,block,sizeof(block));
        if(count>0){if(append_bounded(index==0?out:err,block,(size_t)count)!=0){(void)kill(-child,SIGKILL);(void)waitpid(child,&status,0);return 125;}}
        else if(count<0&&errno==EINTR)continue;else break;}}
      else if(!controller_runtime_live(50)){(void)kill(-child,SIGKILL);(void)waitpid(child,&status,0);return 123;}
      if(!controller_runtime_live(0)){(void)kill(-child,SIGKILL);(void)waitpid(child,&status,0);if(capture){close(stdout_pipe[0]);close(stderr_pipe[0]);}return 123;}
      pid_t waited=waitpid(child,&status,WNOHANG);if(waited==child)finished=1;else if(waited<0&&errno!=EINTR)return 125;
      else if(monotonic_seconds()>=deadline){(void)kill(-child,SIGKILL);(void)waitpid(child,&status,0);return 124;}}
    if(capture){unsigned char block[8192];for(int index=0;index<2;++index){int fd=index==0?stdout_pipe[0]:stderr_pipe[0];for(;;){ssize_t count=read(fd,block,sizeof(block));
      if(count>0){if(append_bounded(index==0?out:err,block,(size_t)count)!=0)return 125;}else if(count<0&&errno==EINTR)continue;else break;}close(fd);}}
    if(WIFEXITED(status))return WEXITSTATUS(status);
    if(WIFSIGNALED(status))return 128+WTERMSIG(status);
    return 125;
}

static void drain_payload_cgroup(void){
    if(payload_kill_fd<0||write_all_fd(payload_kill_fd,"1\n",2U)!=0)die("V27 cgroup.kill failed");
    long deadline=monotonic_seconds()+5;while(monotonic_seconds()<=deadline){char events[256];
      ssize_t count=pread(payload_events_fd,events,sizeof(events),0);
      if(count>0&&memmem(events,(size_t)count,"populated 0\n",12U)!=NULL){payload_drained_receipt=1;return;}
      usleep(20000);}die("V27 recursive payload cgroup remained populated");
}

static void close_payload_cgroup_controls(void){
    if(payload_events_fd<0||payload_kill_fd<0)die("V27 cgroup control close receipt is incomplete");
    if(close(payload_events_fd)!=0||close(payload_kill_fd)!=0)die("V27 cgroup control close receipt failed");
    payload_events_fd=payload_kill_fd=-1;
    cgroup_control_close_receipt=1;
}

static int lifecycle(struct plan *plan,const char *suffix,int readonly,char *const command[],struct bytes *out,struct bytes *err){
    char container[64],mount[8192];if(snprintf(container,sizeof(container),"sf-v27-%.32s-%s",plan->operation_id,suffix)>=(int)sizeof(container)||
      snprintf(mount,sizeof(mount),"type=bind,src=%s,dst=/workspace,%s",plan->repository,readonly?"ro":"rw")>=(int)sizeof(mount))return 125;
    char *create[96];size_t at=0;create[at++]=PODMAN;create[at++]="create";create[at++]="--name";create[at++]=container;
    create[at++]="--pull";create[at++]="never";create[at++]="--network";create[at++]="none";create[at++]="--cgroups";create[at++]="split";
    create[at++]="--runtime";create[at++]=OCI_RUNTIME;
    create[at++]="--read-only";create[at++]="--userns";create[at++]="keep-id";create[at++]="--security-opt";create[at++]="no-new-privileges";
    create[at++]="--security-opt";create[at++]="label=type:startup_factory_beads_payload_t";create[at++]="--cap-drop";create[at++]="all";create[at++]="--pids-limit";create[at++]="64";
    create[at++]="--memory";create[at++]="536870912";create[at++]="--cpus";create[at++]="1";create[at++]="--env";create[at++]="BD_JSON_ENVELOPE=1";create[at++]="--env";create[at++]="HOME=/run/startup-factory/home";
    create[at++]="--env";create[at++]="LANG=C";create[at++]="--env";create[at++]="LC_ALL=C";create[at++]="--env";create[at++]="PATH=/usr/local/bin:/usr/bin:/bin";
    create[at++]="--tmpfs";create[at++]="/run/startup-factory/home:rw,nodev,nosuid,noexec,mode=0700";create[at++]="--mount";create[at++]=mount;
    create[at++]="--workdir";create[at++]="/workspace";create[at++]=plan->image;
    for(size_t index=0;command[index]!=NULL;++index){if(at+1U>=sizeof(create)/sizeof(create[0]))return 125;create[at++]=command[index];}create[at]=NULL;
    char *init[]={PODMAN,"init",container,NULL},*start[]={PODMAN,"start","--attach",container,NULL},*terminal[]={PODMAN,"wait",container,NULL};
    char *cleanup[]={PODMAN,"container","cleanup",container,NULL},*remove[]={PODMAN,"rm","--force",container,NULL};
    int infrastructure=run_argv(create,0,0,out,err);if(infrastructure==123)return 123;if(infrastructure==0)infrastructure=run_argv(init,0,1,out,err);if(infrastructure==123)return 123;int effect=infrastructure;
    if(infrastructure==0)effect=run_argv(start,1,2,out,err);
    if(effect==123)return 123;
    if(infrastructure==0&&effect!=124)infrastructure=run_argv(terminal,0,3,out,err);
    if(infrastructure==123)return 123;
    int cleaned=run_argv(cleanup,0,4,out,err),removed=run_argv(remove,0,5,out,err);if(infrastructure!=0||cleaned!=0||removed!=0)return 125;return effect;
}

static void *sf_beads_creator_thread_main_v1(void *opaque){
    const struct sf_creator_thread_args_v1 *arguments=opaque;
    if(arguments==NULL||arguments->result==NULL)return &creator_abort_sentinel;
    struct sf_creator_thread_args_v1 sealed=*arguments;
    struct creator_result *result=sealed.result;
    const char *status="valid";int old_cancel_state=-1;
    int cancel_present=1,signal_present=0,tid_present=0,start_present=0;
    int supervisor_pid_present=0,supervisor_start_present=0;
    int parent_present=0,nonce_present=0,plan_present=0;
    int cancel_rc=pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&old_cancel_state);
#ifdef STARTUP_FACTORY_V27_TESTING
    if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==1)cancel_rc=EINVAL;
#endif
    int signal_rc=-1;sigset_t blocked;
    if(cancel_rc!=0)status="cancellation-disable-failed";
    else {
      signal_present=1;
      if(sigemptyset(&blocked)!=0||sigaddset(&blocked,SIGTERM)!=0||
         sigaddset(&blocked,SIGUSR1)!=0)signal_rc=EINVAL;
      else signal_rc=pthread_sigmask(SIG_BLOCK,&blocked,NULL);
#ifdef STARTUP_FACTORY_V27_TESTING
      if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==2)signal_rc=EINVAL;
#endif
      if(signal_rc!=0)status="signal-mask-failed";
    }
    pid_t creator_tid=0,supervisor_pid=0;char creator_start[32]={0};
    char supervisor_start[32]={0},nonce_sha256[72]={0};
    unsigned char child_plan[32]={0};int parent_verified=0;
    if(cancel_rc==0&&signal_rc==0){
      creator_tid=(pid_t)syscall(SYS_gettid);
#ifdef STARTUP_FACTORY_V27_TESTING
      if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==7)creator_tid=0;
#endif
      if(creator_tid<=1)status="creator-tid-invalid";
      else {
        tid_present=1;
#ifdef STARTUP_FACTORY_V27_TESTING
        if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==8)
          status="creator-start-unreadable";
        else
#endif
        if(child_start_time(creator_tid,creator_start)!=0)
          status="creator-start-unreadable";
        else start_present=1;
      }
      if(strcmp(status,"valid")==0){
        supervisor_pid=getpid();
        if(supervisor_pid<=1)status="supervisor-start-unreadable";
        else {
          supervisor_pid_present=1;
#ifdef STARTUP_FACTORY_V27_TESTING
          if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==9)
            status="supervisor-start-unreadable";
          else
#endif
          if(child_start_time(supervisor_pid,supervisor_start)!=0)
            status="supervisor-start-unreadable";
          else supervisor_start_present=1;
        }
      }
      if(strcmp(status,"valid")==0){
        parent_present=1;
        parent_verified=supervisor_pid==sealed.supervisor_pid&&
          strcmp(supervisor_start,sealed.supervisor_start_ticks)==0&&
          getppid()==controller_identity_pid;
#ifdef STARTUP_FACTORY_V27_TESTING
        if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==3)parent_verified=0;
#endif
        if(!parent_verified)status="parent-identity-mismatch";
      }
      unsigned char nonce_digest[32]={0};char nonce_hex[65]={0};
      if(strcmp(status,"valid")==0){
        sfv27_sha256(sealed.creation_nonce,sizeof(sealed.creation_nonce),nonce_digest);
        hex_encode(nonce_digest,nonce_hex);
        if(snprintf(nonce_sha256,sizeof(nonce_sha256),"sha256:%s",nonce_hex)!=71)
          status="creation-nonce-echo-failed";
        else nonce_present=1;
#ifdef STARTUP_FACTORY_V27_TESTING
        if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==4){
          nonce_sha256[7]=nonce_sha256[7]=='0'?'1':'0';
          status="creation-nonce-echo-failed";
        }
#endif
      }
      if(strcmp(status,"valid")==0){
        memcpy(child_plan,sealed.plan_digest,sizeof(child_plan));plan_present=1;
#ifdef STARTUP_FACTORY_V27_TESTING
        if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==5){
          child_plan[0]^=1U;status="plan-digest-echo-failed";
        }
#endif
      }
      sfv27_secure_zero(nonce_digest,sizeof(nonce_digest));
      sfv27_secure_zero(nonce_hex,sizeof(nonce_hex));
    }
    int handshake_token=creator_handshake_token_v27(sealed.creation_nonce);
    sfv27_secure_zero(sealed.creation_nonce,sizeof(sealed.creation_nonce));
    if(pthread_mutex_lock(&result->gate_mutex)!=0)return &creator_abort_sentinel;
    result->creator_tid=creator_tid;
    memcpy(result->creator_start_ticks,creator_start,sizeof(creator_start));
    result->creator_waiting=1;
#ifdef STARTUP_FACTORY_V27_TESTING
    if(STARTUP_FACTORY_V27_TEST_HANDSHAKE_FAILURE_PHASE==6){
      while(!result->abort_authorized)
        if(pthread_cond_wait(&result->gate_condition,&result->gate_mutex)!=0){
          result->failure=1;(void)pthread_mutex_unlock(&result->gate_mutex);
          return &creator_abort_sentinel;
        }
      result->creator_return_waiting=1;
      (void)pthread_cond_broadcast(&result->gate_condition);
      while(!result->creator_return_authorized)
        if(pthread_cond_wait(&result->gate_condition,&result->gate_mutex)!=0){
          result->failure=1;(void)pthread_mutex_unlock(&result->gate_mutex);
          return &creator_abort_sentinel;
        }
      (void)pthread_mutex_unlock(&result->gate_mutex);
      return &creator_abort_sentinel;
    }
#endif
    result->creator_cancel_disable_rc=cancel_rc;
    result->creator_cancel_disable_present=cancel_present;
    result->creator_signal_mask_rc=signal_rc;
    result->creator_signal_mask_present=signal_present;
    result->creator_tid_present=tid_present;
    result->creator_start_ticks_present=start_present;
    result->child_supervisor_pid_present=supervisor_pid_present;
    result->child_supervisor_start_ticks_present=supervisor_start_present;
    result->parent_identity_present=parent_present;
    result->child_creation_nonce_present=nonce_present;
    result->child_plan_digest_present=plan_present;
    result->creator_handshake_futex_present=1;
    result->child_supervisor_pid=supervisor_pid;
    memcpy(result->child_supervisor_start_ticks,supervisor_start,sizeof(supervisor_start));
    result->parent_identity_verified=parent_verified;
    memcpy(result->child_creation_nonce_sha256,nonce_sha256,sizeof(nonce_sha256));
    memcpy(result->child_plan_digest,child_plan,sizeof(child_plan));
    result->creator_handshake_status=status;
    result->creator_handshake_reported=1;
    result->creator_handshake_complete=strcmp(status,"valid")==0;
    __atomic_store_n(&result->creator_handshake_futex_word,
      handshake_token,__ATOMIC_RELEASE);
    long handshake_wake=syscall(
      SYS_futex,&result->creator_handshake_futex_word,FUTEX_WAKE_PRIVATE,1,
      NULL,NULL,0);
    if(handshake_wake<0||handshake_wake>1L){
      result->failure=1;(void)pthread_mutex_unlock(&result->gate_mutex);
      return &creator_abort_sentinel;
    }
    result->creator_handshake_futex_wake_return=(int)handshake_wake;
    while(!result->release_authorized&&!result->abort_authorized)
      if(pthread_cond_wait(&result->gate_condition,&result->gate_mutex)!=0){result->failure=1;(void)pthread_mutex_unlock(&result->gate_mutex);return &creator_abort_sentinel;}
    if(result->abort_authorized){
      result->creator_return_waiting=1;(void)pthread_cond_broadcast(&result->gate_condition);
      while(!result->creator_return_authorized)
        if(pthread_cond_wait(&result->gate_condition,&result->gate_mutex)!=0){result->failure=1;(void)pthread_mutex_unlock(&result->gate_mutex);return &creator_abort_sentinel;}
      (void)pthread_mutex_unlock(&result->gate_mutex);return &creator_abort_sentinel;
    }
    result->release_known_live=1;(void)pthread_cond_broadcast(&result->gate_condition);
    while(!result->release_live_ack&&!result->abort_authorized)
      if(pthread_cond_wait(&result->gate_condition,&result->gate_mutex)!=0){result->failure=1;(void)pthread_mutex_unlock(&result->gate_mutex);return &creator_abort_sentinel;}
    if(result->abort_authorized){
      result->creator_return_waiting=1;(void)pthread_cond_broadcast(&result->gate_condition);
      while(!result->creator_return_authorized)
        if(pthread_cond_wait(&result->gate_condition,&result->gate_mutex)!=0){result->failure=1;(void)pthread_mutex_unlock(&result->gate_mutex);return &creator_abort_sentinel;}
      (void)pthread_mutex_unlock(&result->gate_mutex);return &creator_abort_sentinel;
    }
    if(pthread_mutex_unlock(&result->gate_mutex)!=0){result->failure=1;return &creator_abort_sentinel;}
    int readonly=strncmp(result->plan->stage_key,"reader-",7U)==0;
    char suffix[24];if(snprintf(suffix,sizeof(suffix),"s%s",result->plan->stage_location)>=(int)sizeof(suffix))result->failure=1;
    else if(result->test_fast_exit)result->effect_code=0;
    else {result->effect_code=lifecycle(result->plan,suffix,readonly,result->plan->argv,&result->stdout_bytes,&result->stderr_bytes);if(result->effect_code==123)result->failure=2;}
    if(!result->test_fast_exit)drain_payload_cgroup();
    if(pthread_mutex_lock(&result->gate_mutex)!=0){result->failure=1;return &creator_abort_sentinel;}
    result->creator_return_waiting=1;(void)pthread_cond_broadcast(&result->gate_condition);
    while(!result->creator_return_authorized)
      if(pthread_cond_wait(&result->gate_condition,&result->gate_mutex)!=0){result->failure=1;(void)pthread_mutex_unlock(&result->gate_mutex);return &creator_abort_sentinel;}
    if(pthread_mutex_unlock(&result->gate_mutex)!=0){result->failure=1;return &creator_abort_sentinel;}
    return &creator_positive_sentinel;
}

static void credentialed_control(const char *expected,int accept_cgroup_fds){
    int enabled=1;if(setsockopt(CONTROL_SOCKET_FD,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled))!=0)die("V27 SO_PASSCRED setup failed");
    unsigned char buffer[64],control[CMSG_SPACE(sizeof(struct ucred))+CMSG_SPACE(2U*sizeof(int))];struct iovec iov={.iov_base=buffer,.iov_len=sizeof(buffer)};struct msghdr message={0};
    message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);ssize_t count;
    do{count=recvmsg(CONTROL_SOCKET_FD,&message,MSG_CMSG_CLOEXEC);}while(count<0&&errno==EINTR&&controller_loss_signal==0);int credentials=0,rights=0;
    for(struct cmsghdr *item=CMSG_FIRSTHDR(&message);item!=NULL;item=CMSG_NXTHDR(&message,item)){
      if(item->cmsg_level!=SOL_SOCKET)die("V27 control ancillary changed");
      if(item->cmsg_type==SCM_CREDENTIALS&&item->cmsg_len==CMSG_LEN(sizeof(struct ucred))){
        struct ucred observed;memcpy(&observed,CMSG_DATA(item),sizeof(observed));if(observed.pid!=getppid()||observed.uid!=geteuid()||observed.gid!=getegid())die("V27 control sender credentials changed");credentials++;}
      else if(item->cmsg_type==SCM_RIGHTS&&item->cmsg_len==CMSG_LEN(2U*sizeof(int))&&accept_cgroup_fds){
        int received[2];memcpy(received,CMSG_DATA(item),sizeof(received));if(received[0]!=13||received[1]!=14)die("V27 private cgroup control FD table changed");payload_events_fd=received[0];payload_kill_fd=received[1];rights++;}
      else die("V27 control ancillary changed");}
    if(count!=(ssize_t)strlen(expected)||memcmp(buffer,expected,(size_t)count)!=0||credentials!=1||rights!=accept_cgroup_fds||(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0)
      die("V27 credentialed control packet changed");
    if(accept_cgroup_fds){struct stat payload,events,kill;errno=0;if(fstat(PAYLOAD_CGROUP_FD,&payload)!=0||fstat(payload_events_fd,&events)!=0||fstat(payload_kill_fd,&kill)!=0||!S_ISDIR(payload.st_mode)||!S_ISREG(events.st_mode)||!S_ISREG(kill.st_mode)||events.st_dev!=payload.st_dev||kill.st_dev!=payload.st_dev||(fcntl(payload_events_fd,F_GETFL)&O_ACCMODE)!=O_RDONLY||(fcntl(payload_kill_fd,F_GETFL)&O_ACCMODE)!=O_WRONLY||fcntl(15,F_GETFD)>=0||errno!=EBADF)die("V27 preopened cgroup controls changed");}
}

static char *base64(const unsigned char *data,size_t length){
    static const char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";size_t output_length=4U*((length+2U)/3U);char *result=calloc(output_length+1U,1U);
    if(result==NULL)die("V27 base64 allocation failed");
    size_t input=0,output=0;while(input<length){uint32_t a=input<length?data[input++]:0,b=input<length?data[input++]:0,
      c=input<length?data[input++]:0,triple=(a<<16)|(b<<8)|c;result[output++]=alphabet[(triple>>18)&63U];result[output++]=alphabet[(triple>>12)&63U];
      result[output++]=alphabet[(triple>>6)&63U];result[output++]=alphabet[triple&63U];}if(length%3U==1U)result[output_length-2U]=result[output_length-1U]='=';
    else if(length%3U==2U)result[output_length-1U]='=';
    return result;
}

static void hex_encode(const unsigned char input[32], char output[65]) {
    static const char alphabet[] = "0123456789abcdef";
    for (size_t index = 0U; index < 32U; ++index) {
        output[index*2U] = alphabet[input[index] >> 4U];
        output[index*2U+1U] = alphabet[input[index] & 15U];
    }
    output[64] = '\0';
}

static void hex_encode_bytes(const unsigned char *input,size_t length,char *output){
    static const char alphabet[] = "0123456789abcdef";
    for(size_t index=0U;index<length;++index){output[index*2U]=alphabet[input[index]>>4U];output[index*2U+1U]=alphabet[input[index]&15U];}
    output[length*2U]='\0';
}

static int native_event(struct plan *plan,const char *event,const char *phase,const char *observation){
    unsigned int sequence=++native_event_sequence;char evidence_hex[65],hmac_hex[65];
    size_t observation_length=strlen(observation);if(observation_length<2U||observation_length>2048U||observation[0]!='{'||observation[observation_length-1U]!='}')die("V27 native event observation changed");
    char evidence_body[4096];int evidence_body_length=snprintf(evidence_body,sizeof(evidence_body),"{\"event\":\"%s\",\"eventObservation\":%s,\"phase\":\"%s\",\"schemaVersion\":27,\"sequence\":%u,\"stagePlanSha256\":\"%s\"}",event,observation,phase,sequence,plan->stage_plan_sha256);
    if(evidence_body_length<=0||(size_t)evidence_body_length>=sizeof(evidence_body))die("V27 native event evidence body overflow");
    size_t evidence_material_length=(sizeof(native_event_evidence_domain)-1U)+(size_t)evidence_body_length;
    unsigned char material[sizeof(native_event_evidence_domain)+4096U];
    if(evidence_material_length>sizeof(material))die("V27 native event evidence material overflow");
    memcpy(material,native_event_evidence_domain,sizeof(native_event_evidence_domain)-1U);memcpy(material+sizeof(native_event_evidence_domain)-1U,evidence_body,(size_t)evidence_body_length);
    unsigned char evidence[32],event_hmac[32];sfv27_sha256(material,evidence_material_length,evidence);hex_encode(evidence,evidence_hex);
    char body[4096];int body_length=snprintf(body,sizeof(body),"{\"event\":\"%s\",\"eventEvidenceSha256\":\"sha256:%s\",\"eventObservation\":%s,\"phase\":\"%s\",\"schemaVersion\":27,\"sequence\":%u,\"stagePlanSha256\":\"%s\"}",event,evidence_hex,observation,phase,sequence,plan->stage_plan_sha256);
    if(body_length<=0||(size_t)body_length>=sizeof(body))die("V27 native event body overflow");
    sfv27_hmac_sha256(request_key,native_event_domain,sizeof(native_event_domain)-1U,(const unsigned char*)body,(size_t)body_length,event_hmac);hex_encode(event_hmac,hmac_hex);
    char observation_hex[4097];hex_encode_bytes((const unsigned char*)observation,observation_length,observation_hex);
    char packet[8192];int packet_length=snprintf(packet,sizeof(packet),"EVENT %u %s %s %s %s %s\n",sequence,phase,event,observation_hex,evidence_hex,hmac_hex);
    if(packet_length<=0||(size_t)packet_length>=sizeof(packet)||send(CONTROL_SOCKET_FD,packet,(size_t)packet_length,MSG_NOSIGNAL)!=packet_length)die("V27 native event send failed");
    unsigned char received[512],control[CMSG_SPACE(sizeof(struct ucred))];struct iovec iov={.iov_base=received,.iov_len=sizeof(received)};struct msghdr message={0};message.msg_iov=&iov;message.msg_iovlen=1;message.msg_control=control;message.msg_controllen=sizeof(control);ssize_t count;
    do{count=recvmsg(CONTROL_SOCKET_FD,&message,0);}while(count<0&&errno==EINTR&&controller_loss_signal==0);
    int credentials=0;for(struct cmsghdr *item=CMSG_FIRSTHDR(&message);item!=NULL;item=CMSG_NXTHDR(&message,item)){if(item->cmsg_level!=SOL_SOCKET||item->cmsg_type!=SCM_CREDENTIALS||item->cmsg_len!=CMSG_LEN(sizeof(struct ucred)))die("V27 native event ACK ancillary changed");struct ucred observed;memcpy(&observed,CMSG_DATA(item),sizeof(observed));if(observed.pid!=getppid()||observed.uid!=geteuid()||observed.gid!=getegid())die("V27 native event ACK credentials changed");credentials++;}
    if(count<=0||count>=(ssize_t)sizeof(received)||credentials!=1||(message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0||received[count-1]!='\n')die("V27 native event ACK framing changed");
    received[count-1]='\0';
    unsigned int ack_sequence=0U;char ack_phase[16],ack_event[80],authority_hex[65],expected_ack_wire[65],control_action[16],control_authority_hex[65],capture_hex[65],return_hex[65],current_hex[65],extra;
    if(sscanf((char*)received,"EVENT-ACK %u %15s %79s %64s %64s %15s %64s %64s %64s %64s%c",&ack_sequence,ack_phase,ack_event,authority_hex,expected_ack_wire,control_action,control_authority_hex,capture_hex,return_hex,current_hex,&extra)!=10||ack_sequence!=sequence||strcmp(ack_phase,phase)!=0||strcmp(ack_event,event)!=0)die("V27 native event ACK framing changed");
    for(size_t index=0;index<64U;++index){if(!((authority_hex[index]>='0'&&authority_hex[index]<='9')||(authority_hex[index]>='a'&&authority_hex[index]<='f')))die("V27 native event ACK authority digest changed");if(!((expected_ack_wire[index]>='0'&&expected_ack_wire[index]<='9')||(expected_ack_wire[index]>='a'&&expected_ack_wire[index]<='f')))die("V27 native event ACK HMAC encoding changed");}
    const char *control_authority_json="null";char control_authority_value[80];
    if(strcmp(control_action,"continue")==0){if(strcmp(control_authority_hex,"-")!=0)die("V27 continue ACK carried revoke authority");}
    else if(strcmp(control_action,"revoke")==0){
      int creator_ready_cutoff=strcmp(event,"native-creator-created")==0&&strcmp(phase,"after")==0;
      int release_consumption_cutoff=strcmp(event,"release-consumed-current")==0&&strcmp(phase,"before")==0;
      if(controller_revoke_authorized||(!creator_ready_cutoff&&!release_consumption_cutoff))die("V27 revoke ACK is outside the pre-release gate");
      for(size_t index=0;index<64U;++index)if(!((control_authority_hex[index]>='0'&&control_authority_hex[index]<='9')||(control_authority_hex[index]>='a'&&control_authority_hex[index]<='f')))die("V27 revoke authority digest changed");
      if(snprintf(control_authority_value,sizeof(control_authority_value),"\"sha256:%s\"",control_authority_hex)<=0)die("V27 revoke authority encoding failed");
      control_authority_json=control_authority_value;
    } else die("V27 native event ACK control action changed");
    int capture_gate=strcmp(event,"creator-return-ready")==0&&strcmp(phase,"before")==0;
    const char *capture_json="null";char capture_value[512];
    if(capture_gate){
      for(size_t index=0;index<64U;++index)if(!((capture_hex[index]>='0'&&capture_hex[index]<='9')||(capture_hex[index]>='a'&&capture_hex[index]<='f'))||!((return_hex[index]>='0'&&return_hex[index]<='9')||(return_hex[index]>='a'&&return_hex[index]<='f'))||!((current_hex[index]>='0'&&current_hex[index]<='9')||(current_hex[index]>='a'&&current_hex[index]<='f')))die("V27 creator capture ACK digest changed");
      if(snprintf(capture_preparation_record_sha256,sizeof(capture_preparation_record_sha256),"sha256:%s",capture_hex)!=71||snprintf(return_authorization_record_sha256,sizeof(return_authorization_record_sha256),"sha256:%s",return_hex)!=71||snprintf(creator_return_current_record_sha256,sizeof(creator_return_current_record_sha256),"sha256:%s",current_hex)!=71)die("V27 creator capture ACK digest encoding failed");
      if(snprintf(capture_value,sizeof(capture_value),"{\"capturePreparationRecordSha256\":\"sha256:%s\",\"creatorReturnCurrentRecordSha256\":\"sha256:%s\",\"returnAuthorizationRecordSha256\":\"sha256:%s\"}",capture_hex,current_hex,return_hex)<=0)die("V27 creator capture ACK encoding failed");
      capture_json=capture_value;
    } else if(strcmp(capture_hex,"-")!=0||strcmp(return_hex,"-")!=0||strcmp(current_hex,"-")!=0)die("V27 non-capture ACK carried creator authority");
    char ack_body[1536];int ack_body_length=snprintf(ack_body,sizeof(ack_body),"{\"authorityRecordSha256\":\"sha256:%s\",\"controlAction\":\"%s\",\"controlAuthorityRecordSha256\":%s,\"creatorCaptureBinding\":%s,\"event\":\"%s\",\"phase\":\"%s\",\"schemaVersion\":27,\"sequence\":%u,\"stagePlanSha256\":\"%s\"}",authority_hex,control_action,control_authority_json,capture_json,event,phase,sequence,plan->stage_plan_sha256);
    unsigned char expected_ack[32];char expected_ack_hex[65];if(ack_body_length<=0||(size_t)ack_body_length>=sizeof(ack_body))die("V27 native event ACK body overflow");sfv27_hmac_sha256(request_key,native_event_ack_domain,sizeof(native_event_ack_domain)-1U,(const unsigned char*)ack_body,(size_t)ack_body_length,expected_ack);hex_encode(expected_ack,expected_ack_hex);
    if(strcmp(expected_ack_wire,expected_ack_hex)!=0)die("V27 native event ACK HMAC changed");
    int revoke_command=strcmp(control_action,"revoke")==0;
    if(revoke_command)controller_revoke_authorized=1;
    sfv27_secure_zero(material,sizeof(material));sfv27_secure_zero(observation_hex,sizeof(observation_hex));
    sfv27_secure_zero(evidence,sizeof(evidence));sfv27_secure_zero(event_hmac,sizeof(event_hmac));sfv27_secure_zero(expected_ack,sizeof(expected_ack));
    return revoke_command;
}

static void print_runtime_probe(void) {
    static const char digest_prefix[] = "\"supervisorSha256\":\"sha256:";
    const char *embedded = STARTUP_FACTORY_V27_PROBE_JSON;
    size_t length = strlen(embedded);
    /* The fixture intentionally compiles with the default `{}` probe. Keep a
     * fixed inspection margin so strict fortified builds can prove that the
     * 64-byte slot checks are memory-safe before the missing-prefix branch. */
    char *observed = calloc(length + 128U, 1U);
    if (observed == NULL) die("V27 runtime probe allocation failed");
    memcpy(observed, embedded, length + 1U);
    char *prefix = strstr(observed, digest_prefix);
    if (prefix == NULL || strstr(prefix + sizeof(digest_prefix) - 1U, digest_prefix) != NULL)
        die("V27 runtime probe supervisor digest slot is absent or duplicated");
    char *slot = prefix + sizeof(digest_prefix) - 1U;
    for (size_t index = 0U; index < 64U; ++index)
        if (slot[index] != '0') die("V27 runtime probe digest slot is not the build placeholder");
    if (slot[64] != '"') die("V27 runtime probe digest slot width changed");

    int executable = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (executable < 0) die("V27 runtime probe cannot open its executable identity");
    struct stat before, after;
    if (fstat(executable, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != 0 || before.st_nlink != 1 ||
        (before.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (before.st_mode & S_IXUSR) == 0 || before.st_size <= 0 ||
        (uint64_t)before.st_size > (uint64_t)MAX_EXECUTABLE_BYTES)
        die("V27 runtime probe executable identity is unsafe");
    struct sfv27_sha256_ctx context;
    sfv27_sha256_init(&context);
    unsigned char block[65536];
    uint64_t total = 0U;
    for (;;) {
        ssize_t count = read(executable, block, sizeof(block));
        if (count < 0 && errno == EINTR) continue;
        if (count < 0) die("V27 runtime probe executable read failed");
        if (count == 0) break;
        total += (uint64_t)count;
        if (total > (uint64_t)MAX_EXECUTABLE_BYTES)
            die("V27 runtime probe executable exceeded its bound");
        sfv27_sha256_update(&context, block, (size_t)count);
    }
    if (fstat(executable, &after) != 0 || close(executable) != 0 ||
        total != (uint64_t)before.st_size || before.st_dev != after.st_dev ||
        before.st_ino != after.st_ino || before.st_size != after.st_size ||
        before.st_mode != after.st_mode || before.st_uid != after.st_uid ||
        before.st_nlink != after.st_nlink)
        die("V27 runtime probe executable changed during observation");
    unsigned char digest[32];
    char digest_hex[65];
    sfv27_sha256_final(&context, digest);
    hex_encode(digest, digest_hex);
    memcpy(slot, digest_hex, 64U);
    sfv27_secure_zero(digest, sizeof(digest));
    sfv27_secure_zero(digest_hex, sizeof(digest_hex));
    if (write_all_fd(STDOUT_FILENO, observed, length) != 0 ||
        write_all_fd(STDOUT_FILENO, "\n", 1U) != 0)
        die("V27 runtime probe write failed");
    free(observed);
}

static void persist_terminal_no_replace(
    const char *temporary_name, const char *final_name,
    const char *value, size_t value_length
) {
    int descriptor = openat(
        RESULT_FD, temporary_name,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600
    );
    if (descriptor < 0)
        die("V27 protected terminal temporary creation failed");
    if (write_all_fd(descriptor, value, value_length) != 0 ||
        fsync(descriptor) != 0 || close(descriptor) != 0)
        die("V27 protected terminal temporary write/fsync failed");
    if (syscall(
            SYS_renameat2, RESULT_FD, temporary_name,
            RESULT_FD, final_name, RENAME_NOREPLACE
        ) != 0)
        die("V27 protected terminal no-replace install failed");
    if (fsync(RESULT_FD) != 0)
        die("V27 protected terminal directory fsync failed");
}

static void persist_authenticated_result(
    const char *envelope, size_t envelope_length
) {
    struct stat conflicting;
    errno = 0;
    if (fstatat(RESULT_FD, "disposition.json", &conflicting, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT)
        die("V27 protected result/disposition terminal XOR changed");
    persist_terminal_no_replace(
        ".result.json.tmp", "result.json", envelope, envelope_length
    );
}

static void persist_loss_disposition(const struct plan *plan) {
    char request_key_hex[65],hmac_hex[65],body[1024],envelope[1280];unsigned char disposition_hmac[32];
    struct stat operation_lock, conflicting;
    if (fstat(OPERATION_LOCK_FD, &operation_lock) != 0 ||
        !S_ISREG(operation_lock.st_mode) ||
        (operation_lock.st_mode & 07777U) != 0600U ||
        operation_lock.st_nlink != 1)
        die("V27 loss disposition operation lock changed");
    errno = 0;
    if (fstatat(RESULT_FD, "result.json", &conflicting, AT_SYMLINK_NOFOLLOW) == 0 ||
        errno != ENOENT)
        die("V27 loss disposition/result terminal XOR changed");
    hex_encode(request_key_id,request_key_hex);
    int body_length=snprintf(
      body,sizeof(body),
      "{\"disposition\":\"controller-lost-payload-drained\",\"operationId\":\"%s\",\"operationLock\":{\"device\":%llu,\"gid\":%llu,\"inode\":%llu,\"mode\":\"0600\",\"nlink\":%llu,\"uid\":%llu},\"requestKeyId\":\"sha256:%s\",\"schemaVersion\":27,\"stageLocation\":%s,\"stagePlanSha256\":\"%s\"}",
      plan->operation_id,
      (unsigned long long)operation_lock.st_dev,
      (unsigned long long)operation_lock.st_gid,
      (unsigned long long)operation_lock.st_ino,
      (unsigned long long)operation_lock.st_nlink,
      (unsigned long long)operation_lock.st_uid,
      request_key_hex,
      plan->stage_location,
      plan->stage_plan_sha256
    );
    if(body_length<0||(size_t)body_length>=sizeof(body))die("V27 loss disposition serialization failed");
    sfv27_hmac_sha256(request_key,disposition_domain,sizeof(disposition_domain)-1U,(const unsigned char*)body,(size_t)body_length,disposition_hmac);hex_encode(disposition_hmac,hmac_hex);
    int envelope_length=snprintf(envelope,sizeof(envelope),"{\"disposition\":%s,\"dispositionHmac\":\"hmac-sha256:%s\"}\n",body,hmac_hex);
    sfv27_secure_zero(disposition_hmac,sizeof(disposition_hmac));
    if(envelope_length<0||(size_t)envelope_length>=sizeof(envelope))die("V27 loss disposition envelope failed");
    persist_terminal_no_replace(
      ".disposition.json.tmp", "disposition.json",
      envelope, (size_t)envelope_length
    );
}

static int publish_authenticated_stage_result(
    const struct plan *plan,
    const struct creator_result *result,
    const char *result_kind, const char *predecessor_kind,
    const char *failure_reason
) {
    static const unsigned char failure_domain[] =
        "startup-factory/beads/v27/native-failure-evidence\0";
    const unsigned char empty[1] = {0};
    const unsigned char *stdout_value = result == NULL || result->stdout_bytes.data == NULL
        ? empty : result->stdout_bytes.data;
    const unsigned char *stderr_value = result == NULL || result->stderr_bytes.data == NULL
        ? empty : result->stderr_bytes.data;
    size_t stdout_length = result == NULL ? 0U : result->stdout_bytes.length;
    size_t stderr_length = result == NULL ? 0U : result->stderr_bytes.length;
    int exit_code = result == NULL ? 125 : result->effect_code;
    char *stdout64=base64(stdout_value,stdout_length);
    char *stderr64=base64(stderr_value,stderr_length);
    unsigned char failure_digest[32] = {0}; char failure_hex[65] = {0};
    char failure_json[96] = "null";
    if(failure_reason!=NULL){
      sfv27_hmac_sha256(
        request_key,failure_domain,sizeof(failure_domain)-1U,
        (const unsigned char*)failure_reason,strlen(failure_reason),failure_digest
      );
      hex_encode(failure_digest,failure_hex);
      if(snprintf(failure_json,sizeof(failure_json),"\"sha256:%s\"",failure_hex)>=(int)sizeof(failure_json))
        die("V27 failure evidence serialization failed");
    }
    size_t length=strlen(stdout64)+strlen(stderr64)+strlen(result_kind)+strlen(predecessor_kind)+768U;
    char *json=calloc(length,1U);if(json==NULL)die("V27 result allocation failed");
    int written=snprintf(json,length,
      "{\"exitCode\":%d,\"failureEvidenceSha256\":%s,\"lifecycle\":[\"create\",\"init\",\"start-attach\",\"terminal\",\"cleanup\",\"rm\"],\"placementMask\":%u,\"resultKind\":\"%s\",\"resultPredecessorKind\":\"%s\",\"stderrBase64\":\"%s\",\"stdoutBase64\":\"%s\"}",
      exit_code,failure_json,placement_mask,result_kind,predecessor_kind,stderr64,stdout64);
    if(written<0||(size_t)written>=length)die("V27 result serialization failed");
    unsigned char evidence_hmac[32],result_hmac[32],stdout_digest[32],stderr_digest[32];
    char result_hex[65],request_key_hex[65],stdout_hex[65],stderr_hex[65];
    sfv27_sha256(stdout_value,stdout_length,stdout_digest);hex_encode(stdout_digest,stdout_hex);
    sfv27_sha256(stderr_value,stderr_length,stderr_digest);hex_encode(stderr_digest,stderr_hex);
    sfv27_hmac_sha256(request_key,evidence_domain,sizeof(evidence_domain)-1U,plan_commitment,sizeof(plan_commitment),evidence_hmac);
    sfv27_hmac_sha256(request_key,result_domain,sizeof(result_domain)-1U,(const unsigned char*)json,(size_t)written,result_hmac);hex_encode(result_hmac,result_hex);
    hex_encode(request_key_id,request_key_hex);
    size_t envelope_length=(size_t)written+256U;char *envelope=calloc(envelope_length,1U);if(envelope==NULL)die("V27 result envelope allocation failed");
    int envelope_written=snprintf(envelope,envelope_length,"{\"requestKeyId\":\"sha256:%s\",\"result\":%s,\"resultHmac\":\"hmac-sha256:%s\"}\n",request_key_hex,json,result_hex);
    if(envelope_written<0||(size_t)envelope_written>=envelope_length)
      die("V27 authenticated result envelope serialization failed");

    /* The controller must durably consume the one-use handoff authority before
     * FD10, CONTROL-DONE, or stdout can expose the result.  This canonical
     * projection is byte-for-byte the Python NativeStageObservation. */
    size_t observation_length=strlen(stdout64)+strlen(stderr64)+strlen(result_kind)+strlen(predecessor_kind)+1024U;
    char *observation=calloc(observation_length,1U);if(observation==NULL)die("V27 result offer allocation failed");
    int observation_written=snprintf(observation,observation_length,
      "{\"exitCode\":%d,\"failureEvidenceSha256\":%s,\"lifecycle\":[\"create\",\"init\",\"start-attach\",\"terminal\",\"cleanup\",\"rm\"],\"placementMask\":%u,\"resultKind\":\"%s\",\"resultPredecessorKind\":\"%s\",\"stderrBase64\":\"%s\",\"stderrSha256\":\"sha256:%s\",\"stdoutBase64\":\"%s\",\"stdoutSha256\":\"sha256:%s\"}",
      exit_code,failure_json,placement_mask,result_kind,predecessor_kind,stderr64,stderr_hex,stdout64,stdout_hex);
    if(observation_written<0||(size_t)observation_written>=observation_length)
      die("V27 result offer observation serialization failed");
    unsigned char native_result_digest[32],offer_hmac[32];char native_result_hex[65],offer_hmac_hex[65];
    sfv27_sha256((const unsigned char*)observation,(size_t)observation_written,native_result_digest);hex_encode(native_result_digest,native_result_hex);
    char offer_body[2048];int offer_body_length=snprintf(offer_body,sizeof(offer_body),
      "{\"failureEvidenceSha256\":%s,\"nativeResultSha256\":\"sha256:%s\",\"placementMask\":%u,\"protocol\":\"startup-factory/beads-native-worker/v27\",\"resultKind\":\"%s\",\"resultPredecessorKind\":\"%s\",\"schemaVersion\":27,\"stagePlanSha256\":\"%s\",\"status\":\"result-offer\"}",
      failure_json,native_result_hex,placement_mask,result_kind,predecessor_kind,plan->stage_plan_sha256);
    if(offer_body_length<=0||(size_t)offer_body_length>=sizeof(offer_body))
      die("V27 result offer body serialization failed");
    sfv27_hmac_sha256(request_key,result_offer_domain,sizeof(result_offer_domain)-1U,(const unsigned char*)offer_body,(size_t)offer_body_length,offer_hmac);hex_encode(offer_hmac,offer_hmac_hex);
    const char *failure_wire=failure_reason==NULL?"-":failure_hex;
    char offer_packet[1024];int offer_packet_length=snprintf(offer_packet,sizeof(offer_packet),
      "RESULT-OFFER %s %s %s %s %u %s\n",native_result_hex,result_kind,predecessor_kind,failure_wire,placement_mask,offer_hmac_hex);
    if(offer_packet_length<=0||(size_t)offer_packet_length>=sizeof(offer_packet)||
       send(CONTROL_SOCKET_FD,offer_packet,(size_t)offer_packet_length,MSG_NOSIGNAL)!=offer_packet_length)
      die("V27 result offer send failed");
    unsigned char ack_packet[512],ack_control[CMSG_SPACE(sizeof(struct ucred))];
    struct iovec ack_iov={.iov_base=ack_packet,.iov_len=sizeof(ack_packet)};struct msghdr ack_message={0};
    ack_message.msg_iov=&ack_iov;ack_message.msg_iovlen=1;ack_message.msg_control=ack_control;ack_message.msg_controllen=sizeof(ack_control);ssize_t ack_count;
    do{ack_count=recvmsg(CONTROL_SOCKET_FD,&ack_message,0);}while(ack_count<0&&errno==EINTR&&controller_loss_signal==0);
    int ack_credentials=0;for(struct cmsghdr *item=CMSG_FIRSTHDR(&ack_message);item!=NULL;item=CMSG_NXTHDR(&ack_message,item)){
      if(item->cmsg_level!=SOL_SOCKET||item->cmsg_type!=SCM_CREDENTIALS||item->cmsg_len!=CMSG_LEN(sizeof(struct ucred)))die("V27 result offer ACK ancillary changed");
      struct ucred observed;memcpy(&observed,CMSG_DATA(item),sizeof(observed));if(observed.pid!=getppid()||observed.uid!=geteuid()||observed.gid!=getegid())die("V27 result offer ACK credentials changed");ack_credentials++;}
    if(ack_count<=0||ack_count>=(ssize_t)sizeof(ack_packet)||ack_credentials!=1||(ack_message.msg_flags&(MSG_TRUNC|MSG_CTRUNC))!=0||ack_packet[ack_count-1]!='\n')
      die("V27 result offer ACK framing changed");
    ack_packet[ack_count-1]='\0';char ack_native_hex[65],authorization_hex[65],ack_hmac_wire[65],ack_extra;
    if(sscanf((char*)ack_packet,"RESULT-OFFER-ACK %64s %64s %64s%c",ack_native_hex,authorization_hex,ack_hmac_wire,&ack_extra)!=3||strcmp(ack_native_hex,native_result_hex)!=0)
      die("V27 result offer ACK identity changed");
    for(size_t index=0;index<64U;++index)if(!((authorization_hex[index]>='0'&&authorization_hex[index]<='9')||(authorization_hex[index]>='a'&&authorization_hex[index]<='f'))||!((ack_hmac_wire[index]>='0'&&ack_hmac_wire[index]<='9')||(ack_hmac_wire[index]>='a'&&ack_hmac_wire[index]<='f')))die("V27 result offer ACK digest encoding changed");
    char ack_body[1024];int ack_body_length=snprintf(ack_body,sizeof(ack_body),
      "{\"action\":\"ACK-RESULT-OFFER\",\"authorizationRecordSha256\":\"sha256:%s\",\"nativeResultSha256\":\"sha256:%s\",\"protocol\":\"startup-factory/beads-native-worker/v27\",\"schemaVersion\":27,\"stagePlanSha256\":\"%s\"}",
      authorization_hex,native_result_hex,plan->stage_plan_sha256);
    unsigned char expected_offer_ack[32];char expected_offer_ack_hex[65];
    if(ack_body_length<=0||(size_t)ack_body_length>=sizeof(ack_body))die("V27 result offer ACK body overflow");
    sfv27_hmac_sha256(request_key,result_offer_ack_domain,sizeof(result_offer_ack_domain)-1U,(const unsigned char*)ack_body,(size_t)ack_body_length,expected_offer_ack);hex_encode(expected_offer_ack,expected_offer_ack_hex);
    if(strcmp(ack_hmac_wire,expected_offer_ack_hex)!=0)die("V27 result offer ACK HMAC changed");

    persist_authenticated_result(envelope,(size_t)envelope_written);
    char control_done[32];int control_done_length=snprintf(control_done,sizeof(control_done),"CONTROL-DONE %u\n",placement_mask);
    if(control_done_length<=0||(size_t)control_done_length>=sizeof(control_done)||send(CONTROL_SOCKET_FD,control_done,(size_t)control_done_length,MSG_NOSIGNAL)!=control_done_length)die("V27 placement-control terminal receipt failed");
    verify_controller_liveness(1);
    if(write_all_fd(STDOUT_FILENO,envelope,(size_t)envelope_written)!=0||write_all_fd(EVIDENCE_FD,evidence_hmac,sizeof(evidence_hmac))!=0||fsync(EVIDENCE_FD)!=0)
      die("V27 authenticated result/evidence write failed");
    free(stdout64);free(stderr64);free(json);free(envelope);free(observation);
    sfv27_secure_zero(request_key,sizeof(request_key));request_key_live=0;
    sfv27_secure_zero(request_key_id,sizeof(request_key_id));
    sfv27_secure_zero(failure_digest,sizeof(failure_digest));
    sfv27_secure_zero(evidence_hmac,sizeof(evidence_hmac));sfv27_secure_zero(result_hmac,sizeof(result_hmac));
    sfv27_secure_zero(stdout_digest,sizeof(stdout_digest));sfv27_secure_zero(stderr_digest,sizeof(stderr_digest));
    sfv27_secure_zero(native_result_digest,sizeof(native_result_digest));sfv27_secure_zero(offer_hmac,sizeof(offer_hmac));sfv27_secure_zero(expected_offer_ack,sizeof(expected_offer_ack));
    return 0;
}

static int native_event_pair(struct plan *plan,const char *event,const char *before,const char *after){
    if(native_event(plan,event,"before",before))return 1;
    return native_event(plan,event,"after",after);
}

static int store_gate_and_wake(struct creator_result *result,int value){
    __atomic_store_n(&result->gate_word,value,__ATOMIC_RELEASE);
    long wake=syscall(SYS_futex,&result->gate_word,FUTEX_WAKE_PRIVATE,1,NULL,NULL,0);
    if(wake<0||wake>1L)die("V27 creator futex wake failed");
    return (int)wake;
}

static void closure_flags_digest(char output[72]){
    char body[256];int body_length=snprintf(body,sizeof(body),"{\"cgroupControlsClosed\":%s,\"payloadDrained\":%s,\"proofFdsClosed\":%s}",cgroup_control_close_receipt?"true":"false",payload_drained_receipt?"true":"false",proof_fds_closed?"true":"false");
    if(body_length<=0||(size_t)body_length>=sizeof(body))die("V27 terminal S/P/O observation overflow");
    unsigned char digest[32];char hex[65];sfv27_sha256((const unsigned char*)body,(size_t)body_length,digest);hex_encode(digest,hex);
    if(snprintf(output,72U,"sha256:%s",hex)!=71)
      die("V27 terminal S/P/O digest encoding failed");
    sfv27_secure_zero(digest,sizeof(digest));
}

static void creator_departure_and_join_attempt_digests(
    const struct creator_result *result,
    const char capture_preparation_sha256[72],
    char departure_sha256[72],
    char join_attempt_nonce_sha256[72]
){
    static const unsigned char join_nonce_domain[]=
      "startup-factory/beads/creator-join-attempt-nonce/v2\0";
    char departure[1024];int departure_length=snprintf(
      departure,sizeof(departure),
      "{\"capturePreparationSha256\":\"%s\",\"creatorReturnBarrierHeld\":true,\"creatorStartTicks\":\"%s\",\"creatorTaskObserved\":true,\"creatorTid\":%ld,\"joinOwnerTokenSha256\":\"%s\",\"slotGeneration\":%llu}",
      capture_preparation_sha256,result->creator_start_ticks,
      (long)result->creator_tid,join_owner_token_sha256,
      (unsigned long long)creator_slot_generation
    );
    if(departure_length<=0||(size_t)departure_length>=sizeof(departure))
      die("V27 creator departure intent overflow");
    unsigned char departure_digest[32],join_digest[32];char hex[65];
    sfv27_sha256(
      (const unsigned char *)departure,(size_t)departure_length,
      departure_digest
    );
    hex_encode(departure_digest,hex);
    if(snprintf(departure_sha256,72U,"sha256:%s",hex)!=71)
      die("V27 creator departure digest failed");
    sfv27_hmac_sha256(
      supervisor_ephemeral_key,join_nonce_domain,
      sizeof(join_nonce_domain)-1U,departure_digest,sizeof(departure_digest),
      join_digest
    );
    hex_encode(join_digest,hex);
    if(snprintf(join_attempt_nonce_sha256,72U,"sha256:%s",hex)!=71)
      die("V27 creator join-attempt nonce digest failed");
    sfv27_secure_zero(departure,sizeof(departure));
    sfv27_secure_zero(departure_digest,sizeof(departure_digest));
    sfv27_secure_zero(join_digest,sizeof(join_digest));
    sfv27_secure_zero(hex,sizeof(hex));
}

static int publish_revoked_creator(
    struct plan *plan,struct creator_result *result,
    struct sf_creator_slot_v1 *creator_slot,
    int gate_mutex_locked
){
    if(!join_owner_token_valid(creator_slot))
      die("V27 revoke join-owner token changed");
    if(controller_revoke_authorized){
      if(native_event(plan,"revoke-decision","after","{\"releaseNotIssued\":true,\"revokeAuthorized\":true}"))
        die("V27 revoke decision receipt carried a second revoke command");
    } else if(native_event_pair(plan,"revoke-decision","{\"releaseNotIssued\":true,\"revokeAuthorized\":true}","{\"releaseNotIssued\":true,\"revokeAuthorized\":true}"))
      die("V27 revoke decision carried a recursive revoke command");
    if(native_event(plan,"revoke-issued","before","{\"abortStoreReturn\":null,\"conditionBroadcastRc\":null,\"futexWakeReturn\":null}"))
      die("V27 revoke issue carried a recursive revoke command");
    if(!gate_mutex_locked&&pthread_mutex_lock(&result->gate_mutex)!=0)
      die("V27 creator revoke lock failed");
    result->abort_authorized=1;int futex_return=store_gate_and_wake(result,2);int broadcast_return=pthread_cond_broadcast(&result->gate_condition);
    if(broadcast_return!=0||pthread_mutex_unlock(&result->gate_mutex)!=0)
      die("V27 creator revoke wake failed");
    char revoke_observation[192];if(snprintf(revoke_observation,sizeof(revoke_observation),"{\"abortStoreReturn\":0,\"conditionBroadcastRc\":%d,\"futexWakeReturn\":%d}",broadcast_return,futex_return)<=0)die("V27 revoke observation failed");
    if(native_event(plan,"revoke-issued","after",revoke_observation))
      die("V27 revoke receipt carried a recursive revoke command");
    if(pthread_mutex_lock(&result->gate_mutex)!=0)
      die("V27 creator revoke terminal lock failed");
    while(!result->creator_return_waiting)
      if(pthread_cond_wait(&result->gate_condition,&result->gate_mutex)!=0)
        die("V27 creator revoke return-wait failed");
    if(!creator_task_matches(result->creator_tid,result->creator_start_ticks))
      die("V27 creator revoke identity disappeared before return authorization");
    char revoke_terminal_observation[768];if(snprintf(revoke_terminal_observation,sizeof(revoke_terminal_observation),
      "{\"abortAuthorized\":true,\"creatorHandleConsumed\":false,\"creatorStartTicks\":\"%s\",\"creatorTaskObserved\":true,\"creatorTid\":%ld,\"slotGeneration\":%llu}",
      result->creator_start_ticks,(long)result->creator_tid,
      (unsigned long long)creator_slot_generation)<=0)
      die("V27 revoke terminal observation failed");
    if(native_event_pair(plan,"revoke-terminal",revoke_terminal_observation,revoke_terminal_observation))
      die("V27 revoke terminal carried a recursive revoke command");
    char capture_preparation_sha256[72];prepare_post_return_capture(result->creator_tid,capture_preparation_sha256);
    char departure_intent_sha256[72],join_attempt_nonce_sha256[72];
    creator_departure_and_join_attempt_digests(
      result,capture_preparation_sha256,departure_intent_sha256,
      join_attempt_nonce_sha256
    );
    char creator_return_before[1024];if(snprintf(creator_return_before,sizeof(creator_return_before),
      "{\"atomicCaptureSha256\":null,\"capturePreparationSha256\":\"%s\",\"creatorHandleConsumed\":false,\"creatorStartTicks\":\"%s\",\"creatorTaskAbsent\":false,\"creatorTid\":%ld,\"departureIntentSha256\":\"%s\",\"joinAttemptNonceSha256\":\"%s\",\"joinOwnerTokenSha256\":\"%s\",\"postReturnObservationSha256\":null,\"pthreadJoinCount\":0,\"pthreadJoinRc\":null,\"returnSignalCount\":0,\"returnSentinel\":null,\"slotGeneration\":%llu}",
      capture_preparation_sha256,result->creator_start_ticks,(long)result->creator_tid,
      departure_intent_sha256,join_attempt_nonce_sha256,join_owner_token_sha256,
      (unsigned long long)creator_slot_generation)<=0)
      die("V27 revoked creator return preparation failed");
    if(native_event(plan,"creator-return-ready","before",creator_return_before))
      die("V27 revoke return authorization carried a recursive revoke");
    result->creator_return_authorized=1;
    if(pthread_cond_broadcast(&result->gate_condition)!=0||pthread_mutex_unlock(&result->gate_mutex)!=0)
      die("V27 revoked creator return authorization failed");
    struct timespec departure_poll={.tv_sec=0,.tv_nsec=1000000L};
    unsigned int departure_attempt=0U;
    while(!creator_task_absent(result->creator_tid)&&departure_attempt<5000U){
      if(controller_loss_signal!=0||nanosleep(&departure_poll,NULL)!=0)
        die("V27 revoked creator departure observation interrupted");
      departure_attempt++;
    }
    if(!creator_task_absent(result->creator_tid))
      die("V27 revoked creator departure was not observed");
    char creator_return_after[1024];if(snprintf(creator_return_after,sizeof(creator_return_after),
      "{\"atomicCaptureSha256\":null,\"capturePreparationSha256\":\"%s\",\"creatorHandleConsumed\":false,\"creatorStartTicks\":\"%s\",\"creatorTaskAbsent\":true,\"creatorTid\":%ld,\"departureIntentSha256\":\"%s\",\"joinAttemptNonceSha256\":\"%s\",\"joinOwnerTokenSha256\":\"%s\",\"postReturnObservationSha256\":null,\"pthreadJoinCount\":0,\"pthreadJoinRc\":null,\"returnSignalCount\":1,\"returnSentinel\":null,\"slotGeneration\":%llu}",
      capture_preparation_sha256,result->creator_start_ticks,(long)result->creator_tid,
      departure_intent_sha256,join_attempt_nonce_sha256,join_owner_token_sha256,
      (unsigned long long)creator_slot_generation)<=0)
      die("V27 revoked creator departure/join attempt failed");
    if(native_event(plan,"creator-return-ready","after",creator_return_after))
      die("V27 revoke departure receipt carried a recursive revoke");
    void *creator_return=NULL;int join_return=pthread_join(creator_slot->pthread,&creator_return);result->creator_handle_consumed=join_return==0;creator_slot->handle_consumed=result->creator_handle_consumed;
    if(join_return!=0||creator_return!=&creator_abort_sentinel||!creator_slot->handle_consumed)
      die("V27 creator revoke join/sentinel failed");
    drain_payload_cgroup();close_payload_cgroup_controls();
    struct sf_post_return_artifacts_v1 artifacts={0};
    persist_post_return_artifacts_while_held_v27(
      result,join_return,"creator-abort-sentinel",capture_preparation_sha256,
      &artifacts);
    char closure_flags[72];closure_flags_digest(closure_flags);
    char lifetime_before[3072];if(snprintf(lifetime_before,sizeof(lifetime_before),
      "{\"allocationGateHeld\":true,\"allocationGateReleaseCount\":0,\"allocationGateReleaseMonotonicNs\":null,\"allocationGateReleaseReceiptSha256\":null,\"atomicCaptureSha256\":\"%s\",\"bootIdSha256\":\"%s\",\"captureMonotonicNs\":%llu,\"capturePreparationSha256\":\"%s\",\"capturePrepareMonotonicNs\":%llu,\"captureWritersSha256\":\"%s\",\"closureFlagsSha256\":\"%s\",\"creatorHandleConsumed\":true,\"creatorStartTicks\":\"%s\",\"creatorStartTicksPresent\":true,\"creatorTaskAbsent\":true,\"creatorTaskBytesSha256\":\"%s\",\"creatorTid\":%ld,\"creatorTidPresent\":true,\"fd11GetfdErrno\":%d,\"fd7GetfdErrno\":%d,\"joinOwnerTokenSha256\":\"%s\",\"joinResultSha256\":\"%s\",\"lifetimeRecordSha256\":\"%s\",\"payloadDrained\":true,\"postReturnObservationSha256\":\"%s\",\"proofFd11Closed\":true,\"proofFd7Closed\":true,\"pthreadJoinCount\":1,\"pthreadJoinRc\":0,\"resultFdIdentitySha256\":\"%s\",\"returnSentinel\":\"creator-abort-sentinel\",\"slotGeneration\":%llu,\"taskSetSha256\":\"%s\"}",
      artifacts.atomic_capture_sha256,creator_boot_id_sha256,
      artifacts.capture_monotonic_ns,capture_preparation_sha256,
      creator_capture_prepare_monotonic_ns,creator_capture_writers_sha256,
      closure_flags,result->creator_start_ticks,creator_task_bytes_sha256,
      (long)result->creator_tid,artifacts.fd11_getfd_errno,
      artifacts.fd7_getfd_errno,join_owner_token_sha256,
      artifacts.join_result_sha256,artifacts.lifetime_sha256,
      artifacts.post_return_observation_sha256,creator_result_fd_identity_sha256,
      (unsigned long long)creator_slot_generation,artifacts.task_set_sha256)<=0)
      die("V27 held revoke lifetime observation failed");
    if(native_event(plan,"creator-lifetime-closed","before",lifetime_before))
      die("V27 held revoke lifetime carried a recursive revoke");
    release_post_return_capture();
    persist_allocation_gate_release_receipt_v27(
      plan,&artifacts,capture_preparation_sha256,"creator-abort-sentinel");
    char lifetime_after[3072];if(snprintf(lifetime_after,sizeof(lifetime_after),
      "{\"allocationGateHeld\":false,\"allocationGateReleaseCount\":1,\"allocationGateReleaseMonotonicNs\":%llu,\"allocationGateReleaseReceiptSha256\":\"%s\",\"atomicCaptureSha256\":\"%s\",\"bootIdSha256\":\"%s\",\"captureMonotonicNs\":%llu,\"capturePreparationSha256\":\"%s\",\"capturePrepareMonotonicNs\":%llu,\"captureWritersSha256\":\"%s\",\"closureFlagsSha256\":\"%s\",\"creatorHandleConsumed\":true,\"creatorStartTicks\":\"%s\",\"creatorStartTicksPresent\":true,\"creatorTaskAbsent\":true,\"creatorTaskBytesSha256\":\"%s\",\"creatorTid\":%ld,\"creatorTidPresent\":true,\"fd11GetfdErrno\":%d,\"fd7GetfdErrno\":%d,\"joinOwnerTokenSha256\":\"%s\",\"joinResultSha256\":\"%s\",\"lifetimeRecordSha256\":\"%s\",\"payloadDrained\":true,\"postReturnObservationSha256\":\"%s\",\"proofFd11Closed\":true,\"proofFd7Closed\":true,\"pthreadJoinCount\":1,\"pthreadJoinRc\":0,\"resultFdIdentitySha256\":\"%s\",\"returnSentinel\":\"creator-abort-sentinel\",\"slotGeneration\":%llu,\"taskSetSha256\":\"%s\"}",
      artifacts.release_monotonic_ns,artifacts.gate_release_receipt_sha256,
      artifacts.atomic_capture_sha256,
      creator_boot_id_sha256,artifacts.capture_monotonic_ns,
      capture_preparation_sha256,creator_capture_prepare_monotonic_ns,
      creator_capture_writers_sha256,closure_flags,result->creator_start_ticks,
      creator_task_bytes_sha256,(long)result->creator_tid,
      artifacts.fd11_getfd_errno,artifacts.fd7_getfd_errno,
      join_owner_token_sha256,
      artifacts.join_result_sha256,artifacts.lifetime_sha256,
      artifacts.post_return_observation_sha256,creator_result_fd_identity_sha256,
      (unsigned long long)creator_slot_generation,artifacts.task_set_sha256)<=0)
      die("V27 released revoke lifetime observation failed");
    if(native_event(plan,"creator-lifetime-closed","after",lifetime_after))
      die("V27 creator lifetime carried a recursive revoke command");
    consume_join_owner_token();
    if(pthread_cond_destroy(&result->gate_condition)!=0||pthread_mutex_destroy(&result->gate_mutex)!=0)
      die("V27 revoked creator gate close failed");
    return publish_authenticated_stage_result(
      plan,result,"revoke-verified-no-effect","creator-lifetime-closed-revoke-verified-no-effect",
      "runtime-revoked-no-effect"
    );
}

static const char *creator_optional_int_v27(int value,char output[32]){
    if(value<0)return "null";
    int length=snprintf(output,32U,"%d",value);
    if(length<=0||length>=32)die("V27 creator integer encoding failed");
    return output;
}

static const char *creator_detach_readback_v27(int value){
    if(value<0)return "null";
    if(value==PTHREAD_CREATE_JOINABLE)return "\"joinable\"";
    if(value==PTHREAD_CREATE_DETACHED)return "\"detached\"";
    die("V27 creator detach-state readback changed");return "null";
}

static const char *creator_optional_json_string_v27(
    const char *value,int present,char *output,size_t output_size
){
    if(!present)return "null";
    if(value==NULL||value[0]=='\0')die("V27 creator optional string is empty");
    for(const char *cursor=value;*cursor!='\0';++cursor)
      if(!((*cursor>='a'&&*cursor<='z')||(*cursor>='A'&&*cursor<='Z')||
           (*cursor>='0'&&*cursor<='9')||*cursor==':'||*cursor=='-'))
        die("V27 creator optional string encoding changed");
    int length=snprintf(output,output_size,"\"%s\"",value);
    if(length<=0||(size_t)length>=output_size)
      die("V27 creator optional string overflow");
    return output;
}

static void creator_creation_observation_v27(
    char *output,size_t output_size,const struct sf_creator_started_v1 *started,
    int readiness_observed
){
    char plan_hex[65],plan_sha256[72]={0};
    if(started->child_plan_digest_present){
      hex_encode(started->plan_digest,plan_hex);
      if(snprintf(plan_sha256,sizeof(plan_sha256),"sha256:%s",plan_hex)!=71)
        die("V27 child plan digest encoding failed");
    }
    char nonce_json[96],plan_json[96],start_json[64],supervisor_start_json[64];
    const char *nonce_value=creator_optional_json_string_v27(
      started->handshake_nonce_sha256,started->child_creation_nonce_present,
      nonce_json,sizeof(nonce_json));
    const char *plan_value=creator_optional_json_string_v27(
      plan_sha256,started->child_plan_digest_present,plan_json,sizeof(plan_json));
    const char *start_value=creator_optional_json_string_v27(
      started->creator_start_ticks,started->creator_start_ticks_present,
      start_json,sizeof(start_json));
    const char *supervisor_start_value=creator_optional_json_string_v27(
      started->child_supervisor_start_ticks,
      started->child_supervisor_start_ticks_present,
      supervisor_start_json,sizeof(supervisor_start_json));
    char creator_tid[32],supervisor_pid[32],cancel_rc[32],signal_rc[32];
    char futex_value[32],futex_wake[32];
    const char *creator_tid_value=creator_optional_int_v27(
      started->creator_tid_present?(int)started->creator_tid:-1,creator_tid);
    const char *supervisor_pid_value=creator_optional_int_v27(
      started->child_supervisor_pid_present?(int)started->child_supervisor_pid:-1,supervisor_pid);
    const char *cancel_value=creator_optional_int_v27(
      started->creator_cancel_disable_present?started->creator_cancel_disable_rc:-1,cancel_rc);
    const char *signal_value=creator_optional_int_v27(
      started->creator_signal_mask_present?started->creator_signal_mask_rc:-1,signal_rc);
    const char *futex_value_json=creator_optional_int_v27(
      started->handshake_futex_present?started->handshake_futex_value:-1,futex_value);
    const char *futex_wake_json=creator_optional_int_v27(
      started->handshake_futex_present?started->handshake_futex_wake_return:-1,futex_wake);
    const char *parent_value=!started->parent_identity_observed?"null":
      (started->parent_identity_verified?"true":"false");
    int length;
    if(readiness_observed&&started->failure_phase==NULL){
      length=snprintf(output,output_size,
        "{\"createCalled\":true,\"creationNoncePresent\":true,\"creationNonceSha256\":%s,\"creatorCancelDisablePresent\":true,\"creatorCancelDisableRc\":%s,\"creatorHandleCaptured\":true,\"creatorHandshakeComplete\":true,\"creatorHandshakePresent\":true,\"creatorHandshakeStatus\":\"%s\",\"creatorPlanPresent\":true,\"creatorPlanSha256\":%s,\"creatorSignalMaskPresent\":true,\"creatorSignalMaskRc\":%s,\"creatorStartTicks\":%s,\"creatorStartTicksPresent\":true,\"creatorTid\":%s,\"creatorTidPresent\":true,\"fd11CloseRc\":%d,\"fd11PreCloseIdentityRevalidated\":true,\"fd7CloseRc\":%d,\"handshakeFutexPresent\":true,\"handshakeFutexValue\":%s,\"handshakeFutexWaitErrno\":%d,\"handshakeFutexWaitReturn\":%d,\"handshakeFutexWakeReturn\":%s,\"joinOwnerStartTicks\":\"%s\",\"joinOwnerTid\":%ld,\"joinOwnerTokenRetained\":true,\"joinOwnerTokenSha256\":\"%s\",\"parentIdentityPresent\":true,\"parentIdentityVerified\":%s,\"pidfdPreCloseTerminal\":false,\"proofFdsClosed\":true,\"pthreadAttrDestroyRc\":%d,\"pthreadAttrDetachStateReadback\":%s,\"pthreadAttrGetDetachStateRc\":%d,\"pthreadAttrInitRc\":%d,\"pthreadAttrSetDetachStateRc\":%d,\"pthreadAttrSetGuardSizeRc\":%d,\"pthreadAttrSetStackSizeRc\":%d,\"pthreadCreateRc\":%d,\"pthreadDetachState\":\"joinable\",\"slotAllocated\":true,\"slotGeneration\":%llu,\"slotId\":\"payload-terminal-creator\",\"supervisorPid\":%s,\"supervisorPidPresent\":true,\"supervisorStartTicks\":%s,\"supervisorStartTicksPresent\":true}",
        nonce_value,cancel_value,started->handshake_status,plan_value,signal_value,
        start_value,creator_tid_value,started->stat_close_rc,started->pidfd_close_rc,
        futex_value_json,started->handshake_futex_wait_errno,
        started->handshake_futex_wait_return,futex_wake_json,
        join_owner_start_ticks,(long)join_owner_tid,join_owner_token_sha256,
        parent_value,started->pthread_attr_destroy_rc,
        creator_detach_readback_v27(started->pthread_attr_detachstate_readback),
        started->pthread_attr_getdetachstate_rc,started->pthread_attr_init_rc,
        started->pthread_attr_setdetachstate_rc,started->pthread_attr_setguardsize_rc,
        started->pthread_attr_setstacksize_rc,started->pthread_create_rc,
        (unsigned long long)started->slot_generation,supervisor_pid_value,
        supervisor_start_value);
    } else {
      length=snprintf(output,output_size,
        "{\"createCalled\":true,\"creationNoncePresent\":%s,\"creationNonceSha256\":%s,\"creatorCancelDisablePresent\":%s,\"creatorCancelDisableRc\":%s,\"creatorHandleCaptured\":true,\"creatorHandshakePresent\":%s,\"creatorHandshakeStatus\":\"%s\",\"creatorPlanPresent\":%s,\"creatorPlanSha256\":%s,\"creatorSignalMaskPresent\":%s,\"creatorSignalMaskRc\":%s,\"creatorStartTicks\":%s,\"creatorStartTicksPresent\":%s,\"creatorTid\":%s,\"creatorTidPresent\":%s,\"failurePhase\":\"%s\",\"handshakeFutexPresent\":%s,\"handshakeFutexValue\":%s,\"handshakeFutexWaitErrno\":%d,\"handshakeFutexWaitReturn\":%d,\"handshakeFutexWakeReturn\":%s,\"joinOwnerStartTicks\":\"%s\",\"joinOwnerTid\":%ld,\"joinOwnerTokenRetained\":true,\"joinOwnerTokenSha256\":\"%s\",\"parentIdentityPresent\":%s,\"parentIdentityVerified\":%s,\"pthreadAttrDestroyRc\":%d,\"pthreadAttrDetachStateReadback\":%s,\"pthreadAttrGetDetachStateRc\":%d,\"pthreadAttrInitRc\":%d,\"pthreadAttrSetDetachStateRc\":%d,\"pthreadAttrSetGuardSizeRc\":%d,\"pthreadAttrSetStackSizeRc\":%d,\"pthreadCreateRc\":%d,\"readinessObserved\":%s,\"slotAllocated\":true,\"slotGeneration\":%llu,\"slotId\":\"payload-terminal-creator\",\"supervisorPid\":%s,\"supervisorPidPresent\":%s,\"supervisorStartTicks\":%s,\"supervisorStartTicksPresent\":%s}",
        started->child_creation_nonce_present?"true":"false",nonce_value,
        started->creator_cancel_disable_present?"true":"false",cancel_value,
        started->handshake_reported?"true":"false",
        started->handshake_status,
        started->child_plan_digest_present?"true":"false",plan_value,
        started->creator_signal_mask_present?"true":"false",signal_value,
        start_value,started->creator_start_ticks_present?"true":"false",
        creator_tid_value,started->creator_tid_present?"true":"false",
        started->failure_phase,
        started->handshake_futex_present?"true":"false",futex_value_json,
        started->handshake_futex_wait_errno,started->handshake_futex_wait_return,
        futex_wake_json,join_owner_start_ticks,(long)join_owner_tid,
        join_owner_token_sha256,
        started->parent_identity_observed?"true":"false",parent_value,
        started->pthread_attr_destroy_rc,
        creator_detach_readback_v27(started->pthread_attr_detachstate_readback),
        started->pthread_attr_getdetachstate_rc,started->pthread_attr_init_rc,
        started->pthread_attr_setdetachstate_rc,started->pthread_attr_setguardsize_rc,
        started->pthread_attr_setstacksize_rc,started->pthread_create_rc,
        readiness_observed?"true":"false",
        (unsigned long long)started->slot_generation,supervisor_pid_value,
        started->child_supervisor_pid_present?"true":"false",
        supervisor_start_value,
        started->child_supervisor_start_ticks_present?"true":"false");
    }
    if(length<=0||(size_t)length>=output_size)
      die("V27 creator creation observation overflow");
    sfv27_secure_zero(plan_hex,sizeof(plan_hex));
    sfv27_secure_zero(plan_sha256,sizeof(plan_sha256));
}

static int execute_plan(void){
    pid_t expected_parent=getppid();
    struct sigaction action={0};action.sa_handler=mark_controller_loss;sigemptyset(&action.sa_mask);
    struct sigaction revoke_action={0};revoke_action.sa_handler=mark_revoke;sigemptyset(&revoke_action.sa_mask);
    if(sigaction(SIGTERM,&action,NULL)!=0||sigaction(SIGUSR1,&revoke_action,NULL)!=0||expected_parent<=1||prctl(PR_SET_PDEATHSIG,SIGTERM)!=0||getppid()!=expected_parent)
      die("V27 supervisor parent-death binding failed");
    verify_fd_table();verify_selinux_transition();verify_controller_liveness(0);struct plan plan=read_plan();credentialed_control("RELEASE\n",1);
    if(getppid()!=expected_parent)die("V27 supervisor parent changed after Release");
    verify_controller_liveness(1);
    if(send(CONTROL_SOCKET_FD,"SETUPREADY\n",11U,MSG_NOSIGNAL)!=11)die("V27 SetupReady failed");
    credentialed_control("ACK\n",0);
    if(getppid()!=expected_parent)die("V27 supervisor parent changed after ACK");
    struct creator_result result={.plan=&plan};
#ifdef STARTUP_FACTORY_V27_TEST_PRECREATE_FAILURE
    int mutex_status=EINVAL;
    int condition_status=EINVAL;
#else
    int mutex_status=pthread_mutex_init(&result.gate_mutex,NULL);
    int condition_status=mutex_status==0?pthread_cond_init(&result.gate_condition,NULL):EINVAL;
#endif
    if(mutex_status!=0||condition_status!=0){
      int partial_cleanup=0;if(condition_status==0)partial_cleanup=pthread_cond_destroy(&result.gate_condition);
      if(partial_cleanup==0&&mutex_status==0)partial_cleanup=pthread_mutex_destroy(&result.gate_mutex);
      if(partial_cleanup!=0)die("V27 partial creator cleanup failed");
      int pidfd_close_rc,stat_close_rc;close_creation_proof_fds(&pidfd_close_rc,&stat_close_rc);
      char precreate_observation[256];if(snprintf(precreate_observation,sizeof(precreate_observation),"{\"conditionInitRc\":%d,\"fd11CloseRc\":%d,\"fd7CloseRc\":%d,\"mutexInitRc\":%d,\"partialCleanupRc\":%d,\"proofFdsClosed\":%s}",condition_status,stat_close_rc,pidfd_close_rc,mutex_status,partial_cleanup,proof_fds_closed?"true":"false")<=0)die("V27 precreate observation failed");
      native_event_pair(&plan,"supervisor-precreate-failed",precreate_observation,precreate_observation);
      if(!proof_fds_closed)die("V27 precreate proof FD close outcome is uncertain");
      drain_payload_cgroup();close_payload_cgroup_controls();
      return publish_authenticated_stage_result(
        &plan,NULL,"precreate-failed","supervisor-precreate-failed",
        "runtime-precreate-failed"
      );
    }
    join_owner_tid=(pid_t)syscall(SYS_gettid);
    if(join_owner_tid<=1||child_start_time(join_owner_tid,join_owner_start_ticks)!=0)
      die("V27 join-owner identity failed");
    char supervisor_start_ticks[32];
    if(child_start_time(getpid(),supervisor_start_ticks)!=0)
      die("V27 supervisor creation identity failed");
    initialize_creator_secrets();
    char creation_intent_observation[1024],creation_plan_hex[65];
    hex_encode(plan_commitment,creation_plan_hex);
    if(snprintf(creation_intent_observation,sizeof(creation_intent_observation),
      "{\"creationNonceSha256\":\"%s\",\"creatorPlanSha256\":\"sha256:%s\",\"joinOwnerStartTicks\":\"%s\",\"joinOwnerTid\":%ld,\"pthreadAttrDestroyRc\":null,\"pthreadAttrDetachStateReadback\":null,\"pthreadAttrGetDetachStateRc\":null,\"pthreadAttrGuardSize\":%u,\"pthreadAttrInitRc\":null,\"pthreadAttrScheduling\":\"inherited-default\",\"pthreadAttrSetDetachStateRc\":null,\"pthreadAttrSetGuardSizeRc\":null,\"pthreadAttrSetStackSizeRc\":null,\"pthreadAttrStackSize\":%u,\"pthreadCreateCalled\":false,\"pthreadDetachState\":\"joinable\",\"slotAllocated\":false,\"slotGeneration\":%llu,\"slotId\":\"payload-terminal-creator\"}",
      creator_creation_nonce_sha256,creation_plan_hex,join_owner_start_ticks,(long)join_owner_tid,
      REGISTERED_CREATOR_GUARD_SIZE,
      REGISTERED_CREATOR_STACK_SIZE,(unsigned long long)creator_slot_generation)<=0)
      die("V27 creation intent observation failed");
    if(native_event_pair(&plan,"creator-creation-consumed",creation_intent_observation,creation_intent_observation))
      die("V27 revoke cannot consume creator creation authority");
    struct sf_creator_slot_v1 creator_slot={
      .slot_id="payload-terminal-creator",.generation=creator_slot_generation
    };
    struct sf_creator_plan_v1 creator_plan={
      .result=&result,.plan_digest=plan_commitment,.plan_digest_length=32U,
      .creation_nonce=creator_creation_nonce,.creation_nonce_length=32U,
      .creation_nonce_sha256=creator_creation_nonce_sha256,
      .supervisor_pid=getpid(),.supervisor_start_ticks=supervisor_start_ticks
    };
    struct sf_creator_started_v1 creator_started={0};
    int start_status=sf_beads_creator_start_v1(&creator_slot,&creator_plan,&creator_started);
    if(!creator_started.slot_allocated){
      /* The protected controller turns this closed union into the directly
       * authenticated NativeCreatorPreCreateFailureV2 artifact. */
      char attr_init[32],attr_setdetach[32],attr_getdetach[32],attr_guard[32],attr_stack[32],attr_destroy[32],create_rc[32];
      char create_failure_observation[2048];if(snprintf(create_failure_observation,sizeof(create_failure_observation),"{\"createCalled\":%s,\"creationNonceSha256\":\"%s\",\"creatorHandleCaptured\":false,\"failurePhase\":\"%s\",\"fd11CloseRc\":%d,\"fd11PreCloseIdentityRevalidated\":true,\"fd7CloseRc\":%d,\"pidfdPreCloseTerminal\":false,\"proofFdsClosed\":%s,\"pthreadAttrDestroyRc\":%s,\"pthreadAttrDetachStateReadback\":%s,\"pthreadAttrGetDetachStateRc\":%s,\"pthreadAttrInitRc\":%s,\"pthreadAttrSetDetachStateRc\":%s,\"pthreadAttrSetGuardSizeRc\":%s,\"pthreadAttrSetStackSizeRc\":%s,\"pthreadCreateRc\":%s,\"slotAllocated\":false,\"slotGeneration\":%llu,\"slotId\":\"payload-terminal-creator\"}",creator_started.create_called?"true":"false",creator_creation_nonce_sha256,creator_started.failure_phase,creator_started.stat_close_rc,creator_started.pidfd_close_rc,proof_fds_closed?"true":"false",creator_optional_int_v27(creator_started.pthread_attr_destroy_rc,attr_destroy),creator_detach_readback_v27(creator_started.pthread_attr_detachstate_readback),creator_optional_int_v27(creator_started.pthread_attr_getdetachstate_rc,attr_getdetach),creator_optional_int_v27(creator_started.pthread_attr_init_rc,attr_init),creator_optional_int_v27(creator_started.pthread_attr_setdetachstate_rc,attr_setdetach),creator_optional_int_v27(creator_started.pthread_attr_setguardsize_rc,attr_guard),creator_optional_int_v27(creator_started.pthread_attr_setstacksize_rc,attr_stack),creator_optional_int_v27(creator_started.pthread_create_rc,create_rc),(unsigned long long)creator_slot_generation)<=0)die("V27 create failure observation failed");
      native_event_pair(&plan,"supervisor-create-failed-no-thread",create_failure_observation,create_failure_observation);
      if(!proof_fds_closed)die("V27 failed-create proof FD close outcome is uncertain");
      if(pthread_cond_destroy(&result.gate_condition)!=0||pthread_mutex_destroy(&result.gate_mutex)!=0)die("V27 failed creator gate close failed");
      consume_join_owner_token();
      drain_payload_cgroup();close_payload_cgroup_controls();
      return publish_authenticated_stage_result(
        &plan,NULL,"create-failed-no-thread","supervisor-create-failed-no-thread",
        "runtime-create-failed"
      );
    }
    if(start_status!=0||!creator_started.handshake_complete){
      char uncertain_observation[2048];creator_creation_observation_v27(
        uncertain_observation,sizeof(uncertain_observation),&creator_started,
        creator_started.handshake_complete);
      native_event_pair(&plan,"creator-status-uncertain",uncertain_observation,uncertain_observation);
      if(pthread_mutex_lock(&result.gate_mutex)!=0)die("V27 creator abort lock failed");
      char abort_wake_before[512];if(snprintf(abort_wake_before,sizeof(abort_wake_before),
        "{\"abortDecision\":\"wake-abort-and-join\",\"abortStoreCount\":0,\"attemptNonceSha256\":\"%s\",\"futexWakeCount\":0,\"slotGeneration\":%llu}",
        creator_creation_nonce_sha256,(unsigned long long)creator_slot_generation)<=0)die("V27 abort wake preparation failed");
      native_event(&plan,"abort-wake-consumed","before",abort_wake_before);result.abort_authorized=1;result.creator_return_authorized=1;int abort_futex_return=store_gate_and_wake(&result,2);int abort_broadcast_return=pthread_cond_broadcast(&result.gate_condition);
      if(abort_broadcast_return!=0||pthread_mutex_unlock(&result.gate_mutex)!=0)die("V27 creator abort wake failed");
      char abort_wake_after[512];if(snprintf(abort_wake_after,sizeof(abort_wake_after),
        "{\"abortDecision\":\"wake-abort-and-join\",\"abortStoreCount\":1,\"attemptNonceSha256\":\"%s\",\"futexWakeCount\":1,\"slotGeneration\":%llu}",
        creator_creation_nonce_sha256,(unsigned long long)creator_slot_generation)<=0)die("V27 abort wake return failed");
      native_event(&plan,"abort-wake-consumed","after",abort_wake_after);char abort_wake_observation[384];if(snprintf(abort_wake_observation,sizeof(abort_wake_observation),"{\"abortStoreReturn\":0,\"conditionBroadcastRc\":%d,\"futexWakeReturn\":%d,\"slotGeneration\":%llu}",abort_broadcast_return,abort_futex_return,(unsigned long long)creator_slot_generation)<=0)die("V27 abort wake observation failed");native_event_pair(&plan,"abort-wake-completed",abort_wake_observation,abort_wake_observation);
      char abort_join_before[512];if(snprintf(abort_join_before,sizeof(abort_join_before),
        "{\"creatorHandleConsumed\":false,\"joinAttemptNonceSha256\":\"%s\",\"pthreadJoinCount\":0,\"slotGeneration\":%llu}",
        creator_creation_nonce_sha256,(unsigned long long)creator_slot_generation)<=0)die("V27 abort join preparation failed");
      native_event(&plan,"abort-join-consumed","before",abort_join_before);void *abort_return=NULL;int abort_join_return=pthread_join(creator_slot.pthread,&abort_return);result.creator_handle_consumed=abort_join_return==0;creator_slot.handle_consumed=result.creator_handle_consumed;
      int abort_identity_observed=
        creator_started.creator_tid_present&&creator_started.creator_start_ticks_present;
      int abort_task_absent=-1;
      if(abort_join_return!=0||abort_return!=&creator_abort_sentinel||
         !result.creator_handle_consumed)
        die("V27 creator abort join/sentinel failed");
      if(abort_identity_observed){
        if(!wait_creator_task_absent(creator_started.creator_tid))
          die("V27 observed creator task remained after abort join");
        abort_task_absent=1;
      }
      char abort_join_after[512];if(snprintf(abort_join_after,sizeof(abort_join_after),
        "{\"creatorHandleConsumed\":true,\"joinAttemptNonceSha256\":\"%s\",\"pthreadJoinCount\":1,\"slotGeneration\":%llu}",
        creator_creation_nonce_sha256,(unsigned long long)creator_slot_generation)<=0){die("V27 abort join return failed");}
      native_event(&plan,"abort-join-consumed","after",abort_join_after);
      char abort_start_json[64],abort_tid_json[32];
      const char *abort_start_value=creator_optional_json_string_v27(
        creator_started.creator_start_ticks,
        creator_started.creator_start_ticks_present,
        abort_start_json,sizeof(abort_start_json));
      const char *abort_tid_value=creator_optional_int_v27(
        creator_started.creator_tid_present?(int)creator_started.creator_tid:-1,
        abort_tid_json);
      char abort_lifetime_observation[1024];if(snprintf(abort_lifetime_observation,sizeof(abort_lifetime_observation),
        "{\"creatorHandleConsumed\":true,\"creatorHandshakeStatus\":\"%s\",\"creatorStartTicks\":%s,\"creatorStartTicksPresent\":%s,\"creatorTaskAbsent\":%s,\"creatorTid\":%s,\"creatorTidPresent\":%s,\"failurePhase\":\"%s\",\"payloadReleaseCount\":0,\"pthreadJoinRc\":%d,\"returnSentinel\":\"creator-abort-sentinel\",\"slotGeneration\":%llu}",
        creator_started.handshake_status,abort_start_value,
        creator_started.creator_start_ticks_present?"true":"false",
        abort_task_absent==1?"true":"null",abort_tid_value,
        creator_started.creator_tid_present?"true":"false",
        creator_started.failure_phase,abort_join_return,
        (unsigned long long)creator_slot_generation)<=0){die("V27 abort lifetime observation failed");}
      native_event_pair(&plan,"abort-failure-lifetime",abort_lifetime_observation,abort_lifetime_observation);
      if(pthread_cond_destroy(&result.gate_condition)!=0||pthread_mutex_destroy(&result.gate_mutex)!=0)die("V27 aborted creator gate close failed");
      consume_join_owner_token();
      drain_payload_cgroup();close_payload_cgroup_controls();
      return publish_authenticated_stage_result(
        &plan,&result,"controlled-abort-failed","creator-abort-failure-lifetime",
        "runtime-controlled-abort-failed"
      );
    }
    if(!proof_fds_closed||!creator_task_matches(result.creator_tid,result.creator_start_ticks))
      die("V27 creator handshake identity is not live");
    char creator_observation[2048];creator_creation_observation_v27(
      creator_observation,sizeof(creator_observation),&creator_started,1);
    int revoke_after_creator=native_event_pair(&plan,"native-creator-created",creator_observation,creator_observation);
    if(pthread_mutex_lock(&result.gate_mutex)!=0)die("V27 creator readiness lock failed");
#ifdef STARTUP_FACTORY_V27_TEST_REVOKE_BEFORE_RELEASE
    revoke_signal=1;
#endif
    if(revoke_after_creator||revoke_signal!=0||controller_revoke_authorized)
      return publish_revoked_creator(&plan,&result,&creator_slot,1);
    if(pthread_mutex_unlock(&result.gate_mutex)!=0)die("V27 creator readiness unlock failed");
    if(native_event_pair(&plan,"release-consumed-current","{\"futexWakeCount\":0,\"releaseStoreCount\":0}","{\"futexWakeCount\":0,\"releaseStoreCount\":0}"))
      return publish_revoked_creator(&plan,&result,&creator_slot,0);
    if(native_event(&plan,"signal-attempt-consumed","before","{\"conditionBroadcastRc\":null,\"futexWakeReturn\":null,\"releaseStoreReturn\":null}"))
      return publish_revoked_creator(&plan,&result,&creator_slot,0);
    if(pthread_mutex_lock(&result.gate_mutex)!=0)
      die("V27 creator release lock failed");
    result.release_authorized=1;int release_futex_return=store_gate_and_wake(&result,1);int release_broadcast_return=pthread_cond_broadcast(&result.gate_condition);
    if(release_broadcast_return!=0||pthread_mutex_unlock(&result.gate_mutex)!=0)
      die("V27 creator release signal failed");
    char release_action_observation[192];if(snprintf(release_action_observation,sizeof(release_action_observation),"{\"conditionBroadcastRc\":%d,\"futexWakeReturn\":%d,\"releaseStoreReturn\":0}",release_broadcast_return,release_futex_return)<=0)die("V27 release action observation failed");native_event(&plan,"signal-attempt-consumed","after",release_action_observation);
    char release_issued_observation[192];if(snprintf(release_issued_observation,sizeof(release_issued_observation),"{\"futexWakeReturn\":%d,\"releaseAuthorized\":true,\"releaseStoreReturn\":0}",release_futex_return)<=0)die("V27 release issued observation failed");native_event_pair(&plan,"release-issued",release_issued_observation,release_issued_observation);
    if(pthread_mutex_lock(&result.gate_mutex)!=0)die("V27 creator live lock failed");
    while(!result.release_known_live){if(pthread_cond_wait(&result.gate_condition,&result.gate_mutex)!=0)die("V27 creator live wait failed");}
    if(!creator_task_matches(result.creator_tid,result.creator_start_ticks))die("V27 creator live identity disappeared before ReleaseKnownLive");
    char release_live_observation[768];if(snprintf(release_live_observation,sizeof(release_live_observation),
      "{\"creatorStartTicks\":\"%s\",\"creatorTaskObserved\":true,\"creatorTid\":%ld,\"joinOwnerTokenSha256\":\"%s\",\"releaseKnownLive\":true,\"secondAckBarrierHeld\":true,\"slotGeneration\":%llu}",
      result.creator_start_ticks,(long)result.creator_tid,join_owner_token_sha256,
      (unsigned long long)creator_slot_generation)<=0)die("V27 creator live observation failed");
    native_event_pair(&plan,"release-known-live",release_live_observation,release_live_observation);
    result.release_live_ack=1;if(pthread_cond_broadcast(&result.gate_condition)!=0||pthread_mutex_unlock(&result.gate_mutex)!=0)
      die("V27 creator second ACK release failed");
    if(pthread_mutex_lock(&result.gate_mutex)!=0)die("V27 creator return-wait lock failed");
    while(!result.creator_return_waiting){if(pthread_cond_wait(&result.gate_condition,&result.gate_mutex)!=0)die("V27 creator return-wait failed");}
    if(!creator_task_matches(result.creator_tid,result.creator_start_ticks))die("V27 creator return waiter identity changed");
    char release_terminal_before[768];if(snprintf(release_terminal_before,sizeof(release_terminal_before),
      "{\"creatorHandleConsumed\":false,\"creatorReturnWaiting\":true,\"creatorStartTicks\":\"%s\",\"creatorTaskObserved\":true,\"creatorTid\":%ld,\"payloadTerminalObserved\":true,\"slotGeneration\":%llu,\"terminalObservationPhase\":\"pre-terminal\"}",
      result.creator_start_ticks,(long)result.creator_tid,(unsigned long long)creator_slot_generation)<=0)
      die("V27 release terminal observation failed");
    native_event(&plan,"release-terminal","before",release_terminal_before);
    char release_terminal_after[768];if(snprintf(release_terminal_after,sizeof(release_terminal_after),
      "{\"creatorHandleConsumed\":false,\"creatorReturnWaiting\":true,\"creatorStartTicks\":\"%s\",\"creatorTaskObserved\":true,\"creatorTid\":%ld,\"payloadTerminalObserved\":true,\"slotGeneration\":%llu,\"terminalObservationPhase\":\"terminal-waiter\"}",
      result.creator_start_ticks,(long)result.creator_tid,(unsigned long long)creator_slot_generation)<=0)
      die("V27 release terminal observation failed");
    native_event(&plan,"release-terminal","after",release_terminal_after);
    char capture_preparation_sha256[72];prepare_post_return_capture(result.creator_tid,capture_preparation_sha256);
    char departure_intent_sha256[72],join_attempt_nonce_sha256[72];
    creator_departure_and_join_attempt_digests(
      &result,capture_preparation_sha256,departure_intent_sha256,
      join_attempt_nonce_sha256
    );
    char creator_return_before[1024];if(snprintf(creator_return_before,sizeof(creator_return_before),
      "{\"atomicCaptureSha256\":null,\"capturePreparationSha256\":\"%s\",\"creatorHandleConsumed\":false,\"creatorStartTicks\":\"%s\",\"creatorTaskAbsent\":false,\"creatorTid\":%ld,\"departureIntentSha256\":\"%s\",\"joinAttemptNonceSha256\":\"%s\",\"joinOwnerTokenSha256\":\"%s\",\"postReturnObservationSha256\":null,\"pthreadJoinCount\":0,\"pthreadJoinRc\":null,\"returnSignalCount\":0,\"returnSentinel\":null,\"slotGeneration\":%llu}",
      capture_preparation_sha256,result.creator_start_ticks,(long)result.creator_tid,
      departure_intent_sha256,join_attempt_nonce_sha256,join_owner_token_sha256,
      (unsigned long long)creator_slot_generation)<=0)
      die("V27 creator return preparation observation failed");
    native_event(&plan,"creator-return-ready","before",creator_return_before);
    result.creator_return_authorized=1;if(pthread_cond_broadcast(&result.gate_condition)!=0||pthread_mutex_unlock(&result.gate_mutex)!=0)
      die("V27 creator return authorization failed");
    if(!join_owner_token_valid(&creator_slot))die("V27 success join-owner token changed");
    struct timespec creator_departure_poll={.tv_sec=0,.tv_nsec=1000000L};
    unsigned int creator_departure_attempt=0U;
    while(!creator_task_absent(result.creator_tid)&&creator_departure_attempt<5000U){
      if(controller_loss_signal!=0||nanosleep(&creator_departure_poll,NULL)!=0)
        die("V27 creator departure observation interrupted");
      creator_departure_attempt++;
    }
    if(!creator_task_absent(result.creator_tid))
      die("V27 creator departure was not observed before join attempt");
    char creator_return_after[1024];if(snprintf(creator_return_after,sizeof(creator_return_after),
      "{\"atomicCaptureSha256\":null,\"capturePreparationSha256\":\"%s\",\"creatorHandleConsumed\":false,\"creatorStartTicks\":\"%s\",\"creatorTaskAbsent\":true,\"creatorTid\":%ld,\"departureIntentSha256\":\"%s\",\"joinAttemptNonceSha256\":\"%s\",\"joinOwnerTokenSha256\":\"%s\",\"postReturnObservationSha256\":null,\"pthreadJoinCount\":0,\"pthreadJoinRc\":null,\"returnSignalCount\":1,\"returnSentinel\":null,\"slotGeneration\":%llu}",
      capture_preparation_sha256,result.creator_start_ticks,(long)result.creator_tid,
      departure_intent_sha256,join_attempt_nonce_sha256,join_owner_token_sha256,
      (unsigned long long)creator_slot_generation)<=0)
      die("V27 creator departure/join attempt observation failed");
    native_event(&plan,"creator-return-ready","after",creator_return_after);
    void *positive_return=NULL;int positive_join_return=pthread_join(creator_slot.pthread,&positive_return);
    result.creator_handle_consumed=positive_join_return==0;creator_slot.handle_consumed=result.creator_handle_consumed;
    if(positive_join_return!=0||positive_return!=&creator_positive_sentinel||!creator_slot.handle_consumed)
      die("V27 literal stage creator join/capture failed closed");
    close_payload_cgroup_controls();
    struct sf_post_return_artifacts_v1 artifacts={0};
    persist_post_return_artifacts_while_held_v27(
      &result,positive_join_return,"creator-positive-sentinel",
      capture_preparation_sha256,&artifacts);
    char closure_flags_sha256[72];closure_flags_digest(closure_flags_sha256);
    char success_lifetime_before[3072];if(snprintf(success_lifetime_before,sizeof(success_lifetime_before),
      "{\"allocationGateHeld\":true,\"allocationGateReleaseCount\":0,\"allocationGateReleaseMonotonicNs\":null,\"allocationGateReleaseReceiptSha256\":null,\"atomicCaptureSha256\":\"%s\",\"bootIdSha256\":\"%s\",\"captureMonotonicNs\":%llu,\"capturePreparationSha256\":\"%s\",\"capturePrepareMonotonicNs\":%llu,\"captureWritersSha256\":\"%s\",\"closureFlagsSha256\":\"%s\",\"creatorHandleConsumed\":true,\"creatorStartTicks\":\"%s\",\"creatorStartTicksPresent\":true,\"creatorTaskAbsent\":true,\"creatorTaskBytesSha256\":\"%s\",\"creatorTid\":%ld,\"creatorTidPresent\":true,\"fd11GetfdErrno\":%d,\"fd7GetfdErrno\":%d,\"joinOwnerTokenSha256\":\"%s\",\"joinResultSha256\":\"%s\",\"lifetimeRecordSha256\":\"%s\",\"payloadDrained\":true,\"postReturnObservationSha256\":\"%s\",\"proofFd11Closed\":true,\"proofFd7Closed\":true,\"pthreadJoinCount\":1,\"pthreadJoinRc\":0,\"resultFdIdentitySha256\":\"%s\",\"returnSentinel\":\"creator-positive-sentinel\",\"slotGeneration\":%llu,\"taskSetSha256\":\"%s\"}",
      artifacts.atomic_capture_sha256,creator_boot_id_sha256,
      artifacts.capture_monotonic_ns,capture_preparation_sha256,
      creator_capture_prepare_monotonic_ns,creator_capture_writers_sha256,
      closure_flags_sha256,result.creator_start_ticks,creator_task_bytes_sha256,
      (long)result.creator_tid,artifacts.fd11_getfd_errno,
      artifacts.fd7_getfd_errno,join_owner_token_sha256,
      artifacts.join_result_sha256,artifacts.lifetime_sha256,
      artifacts.post_return_observation_sha256,creator_result_fd_identity_sha256,
      (unsigned long long)creator_slot_generation,artifacts.task_set_sha256)<=0)
      die("V27 held success lifetime observation failed");
    native_event(&plan,"creator-lifetime-closed","before",success_lifetime_before);
    release_post_return_capture();
    persist_allocation_gate_release_receipt_v27(
      &plan,&artifacts,capture_preparation_sha256,"creator-positive-sentinel");
    char success_lifetime_after[3072];if(snprintf(success_lifetime_after,sizeof(success_lifetime_after),
      "{\"allocationGateHeld\":false,\"allocationGateReleaseCount\":1,\"allocationGateReleaseMonotonicNs\":%llu,\"allocationGateReleaseReceiptSha256\":\"%s\",\"atomicCaptureSha256\":\"%s\",\"bootIdSha256\":\"%s\",\"captureMonotonicNs\":%llu,\"capturePreparationSha256\":\"%s\",\"capturePrepareMonotonicNs\":%llu,\"captureWritersSha256\":\"%s\",\"closureFlagsSha256\":\"%s\",\"creatorHandleConsumed\":true,\"creatorStartTicks\":\"%s\",\"creatorStartTicksPresent\":true,\"creatorTaskAbsent\":true,\"creatorTaskBytesSha256\":\"%s\",\"creatorTid\":%ld,\"creatorTidPresent\":true,\"fd11GetfdErrno\":%d,\"fd7GetfdErrno\":%d,\"joinOwnerTokenSha256\":\"%s\",\"joinResultSha256\":\"%s\",\"lifetimeRecordSha256\":\"%s\",\"payloadDrained\":true,\"postReturnObservationSha256\":\"%s\",\"proofFd11Closed\":true,\"proofFd7Closed\":true,\"pthreadJoinCount\":1,\"pthreadJoinRc\":0,\"resultFdIdentitySha256\":\"%s\",\"returnSentinel\":\"creator-positive-sentinel\",\"slotGeneration\":%llu,\"taskSetSha256\":\"%s\"}",
      artifacts.release_monotonic_ns,artifacts.gate_release_receipt_sha256,
      artifacts.atomic_capture_sha256,
      creator_boot_id_sha256,artifacts.capture_monotonic_ns,
      capture_preparation_sha256,creator_capture_prepare_monotonic_ns,
      creator_capture_writers_sha256,closure_flags_sha256,
      result.creator_start_ticks,creator_task_bytes_sha256,(long)result.creator_tid,
      artifacts.fd11_getfd_errno,artifacts.fd7_getfd_errno,
      join_owner_token_sha256,artifacts.join_result_sha256,
      artifacts.lifetime_sha256,artifacts.post_return_observation_sha256,
      creator_result_fd_identity_sha256,(unsigned long long)creator_slot_generation,
      artifacts.task_set_sha256)<=0)
      die("V27 released success lifetime observation failed");
    native_event(&plan,"creator-lifetime-closed","after",success_lifetime_after);
    consume_join_owner_token();
    if(pthread_cond_destroy(&result.gate_condition)!=0||pthread_mutex_destroy(&result.gate_mutex)!=0)die("V27 creator gate close failed");
    if(!payload_drained_receipt||!cgroup_control_close_receipt)die("V27 cgroup terminal receipts are incomplete");
    if(result.failure==2){persist_loss_disposition(&plan);die("V27 controller loss drained the payload cgroup");}
    if(result.failure)die("V27 literal stage creator failed closed");
    return publish_authenticated_stage_result(
      &plan,&result,"success","creator-lifetime-closed-positive",NULL
    );
}

int main(int argc,char **argv){
    initialize_host_environment();
    if(argc==2&&strcmp(argv[1],"--startup-factory-probe-v27")==0){verify_selinux_transition();print_runtime_probe();return 0;}
    if(argc==2&&strcmp(argv[1],"--startup-factory-launch-v27")==0){char *const next[]={argv[0],"--startup-factory-execute-v27",NULL};
      char *const environment[]={host_home,"LANG=C","LC_ALL=C",host_logname,"PATH=/usr/bin:/bin",host_runtime,host_user,NULL};
      execveat(SUPERVISOR_EXEC_FD,"",next,environment,AT_EMPTY_PATH);die("V27 same-inode execveat failed");}
    if(argc==2&&strcmp(argv[1],"--startup-factory-execute-v27")==0)return execute_plan();
    die("unknown V27 supervisor invocation");return 125;
}
