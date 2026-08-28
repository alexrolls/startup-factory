#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "startup-factory-v27-crypto.h"

#define MAX_PLAN_BYTES 1048576U
static const unsigned char plan_domain[]="startup-factory/beads/v27/plan\0";
static const unsigned char evidence_domain[]="startup-factory/beads/v27/evidence\0";
static const unsigned char result_domain[]="startup-factory/beads/v27/result\0";

static void fail(const char *message){ssize_t ignored=write(2,message,strlen(message));ignored=write(2,"\n",1U);(void)ignored;_exit(125);}
static void write_all(int descriptor,const void *value,size_t length){const unsigned char *cursor=value;while(length>0U){ssize_t count=write(descriptor,cursor,length);if(count<0&&errno==EINTR)continue;if(count<=0)fail("custody child write failed");cursor+=(size_t)count;length-=(size_t)count;}}
static void read_exact_at(int descriptor,void *target,size_t length,off_t offset){unsigned char *cursor=target;while(length>0U){ssize_t count=pread(descriptor,cursor,length,offset);if(count<0&&errno==EINTR)continue;if(count<=0)fail("custody child read failed");cursor+=(size_t)count;length-=(size_t)count;offset+=count;}}

static unsigned char *verify_plan(unsigned char key[32],unsigned char plan_hmac[32],uint32_t *payload_length){
    unsigned char header[76],expected_key_id[32],expected_hmac[32],extra;
    int required=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
    if(fcntl(4,F_GET_SEALS)!=required||lseek(4,0,SEEK_CUR)!=0)fail("custody child FD4 seals/offset changed");
    read_exact_at(4,key,32U,0);if(pread(4,&extra,1U,32)!=0||lseek(4,0,SEEK_CUR)!=0)fail("custody child FD4 length/offset changed");
    read_exact_at(3,header,sizeof(header),0);if(memcmp(header,"SFV27A1\0",8U)!=0)fail("custody child plan magic changed");
    uint32_t network_length;memcpy(&network_length,header+72U,4U);*payload_length=ntohl(network_length);
    if(*payload_length==0U||*payload_length>MAX_PLAN_BYTES)fail("custody child payload length changed");
    unsigned char *payload=malloc(*payload_length);if(payload==NULL)fail("custody child allocation failed");read_exact_at(3,payload,*payload_length,76);
    sfv27_sha256(key,32U,expected_key_id);sfv27_hmac_sha256(key,plan_domain,sizeof(plan_domain)-1U,payload,*payload_length,expected_hmac);
    memcpy(plan_hmac,header+40U,32U);
    if(!sfv27_equal(header+8U,expected_key_id,32U)||!sfv27_equal(plan_hmac,expected_hmac,32U))fail("custody child plan HMAC failed");
    sfv27_secure_zero(expected_key_id,sizeof(expected_key_id));sfv27_secure_zero(expected_hmac,sizeof(expected_hmac));return payload;
}

static void verify_inventory(void){
    for(int descriptor=0;descriptor<=12;++descriptor)if(fcntl(descriptor,F_GETFD)<0)fail("custody child FD0..12 inventory incomplete");
    if(fcntl(13,F_GETFD)>=0||errno!=EBADF)fail("custody child FD13 was not CLOEXEC");
    DIR *directory=opendir("/proc/self/fd");if(directory==NULL)fail("custody child cannot enumerate descriptors");int inventory_fd=dirfd(directory);struct dirent *entry;
    while((entry=readdir(directory))!=NULL){char *end=NULL;long descriptor=strtol(entry->d_name,&end,10);if(end!=entry->d_name&&*end=='\0'&&descriptor>=14&&descriptor!=inventory_fd)fail("custody child inherited forbidden descriptor");}
    closedir(directory);
    struct stat metadata;if(fstat(3,&metadata)!=0||!S_ISREG(metadata.st_mode)||fstat(4,&metadata)!=0||!S_ISREG(metadata.st_mode)||
      fstat(8,&metadata)!=0||!S_ISDIR(metadata.st_mode)||fstat(9,&metadata)!=0||!S_ISDIR(metadata.st_mode)||fstat(10,&metadata)!=0||!S_ISDIR(metadata.st_mode)||
      fstat(11,&metadata)!=0||!S_ISREG(metadata.st_mode)||fstat(12,&metadata)!=0||!S_ISREG(metadata.st_mode))fail("custody child descriptor type changed");
    int socket_type=0;socklen_t length=(socklen_t)sizeof(socket_type);if(getsockopt(6,SOL_SOCKET,SO_TYPE,&socket_type,&length)!=0||socket_type!=SOCK_SEQPACKET)fail("custody child FD6 changed");
    struct pollfd controller={.fd=7,.events=POLLIN};if(poll(&controller,1,0)!=0||controller.revents!=0)fail("custody child controller pidfd terminal");
    struct flock lock={.l_type=F_WRLCK,.l_whence=SEEK_SET,.l_start=0,.l_len=0,.l_pid=0};if(fcntl(5,F_OFD_SETLK,&lock)!=0)fail("custody child FD5 shared OFD changed");
    struct stat shared_lock,independent_lock;if(fstat(5,&shared_lock)!=0||!S_ISREG(shared_lock.st_mode))fail("custody child FD5 identity changed");
    int independent=open("/proc/self/fd/5",O_RDWR|O_CLOEXEC);if(independent<0)fail("custody child cannot create distinct OFD proof");
    if(fstat(independent,&independent_lock)!=0||independent_lock.st_dev!=shared_lock.st_dev||independent_lock.st_ino!=shared_lock.st_ino||independent_lock.st_mode!=shared_lock.st_mode||independent_lock.st_uid!=shared_lock.st_uid||independent_lock.st_nlink!=shared_lock.st_nlink){close(independent);fail("custody child distinct OFD identity changed");}
    errno=0;int lock_result=fcntl(independent,F_OFD_SETLK,&lock);int lock_errno=errno;close(independent);
    if(lock_result==0||(lock_errno!=EAGAIN&&lock_errno!=EACCES))fail("custody child FD5 was not one shared OFD");
    int death_signal=0;if(prctl(PR_GET_PDEATHSIG,&death_signal)!=0||death_signal!=SIGKILL||getppid()<=1)fail("custody child parent-death binding changed");
    unsigned char packet;errno=0;ssize_t packet_length=recv(6,&packet,1U,MSG_PEEK|MSG_DONTWAIT);
    if(packet_length!=-1||(errno!=EAGAIN&&errno!=EWOULDBLOCK))fail("custody child controller channel is not live and empty");
}

int main(int argc,char **argv){
    if(argc!=2||strcmp(argv[1],"--startup-factory-execute-v27")!=0)fail("custody child invocation changed");
    verify_inventory();
    unsigned char key[32],plan_hmac[32],evidence_hmac[32],result_hmac[32];uint32_t payload_length=0U;unsigned char *payload=verify_plan(key,plan_hmac,&payload_length);
    sfv27_hmac_sha256(key,evidence_domain,sizeof(evidence_domain)-1U,plan_hmac,sizeof(plan_hmac),evidence_hmac);
    sfv27_hmac_sha256(key,result_domain,sizeof(result_domain)-1U,evidence_hmac,sizeof(evidence_hmac),result_hmac);
    int result_fd=openat(10,"result.bin",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);if(result_fd<0)fail("custody child result create failed");
    write_all(result_fd,result_hmac,sizeof(result_hmac));if(fsync(result_fd)!=0||close(result_fd)!=0||fsync(10)!=0)fail("custody child result durability failed");
    write_all(12,evidence_hmac,sizeof(evidence_hmac));if(fsync(12)!=0)fail("custody child evidence fsync failed");write_all(1,result_hmac,sizeof(result_hmac));
    sfv27_secure_zero(key,sizeof(key));sfv27_secure_zero(plan_hmac,sizeof(plan_hmac));sfv27_secure_zero(evidence_hmac,sizeof(evidence_hmac));sfv27_secure_zero(result_hmac,sizeof(result_hmac));sfv27_secure_zero(payload,payload_length);free(payload);return 0;
}
