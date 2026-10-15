// seccomp-wrap: 加载过滤规则后 execvp(argv[1:])
// v10: 白名单模式 —— 默认全部 ENOSYS,仅放行 bash/python3/node/coreutils
//      运行所必需的 syscall。黑名单时代(V3-v9.1)的教训:新内核新 syscall
//      拦不到(Dirty Frag 判定反转实证);白名单 fail-closed,新增攻击面默认不可达。
//      保留 v9.1 的参数级封禁:socket(AF_NETLINK) → EAFNOSUPPORT(XFRM/nft/路由配置咽喉)。
//      回归:V8 四件套(超时杀/内存/E2BIG/并发) + python ctypes + node + 常规 coreutils。
#define _GNU_SOURCE
#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <errno.h>
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ERRNO(ENOSYS)); // 默认拒绝
  if (!ctx) return 3;
  int allow[] = {
    /* 进程与信号 */
    SCMP_SYS(exit), SCMP_SYS(exit_group), SCMP_SYS(clone), SCMP_SYS(clone3),
    SCMP_SYS(fork), SCMP_SYS(vfork), SCMP_SYS(execve), SCMP_SYS(execveat),
    SCMP_SYS(wait4), SCMP_SYS(waitid), SCMP_SYS(getpid), SCMP_SYS(getppid),
    SCMP_SYS(gettid), SCMP_SYS(kill), SCMP_SYS(tkill), SCMP_SYS(tgkill),
    SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask), SCMP_SYS(rt_sigreturn),
    SCMP_SYS(rt_sigtimedwait), SCMP_SYS(rt_sigpending), SCMP_SYS(rt_sigsuspend),
    /* 内存 */
    SCMP_SYS(brk), SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(mprotect),
    SCMP_SYS(mremap), SCMP_SYS(madvise), SCMP_SYS(msync), SCMP_SYS(mincore),
    SCMP_SYS(mlock), SCMP_SYS(munlock),
    /* 文件系统 */
    SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(openat2), SCMP_SYS(close),
    SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(pread64), SCMP_SYS(pwrite64),
    SCMP_SYS(readv), SCMP_SYS(writev), SCMP_SYS(preadv), SCMP_SYS(pwritev),
    SCMP_SYS(preadv2), SCMP_SYS(pwritev2),
    SCMP_SYS(lseek), SCMP_SYS(_llseek),
    SCMP_SYS(stat), SCMP_SYS(lstat), SCMP_SYS(fstat), SCMP_SYS(newfstatat),
    SCMP_SYS(statx), SCMP_SYS(readlink), SCMP_SYS(readlinkat),
    SCMP_SYS(getcwd), SCMP_SYS(chdir), SCMP_SYS(fchdir),
    SCMP_SYS(rename), SCMP_SYS(renameat), SCMP_SYS(renameat2),
    SCMP_SYS(unlink), SCMP_SYS(unlinkat),
    SCMP_SYS(link), SCMP_SYS(linkat), SCMP_SYS(symlink), SCMP_SYS(symlinkat),
    SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(rmdir),
    SCMP_SYS(truncate), SCMP_SYS(ftruncate), SCMP_SYS(fallocate),
    SCMP_SYS(getdents), SCMP_SYS(getdents64),
    SCMP_SYS(fcntl), SCMP_SYS(fcntl64), SCMP_SYS(ioctl),
    SCMP_SYS(fchmod), SCMP_SYS(fchmodat), SCMP_SYS(fchown), SCMP_SYS(fchownat),
    SCMP_SYS(faccessat), SCMP_SYS(faccessat2), SCMP_SYS(utimensat),
    SCMP_SYS(utime), SCMP_SYS(utimes),
    SCMP_SYS(dup), SCMP_SYS(dup2), SCMP_SYS(dup3),
    SCMP_SYS(pipe), SCMP_SYS(pipe2),
    SCMP_SYS(sendfile), SCMP_SYS(copy_file_range),
    SCMP_SYS(fsync), SCMP_SYS(fdatasync),
    SCMP_SYS(statfs), SCMP_SYS(statfs64), SCMP_SYS(fstatfs), SCMP_SYS(fstatfs64),
    SCMP_SYS(memfd_create),
    /* 文件属性(coreutils ls/stat 探测必需) */
    SCMP_SYS(listxattr), SCMP_SYS(llistxattr), SCMP_SYS(flistxattr),
    SCMP_SYS(getxattr), SCMP_SYS(lgetxattr), SCMP_SYS(fgetxattr),
    SCMP_SYS(setxattr), SCMP_SYS(lsetxattr), SCMP_SYS(fsetxattr),
    SCMP_SYS(removexattr), SCMP_SYS(lremovexattr), SCMP_SYS(fremovexattr),
    /* IO 多路复用 */
    SCMP_SYS(epoll_create), SCMP_SYS(epoll_create1), SCMP_SYS(epoll_ctl),
    SCMP_SYS(epoll_wait), SCMP_SYS(epoll_pwait), SCMP_SYS(epoll_pwait2),
    SCMP_SYS(eventfd), SCMP_SYS(eventfd2),
    SCMP_SYS(poll), SCMP_SYS(ppoll), SCMP_SYS(select), SCMP_SYS(pselect6),
    /* socket(通配放行,但 netlink 仍被下方参数级规则拒绝) */
    SCMP_SYS(socketpair), SCMP_SYS(bind), SCMP_SYS(connect),
    SCMP_SYS(listen), SCMP_SYS(accept), SCMP_SYS(accept4),
    SCMP_SYS(sendto), SCMP_SYS(recvfrom), SCMP_SYS(sendmsg), SCMP_SYS(recvmsg),
    SCMP_SYS(shutdown), SCMP_SYS(getsockname), SCMP_SYS(getpeername),
    SCMP_SYS(getsockopt), SCMP_SYS(setsockopt),
    /* 时间与定时器 */
    SCMP_SYS(clock_gettime), SCMP_SYS(clock_getres), SCMP_SYS(clock_nanosleep),
    SCMP_SYS(nanosleep), SCMP_SYS(gettimeofday),
    SCMP_SYS(time),
    SCMP_SYS(timerfd_create), SCMP_SYS(timerfd_settime), SCMP_SYS(timerfd_gettime),
    SCMP_SYS(timer_create), SCMP_SYS(timer_settime), SCMP_SYS(timer_gettime),
    SCMP_SYS(timer_delete), SCMP_SYS(getitimer), SCMP_SYS(setitimer), SCMP_SYS(alarm),
    /* 线程与调度(node/python 运行时必需) */
    SCMP_SYS(futex), SCMP_SYS(rseq), SCMP_SYS(set_robust_list),
    SCMP_SYS(get_robust_list), SCMP_SYS(membarrier), SCMP_SYS(sched_yield),
    SCMP_SYS(sched_getaffinity), SCMP_SYS(sched_setaffinity), SCMP_SYS(sched_getscheduler),
    /* 身份与杂项 */
    SCMP_SYS(getuid), SCMP_SYS(geteuid), SCMP_SYS(getgid), SCMP_SYS(getegid),
    SCMP_SYS(getgroups), SCMP_SYS(setuid), SCMP_SYS(setgid),
    SCMP_SYS(umask), SCMP_SYS(set_tid_address), SCMP_SYS(prctl), SCMP_SYS(arch_prctl),
    SCMP_SYS(capget), SCMP_SYS(capset),
    SCMP_SYS(getrlimit), SCMP_SYS(setrlimit), SCMP_SYS(prlimit64),
    SCMP_SYS(getrusage), SCMP_SYS(times), SCMP_SYS(sysinfo), SCMP_SYS(uname),
    SCMP_SYS(getrandom),
    SCMP_SYS(sigaltstack), SCMP_SYS(getcpu), SCMP_SYS(restart_syscall),
    SCMP_SYS(setpriority), SCMP_SYS(getpriority), SCMP_SYS(sched_getparam),
    SCMP_SYS(sched_setparam), SCMP_SYS(ioprio_get), SCMP_SYS(ioprio_set),
  };
  // v9.1 保留 + v10 修正:socket 按 address family 参数级放行(UNIX/INET/INET6),
  // AF_NETLINK 显式拒绝。不用"通配 allow+参数级 deny"——libseccomp 实测该组合
  // 中通配规则会使参数级 deny 静默失效(白名单上线首日实战踩坑)。
  if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
                       SCMP_A0(SCMP_CMP_EQ, 16 /* AF_NETLINK */)) != 0)
    { fprintf(stderr, "netlink deny failed\n"); return 6; }
  const int afs[] = { 1 /*AF_UNIX*/, 2 /*AF_INET*/, 10 /*AF_INET6*/ };
  for (unsigned i = 0; i < sizeof(afs)/sizeof(afs[0]); i++)
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
                         SCMP_A0(SCMP_CMP_EQ, afs[i])) != 0)
      { fprintf(stderr, "socket af allow failed\n"); return 7; }
  for (unsigned i = 0; i < sizeof(allow)/sizeof(allow[0]); i++)
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allow[i], 0) != 0)
      { fprintf(stderr, "allow rule failed: %d\n", allow[i]); return 5; }
  if (seccomp_load(ctx) != 0) { fprintf(stderr, "seccomp_load failed\n"); return 4; }
  execvp(argv[1], &argv[1]);
  perror("execvp");
  return 127;
}
