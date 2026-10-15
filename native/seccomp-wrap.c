// seccomp-wrap: 加载过滤规则后 execvp(argv[1:])
// 封锁挂载类/设备类/内核调试类 syscall —— ns-root 的 CAP_SYS_ADMIN 到此为止
#define _GNU_SOURCE
#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <errno.h>
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx) return 3;
  int deny[] = {
    SCMP_SYS(mount), SCMP_SYS(umount2), SCMP_SYS(pivot_root),
    SCMP_SYS(move_mount), SCMP_SYS(open_tree), SCMP_SYS(fsopen),
    SCMP_SYS(fsconfig), SCMP_SYS(fsmount), SCMP_SYS(mount_setattr), SCMP_SYS(fspick),
    SCMP_SYS(mknod), SCMP_SYS(mknodat),
    SCMP_SYS(ptrace), SCMP_SYS(process_vm_readv), SCMP_SYS(process_vm_writev),
    SCMP_SYS(bpf), SCMP_SYS(perf_event_open),
    SCMP_SYS(kexec_load), SCMP_SYS(kexec_file_load),
    SCMP_SYS(reboot), SCMP_SYS(swapon), SCMP_SYS(swapoff),
    SCMP_SYS(init_module), SCMP_SYS(finit_module), SCMP_SYS(delete_module),
    SCMP_SYS(setns), SCMP_SYS(unshare),
    SCMP_SYS(iopl), SCMP_SYS(ioperm), SCMP_SYS(acct), SCMP_SYS(vhangup),
  };
  for (unsigned i = 0; i < sizeof(deny)/sizeof(deny[0]); i++)
    seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), deny[i], 0);
  // v9.1: 参数级封 socket(AF_NETLINK) —— netlink 是 XFRM/nf_tables/路由的配置通道
  //   (Dirty Frag CVE-2026-43284 攻击链要件实测全通:NETLINK_XFRM 可建+lo UDP 回环+splice,
  //    封此一环即拆 SA 配置,连带拆 nf_tables 系列 LPE 的配置面;租户 bash 不用 netlink)
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
                   SCMP_A0(SCMP_CMP_EQ, 16 /* AF_NETLINK */));
  if (seccomp_load(ctx) != 0) { fprintf(stderr, "seccomp_load failed\n"); return 4; }
  execvp(argv[1], &argv[1]);
  perror("execvp");
  return 127;
}
