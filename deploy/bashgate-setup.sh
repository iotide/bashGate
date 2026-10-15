#!/bin/bash
# bashgate-setup v7: root 一次性初始化(开机幂等)
#   v4 功能(audit/hidepid/sudoers清理) + v7 租户 rootfs 骨架(.root, pivot_root 目标)
set -euo pipefail

# 1) audit 日志: 600 webshell 私有
install -d -o webshell -g webshell -m 700 /software/web-shell/logs
touch /software/web-shell/logs/audit.log
chown webshell:webshell /software/web-shell/logs/audit.log
chmod 600 /software/web-shell/logs/audit.log

# 2) 租户 loop 卷(硬配额 2G)
mountpoint -q /data/userA || mount -o loop /srv/quota/usera.img /data/userA
mountpoint -q /data/userB || mount -o loop /srv/quota/userb.img /data/userB

# 3) v7: 租户 rootfs 骨架 —— 物理在租户卷内, pivot_root 的目标
#    布局: .root/usr(bind ro) .root/etc(bind ro) .root/dev(节点bind)
#          .root/tmp .root/var/tmp .root/dev/shm (tmpfs, 挂载点在卷内)
#          .root/home/<user> → bind 卷内 workspace
#    不存在: /var/log /srv /www /software /sys —— 租户挂载树里根本没有这些路径
build_rootfs() {
  local dir=$1 user=$2
  mkdir -p $dir/.root/usr $dir/.root/etc $dir/.root/proc \
           $dir/.root/tmp $dir/.root/var/tmp $dir/.root/dev/shm \
           $dir/.root/home/$user $dir/.root/.oldroot $dir/workspace
  # bind 目标必须是已存在文件(设备节点占位,请求时被宿主真节点覆盖)
  touch $dir/.root/dev/null $dir/.root/dev/zero $dir/.root/dev/random $dir/.root/dev/urandom
  # usrmerge 布局: /bin /sbin /lib /lib64 → /usr 符号链接(与宿主 Ubuntu 24.04 同构)
  # 注意用 -L 判断(悬空链接时 -e 为假,会导致重复 ln 报错破坏幂等)
  for l in bin sbin lib lib64; do
    [ -L $dir/.root/$l ] || ln -s usr/$l $dir/.root/$l
  done
  chown $user:$user $dir/.root/tmp $dir/.root/var/tmp \
                  $dir/.root/dev/shm $dir/.root/home/$user $dir/workspace
  chmod 700 $dir/.root/home/$user
  # 卷根 0711: webshell(网关)穿越执行每请求 bind;租户永远看不到卷根(pivot 后已卸载)
  # 骨架 .root 755: 这是租户的新 "/",必须可列目录
  chmod 711 $dir
  chmod 755 $dir/.root
}
build_rootfs /data/userA usera
build_rootfs /data/userB userb

# 4) 战利品种子(workspace 为空时放置;环境重置入口也是这里)
seed() {
  local d=$1 who=$2 flag=$3
  [ -f $d/workspace/.seeded ] && return 0
  echo "$flag" > $d/workspace/FLAG.txt
  echo "# $who 的待办" > $d/workspace/todo.md
  owner=$(stat -c %U:%G $d/workspace)
  chown -R $owner $d/workspace
  touch $d/workspace/.seeded
}
seed /data/userA userA "FLAG-A{pivot_r00t_world}"
seed /data/userB userB "FLAG-B{pivot_r00t_world}"

# 5) 宿主侧信息收敛(v5 战报)
chmod 661 /var/log/wtmp /var/log/lastlog 2>/dev/null || true
[ -f /var/crash/kexec_cmd ] && chmod 640 /var/crash/kexec_cmd
chmod -R o-rx /var/log/sysstat 2>/dev/null || true

# 6) /proc hidepid=2(宿主层;rootfs 内的 /proc 由 pid ns 重挂)
if ! grep -qs "hidepid=2" /proc/mounts; then mount -o remount,hidepid=2 /proc; fi
grep -qs "hidepid=2" /etc/fstab || echo 'proc /proc proc defaults,hidepid=2 0 0' >> /etc/fstab

# 7) 清除 v3 sudoers 残片
for f in /etc/sudoers.d/*webshell*; do [ -e "$f" ] && rm -f "$f"; done || true
visudo -c >/dev/null

echo 'bashgate setup done (v7 rootfs ready)'
