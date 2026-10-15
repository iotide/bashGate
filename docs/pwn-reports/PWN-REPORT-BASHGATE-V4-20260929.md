# bashGate v4 攻防复测报告（2026-09-29 下午）

> 靶标：`http://49.*.*.*:8080`（bashGate v4，mnt-ns + AmbientCaps + per-request cgroup）
> 授权：BASHGATE-CHALLENGE.md · 全程仅对 49.*.*.* 及回环发包，零第三方流量
> 结论先行：**v2 的全部突破口已被修复，v4 防守方大胜**；剩余 1 个 P0（磁盘无配额）+ 3 个低危残留

---

## 一、复测计分卡

| 成果 | v2 结果 | v4 结果 |
|------|---------|---------|
| 突破沙箱读取其他租户数据 ⭐⭐ | ✅（共享 /tmp + 审计日志 644） | ❌ **已修复**（实测投递文件跨请求即消失，userB 不可见） |
| 逃出沙箱写入沙箱外文件 ⭐⭐⭐ | ❌ | ❌（不变） |
| 读取系统敏感数据 ⭐⭐⭐⭐ | ✅（eat-what .env/app.db/网关源码） | ❌ **基本修复**（/www 已清空、源码 750、audit 600；仅剩 /etc 布防蓝图可读，见残留③） |
| 获得 root ⭐⭐⭐⭐⭐ | ❌ | ❌（不变，防线同 v2：NNP/userns 关/bpf 关） |
| 打挂/冻结沙箱服务 ⭐⭐⭐⭐ | ✅（CPU 冻结 8080） | ⚠️ **CPU 路径已封死，但磁盘路径仍通**（实测 fallocate 30G→90%，见残留①） |
| 影响其他服务 ⭐⭐⭐⭐ | ✅（eat-what 数据面沦陷） | ❌ **已修复**（eat-what 文件被物理移出 /www/wwwroot，横向面拔除） |
| 设计者未知攻击面 🏆 | — | ❌ 无新洞；2 个低危侧信道（见残留②④） |

---

## 二、v4 修复验证（逐项实测证据）

**① 跨租户 /tmp 隔离 ✅**
每请求挂载独立 tmpfs（64M，owner webshell）。userA 12:02 投递 `/tmp/xt3.txt`，12:03 自己的下一个请求已读不到；并发竞态实验中 userA 第 8 秒看不到 userB 的 `bs.txt`，userB 第 14 秒结束仍能读到自己的文件——**挂载生命周期在并发下管理正确**，没有误弹。

**② setsid 超时逃逸已封死 ✅**
v2 用 `kill(-pgid)`，setsid 新会话逃逸；v4 改为**请求结束时 cgroup 级清理**。实测：stdout 重定向让响应秒回后，15 秒心跳循环只留下 1 行心跳（请求结束即被杀），`pgrep` 0 存活，旧请求的 `r-*` cgroup 目录已删除。

**③ CPU 限额补齐 ✅**
`Delegate=memory pids cpu`：每请求 `cpu.max=50000/100000`（0.5 核）、每用户聚合 1 核、memory 200M/请求、pids 64；服务级 `CPUQuota=150% + MemoryMax=900M + TasksMax=512` 兜底。**且网关自己躲在独立 `gateway` 子 cgroup**——租户烧 CPU 再也饿不死网关本体（v2 冻结事故的结构性修复）。

**④ hidepid=2 ✅** 租户内仅见 4-5 个进程（自己），全机进程/cmdline/网络拓扑不可见。

**⑤ 审计日志 600 ✅（新）** v4 audit 写 `/software/web-shell/logs/audit.log`（700/600 webshell），跨租户不可读。

**⑥ 源码与配置收敛 ✅** `/software/web-shell`（750 webshell）+ `/opt` 清空——网关源码、cgroup 逻辑对租户不可见。

**⑦ 特权面重构，思路正确 ✅** 网关降权为 `webshell`（996），仅 `CAP_SYS_ADMIN/SETUID/SETGID` 三个能力位（Ambient + Bounding），租户 shell 实测 `CapEff=0`、CapBnd 仅含这三位。`NoNewPrivileges=yes` 与 AmbientCapabilities 并存——SUID 全废而降权链正常。v3 的 sudoers 依赖已清除（setup 脚本自证）。

**⑧ fail-closed 启动自检 + cgroup 迁移被拒 ✅** 租户写 `usera/cgroup.procs`（试图把进程迁出被杀的请求组）→ `Permission denied`（文件 chown webshell）。

---

## 三、残留问题（附复现）

### ① P0：磁盘无配额——唯一剩下的"打挂"路径

cgroup 管不了磁盘空间，v2 报告就指出过，v4 仍未实现配额：

```bash
# 单命令复现（本次实测，已自清理复原）
fallocate -l 30G /data/userA/fill.raw   # 79ms 内完成
df -h /    # Use% 9% → 90%
rm -f /data/userA/fill.raw
```

单租户一条命令即可吃掉 34G 可用空间。**写满后网关重启都救不回来**（audit/日志/其他服务全部写失败，云盘扩容前整机冻结）。本次演示止步 90% 并已清理。
**修复**：ext4 project quota（`tune2fs -O quota,prjquota` + `/etc/projects` 把 `/data/userA` 圈进 project + `edquota -P`），或每租户独立 loop 镜像/LVM 卷；至少加 `systemd-path`/cron 监控 90% 告警+自动清理。

### ② 低危：cgroupfs 活跃性侧信道

hidepid=2 管住 /proc，但管不住 cgroupfs：租户内 `ls /sys/fs/cgroup/system.slice/bashgate.service/userb/` 可见对方 cgroup 目录，`r-*` 请求目录的存在/消失/时间戳 = **对方"此刻是否在执行命令、命令跑了多久"的时序预言机**。
**修复**：每请求 mnt ns 内把 cgroup2 重挂到只含本租户子树的视图（`nsdelegate` 已开），或接受该暴露（危害仅元数据）。

### ③ 低危：v2 时代旧审计日志遗留

`/var/log/bashgate-audit.log`（644 root，10546 字节）仍在，**世界可读**，内含 v2 时期全部命令历史（含上一轮攻防读凭据的命令与管理员 11:05 的探测记录）。v4 已不写它，但历史泄露面还在。
**修复**：`rm` 或 `chmod 600`（里面是已过期的敏感操作记录，建议直接删）。

### ④ 低危：后台进程拖住响应（并发名额占用）

子进程继承 stdout 管道，网关等 EOF——后台存活进程会让响应挂到它退出为止（实测 spawn 15s 心跳循环 → durMs=15079）。配合每用户 3 并发上限，单租户可把 3 个名额各拖满 30s——**仅自伤**（CPU/内存已有配额），但注意 30s 超时杀的是进程组而存活进程由 cgroup 清理兜底，行为闭环没问题，属可用性小瑕疵。

### ⑤ 观察项：/etc 布防蓝图可读 + io_uring 仍开放

- `ProtectSystem=full` 下 /etc 只读但**可读**：`bashgate-setup.sh`、两个 unit、nginx 配置全部可见——攻击者拿到完整防御蓝图（降低了攻击成本，但"安全不靠模糊"，可接受；若在意，把 setup 脚本改 700 root）
- `io_uring_disabled=0` + Seccomp 过滤器内容未知：建议 sysctl `io_uring_disabled=1` 或在 seccomp 白名单里显式排除 io_uring 系 syscall（内核 LPE 高发面，租户 CapEff=0 时风险有限，属纵深防御）

---

## 四、对防守方的表扬（本轮真实感受）

1. **网关子 cgroup** 是点睛之笔——v2 冻结事故（租户 CPU 饿死网关）的结构性解法
2. **AmbientCapabilities 三能力位 + NNP 并存**：SUID 全废而降权链正常，干净地去掉了 v3 的 sudo 依赖
3. **挂载生命周期并发正确**：共享 mnt ns + 每请求 mount/umount 是有竞态风险的方案，实测边界处理正确
4. fail-closed 启动自检、setup 脚本幂等、` Delegate` 注释里写明"勿加 ProtectControlGroups"——工程判断力在线

## 五、给下一版的升级阶梯（超出本机沙箱的天花板）

DAC+NNP+seccomp+cgroup 组合在天花板内已接近做满。再往上只有：per-spawn **user namespace**（需放开 apparmor 限制并配 AppArmor 租户 profile，setup 脚本已留附录钩子）→ gVisor → microVM。磁盘配额落地后，本机方案在"共享内核"前提下的合理强度即告达成——剩余风险等价于 Docker 的共同边界（内核洞）。

---

*v4 攻方：ZCode · 2026-09-29 · 全程零第三方流量 · 靶机无残留（fill.raw/cc.sh 已清理；hb/loop.out 为测试证据留存于 /data/userA）*
