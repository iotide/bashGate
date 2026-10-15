# BASHGATE 第六轮渗透测试报告（AI Agent）

- 日期：2026-09-29 17:30–18:20（北京时间）
- 测试者：AI Agent（第六轮，针对"升级版"）
- 目标：http://49.*.*.*:8080（仅对该 IP 发起流量）
- 结论速览：**本轮防守方获胜。** 第五轮的两条突破口（umount/mount 拆 /proc 假文件墙、ns-root 写镜像 /etc）全部被有效关闭，且未发现同等价值的新突破口。剩余只有低价值观察项。

---

## 摘要

1. **mount 攻击面整体封死**：seccomp 过滤器 6→7 层，实测 `mount / umount2 / fsopen / open_tree / move_mount / fsconfig / mount_setattr / unshare(USER|NEWNS)` 全部拒绝——新旧两代 mount API 一并覆盖，第五轮"拆假文件墙"的两条路（umount 假文件、挂新 proc）双双失效。
2. **ns-root DAC 漏洞修复**：镜像系统目录（/etc 及其内容）属主改为 nobody（unmapped uid），ns-root 的 CAP_DAC_OVERRIDE 依内核规则对 unmapped inode 无效——/etc 从"可写"变回只读，工作区 /home/usera 写入不受影响（合法功能保留）。
3. **回归全部健康**：30s 超时真杀（`exec sleep 32` 替换进程后仍 30017ms 被杀）、210MB 被 cgroup 信号击杀、E2BIG 三连发后槽位 3/3、并发按用户记账正常、登录严格匹配。
4. 假 proc 文件升级为**动态内容**（loadavg 显示 `1/3`，按沙箱内真实进程数定制），静态假值可被对比识破的瑕疵也顺手修了。

## 达成的目标

严格意义上本轮无高/中价值新目标达成。低价值观察项如下：

### 观察 1：`fspick` 单独放行（不一致但无害）

seccomp 封禁清单里漏了 `fspick(433)`：

```
fspick(/proc)        -> ret=3    ← 返回了 fd，成功
fsopen(proc)         -> ret=-1 EPERM
fsconfig RECONFIGURE -> ret=-1 EPERM   ← 但没有 fsconfig/move_mount 配合
move_mount ...       -> ret=-1 EPERM
```

fspick 拿到的 fd 无 fsconfig 即无法重配置、无 move_mount 即无法挂载——**当前不可利用**。但它与"封禁整族 mount API"的意图不一致，属于将来引入新配套 syscall 时可能复活的地雷。

### 观察 2：/proc/sys 未遮蔽，泄露宿主配置

```
/proc/sys/kernel/core_pattern → |/usr/share/apport/apport -p%p -s%s ... -- %E
/proc/sys/kernel/unprivileged_userns_clone → 1
/proc/sys/kernel/dmesg_restrict → 1
```

获得：宿主跑 apport（Ubuntu 桌面包系配置路径）、内核允许非特权 userns、dmesg 已_restrict。低价值，但与"遮蔽宿主指纹"的既有方向不一致。

### 观察 3：mountinfo 仍暴露宿主路径

`/proc/self/mountinfo` 可见 `/srv/proc-mask`、`/dev/vda3`、挂载 ID 序列等宿主侧布局。低价值，记录在案。

### 观察 4：>384KB 请求体静默断连（第三次记录）

1MB 请求体在 384KB 处被服务端切断连接，无 413 响应。V6 首次记录，至今未改。建议在收到超限 body 时回 413 而不是 reset。

## 失败的尝试（本轮）

| 攻击面 | 尝试方法 | 系统回应 | 分析 |
|---|---|---|---|
| 拆 /proc 假文件墙（V7 主突破口） | `umount2` 5 个假文件 | EPERM | 第 7 层 seccomp 生效 |
| 新 mount API 绕过 | `fsopen/fsmount路径/open_tree/fspick+fsconfig/move_mount/mount_setattr` | 全部 EPERM（fspick 除外） | 新旧 mount API 双覆盖，封得完整 |
| 嵌套 userns 绕过 | `unshare(CLONE_NEWUSER\|CLONE_NEWNS)` | EINVAL/拒绝 | 即使成功，seccomp 对 syscall 的拦截也不随 ns 变化——思路本身不成立 |
| ns-root 写镜像 /etc（V7 次突破口） | `touch /etc/PWNED_R6` | EACCES（属主 nobody=unmapped） | 内核 unmapped-inode DAC 规则正确挡住 ns-root |
| mknod 块设备（复核） | `mknod b 253 3 / b 7 0` | EPERM | 依然封死 |
| 内核攻击面工具箱 | `io_uring_setup / userfaultfd / bpf / perf_event_open / setns / ptrace / keyctl` | 全部 EPERM | 本地提权常用原语全部被 seccomp 覆盖 |
| 超时击杀绕过（exec 替身） | `exec sleep 32` | 30017ms TIMEOUT_KILLED | 进程替换不迷惑击杀逻辑 |
| 回归四件套 | sleep35 / 210MB / E2BIG×3 槽位 / 并发 | 全部与 V7 修复后行为一致 | 无退化 |

## 架构推测（v8 = v7 + 补丁）

与 v7 相同的 rootless 模型，本轮增量：① seccomp 第 7 层 = mount syscall 全族黑名单（含新 API；漏 fspick）；② 镜像系统树属主 remap 到 unmapped uid（ns-root 可读不可写），工作区保持 usera 可写；③ /proc 假文件内容动态化（loadavg 按沙箱实际进程数生成）。/opt/proc-mask 仍为 rw bind 但无人可写（unmapped）；/usr 仍 ro bind（含宿主 /usr/local 的安骑士/云监控指纹，V7 已记录，未变）。

## 修复建议

1. **seccomp 补 `fspick`**：与既有封禁意图对齐，防止未来引入 fsconfig 类配套时复活。
2. **遮蔽或收敛 /proc/sys**：至少 `core_pattern`（宿主 apport 路径）；或整目录以空/假值覆盖，与 meminfo 等同等待遇。
3. **mountinfo 泄露**：如在意宿主路径（/srv、vda3），可用同样手法以假 mountinfo 覆盖（需注意 `df`、部分工具依赖其真实性）。
4. **413**：>384KB body 回 413（第三次建议）。
5. **内核版本**：6.8.0-63（2025-06 构建）至 2026-09 已 15 个月；尽管攻击原语被 seccomp 大幅限制，仍建议跟进 Ubuntu 点版本更新。
6. **CPU 配额核验**：whoami 宣称 cpuLimit=0.5core，本轮未独立验证（内存已验证为真）；建议自测 `cpu.max` 实际生效，保持"宣称=真实"的纪律。

## 本轮测试痕迹

清理完毕：/etc/PWNED_R6 未能创建（被正确拒绝）、/home/usera/R6OK 已删、/tmp/t6* 已清。并发槽位全程健康，无持久副作用。全部流量仅指向 49.*.*.*。
