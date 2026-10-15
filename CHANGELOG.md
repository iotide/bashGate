# Changelog

本项目的演进由真实的红队攻防驱动：每个版本背后对应一轮渗透测试，
战报见 `docs/pwn-reports/`（脱敏版）。

## [11.0] - 2026-10-15

### 新增(红队建议采纳:AppArmor 现役)
- **AppArmor 路径级防线**:profile 附着于租户专用 bash 副本,ix 继承确保子进程
  不逃逸;deny 宿主敏感路径(/software、/root、shadow、/var/log、跨租户卷)
  作为 mount 布局漂移的兜底保险。
- complain 先行三阶段:观察 → 规则补齐(/home/** rwk、/usr/** mr) → enforce。
- 关键实证:AppArmor mediation 路径按沙箱 mount ns 视图(bind 后是
  /home/usera 而非宿主路径)——规则必须按沙箱视图书写。
- 与 seccomp v10(syscall 级)互补:fd 路径类访问由路径 mediation 兜底。

## [10.0] - 2026-10-15

### 变更（红队建议采纳：黑名单→白名单）
- **seccomp 白名单模式**：默认全部 ENOSYS，仅放行约 150 个 shell/python3/node
  运行必需 syscall。新内核新 syscall 默认不可达（fail-closed）。
- **socket 按地址族参数级管理**：AF_UNIX/INET/INET6 放行、AF_NETLINK 拒绝、
  其余（含 AF_PACKET 原始套接字）默认拒绝——嗅探面连带关闭。
- **/proc/sys/kernel/sysrq 遮蔽**：假值 0 + immutable（红队实测被 DAC 挡后建议）。
- proc-mask 全目录 `chattr +i`：配置漂移不再能复活 core_pattern 逃逸链。

### 踩坑记录（重要）
- libseccomp 中"通配 allow + 参数级 deny"共存时，通配规则会使参数级 deny
  **静默失效**（两轮部署实测）——socket 类规则必须全部参数级化。
- ENOSYS 默认拒绝的开发反馈极佳：ls 的 xattr 探测第一时间暴露缺漏。

## [9.1] - 2026-10-15

### 安全
- **seccomp 第 32 条规则**：参数级封禁 `socket(AF_NETLINK)` → EAFNOSUPPORT。
  源于 CVE-2026-43284（Dirty Frag / XFRM-ESP）可达性判定反转：攻击链要件
  （NETLINK_XFRM / ns 内 CAP_NET_ADMIN / lo 可拉起 / splice / 共享 page-cache
  目标）在沙箱内实测全部可达，封 netlink 一环拆链，同时连带拆除 nf_tables
  系列 LPE（CVE-2024-1086 等）的配置面。
- 意外加固：此前每请求新 net ns 中 `lo` 可被租户拉起（未记录的口子），
  现因 netlink 封禁而永久 down，沙箱收敛为绝对无网络。

## [9.0] - 2026-10-14

### 新增
- **LLM 密钥代理**（`/llm/*` 端点）：租户 env 中只见 60s TTL 的 HMAC
  broker token，真 key 只活在网关内存（`secrets/` 600 权限），转发上游时
  瞬时注入。支持 anthropic 协议透传。
- **零环境变量原则**定稿：沙箱为纯代码执行层，env 层永不承载业务凭据。
- `env-bait.json` 机制：租户 env 诱饵配置（用于靶场运营/金丝雀监控）。
- 443 部署方案：nginx TLS 前置（413/限流/慢连接超时）+ endlessh tarpit（22 端口）。

### 修复
- exec 链 `cd /` 后 `unset OLDPWD`：PID1 environ 不再泄露宿主路径
  （`/data/<tenant>/.root`），AI 红队第 7 轮实证发现。
- nginx 反代后登录限速改用 X-Real-IP（socket 全为 127.0.0.1 导致限额
  全局共享的回归）。

## [8.1] - 2026-09-29

### 修复
- spawn 同步异常（E2BIG 等）路径补 try/finally 释放并发槽位——此前
  3 次失败请求可永久锁死账号（AI 红队第 4 轮实证）。

## [8.0] - 2026-09-29

### 安全（第 6 轮攻防：防守方获胜，0 漏洞）
- seccomp 封禁 mount 全族（mount/umount2/pivot_root/move_mount/open_tree/
  fsopen/fsconfig/fsmount/mount_setattr/fspick）——关闭 ns-root 拆除
  /proc 假文件墙的路径（第 5 轮主突破口）。
- 镜像系统目录属主 remap 至 unmapped uid：ns-root 的 CAP_DAC_OVERRIDE
  对 unmapped inode 无效，/etc 恢复不可写。
- 假 proc 文件内容动态化（loadavg 按沙箱实际进程数生成）。

## [7.0] - 2026-09-29

### 重构（rootless 化）
- 执行模型切换至用户命名空间 root（单值 uid_map `0→1001`）+ 全量 ns 能力。
- env 白名单：spawn 不继承网关环境（OLDPWD 泄露教训）。
- cgroup v2 两段式（先 self 迁入请求组，再建 cgroup ns）——限额真生效
  （含 tmpfs 内核内存），30s 超时 `cgroup.kill` 必杀。

## [6.0] - 2026-09-29
### 修复（第 3 轮报告 6 项全闭环）
- 假 /proc 假文件墙（meminfo/loadavg/stat/diskstats/uptime）、宿主 /etc
  摘除、超时真杀、内存限额、E2BIG 槽位、审计三轨制（audit.log + journal
  副本 + logrotate）。

## [5.0] - 2026-09-29
### 重构
- systemd 沙箱原语（ProtectSystem/ProtectHome/PrivateTmp/Delegate）、
  网关降权至专用用户、loop 卷硬配额（每租户 2G ext4）。

## [4.0] - 2026-09-28
- 租户专属 rootfs 骨架（`.root` + pivot_root）、审计日志、hidepid。

## [1.0–3.0] - 2026-09-27
- 项目诞生：一台服务器被僵尸网络入侵后的应急响应产物。初始形态为
  chroot + AppArmor（见 docs/V3.1-CODE-REVIEW）。

[9.1]: https://example.com/compare/v9.0...v9.1
