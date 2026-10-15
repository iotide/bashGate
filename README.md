# bashGate

**多租户 bash 沙箱**——为 AI Agent 的 shell 执行提供一堵打不穿的墙。

在共享内核的单机上安全执行不可信命令：namespace 六件套 + pivot_root 假文件树 +
cgroup 记账 + seccomp 黑名单 + 零环境变量原则。经九轮红队攻防（人类 + AI Agent
攻击者）实测收敛至零洞，全部战报公开。

> 出身：一台服务器被僵尸网络入侵后的应急响应产物——设计文档的叙事从那次入侵取证开始。

## 威胁模型

**防住**（历轮实测）：

| 攻击面 | 防线 | 实测 |
|---|---|---|
| 跨租户文件读取 | 每租户独立 loop 卷（2G ext4）+ 独立 tmpfs | 七轮红队未破 |
| 宿主信息泄露 | 假 /proc、假 /etc、env 白名单、pid/net ns | 金丝雀五路零泄露 |
| 资源耗尽 | cgroup（200M / 0.5 核 / 并发槽）、loop 硬配额 | 210MB / 30 万 fd 均被杀 |
| 挂载类逃逸 | seccomp 封 mount 全族（新旧 API） | umount 拆假墙路径已关闭 |
| 网络面 | 绝对无网络（netlink 封禁，lo 永久 down） | nf_tables / Dirty Frag 链条不可达 |
| 凭据外带 | 零 env 原则：租户只见 60s broker token | 真 key 从不进入租户可见层 |

**不防**（诚实清单）：内核 0day——共享内核方案的固有残余，对策是跟补丁 +
seccomp 拆前提（方法论见设计文档"Dirty Frag 判定反转"一节）；网关自身代码
漏洞——欢迎来打，见 [SECURITY.md](SECURITY.md)。

## 架构

```
POST /shell {cmd}
  │
  ▼
网关 (Node, 专用用户): 认证 → 并发槽(3/用户) → 每请求 cgroup 子组
  │
  ▼  三段式 exec 链
unshare --mount ──► self 迁入请求 cgroup ──► unshare --cgroup
  │   make-rprivate / usr ro-bind / 假 proc 文件入位 / tmpfs×3 / workspace bind
  ├─ pivot_root（新根 = 租户卷内 .root，旧根立即卸载）
  ├─ setpriv 降权 ──► unshare --user --map-root-user --pid --net --ipc --uts
  └─ busybox sh 重盖 /proc 假文件 ──► exec seccomp-wrap(32 条黑名单) bash -c
                                             │
租户视角: uid=0(root), hostname=sandbox,     │
          MemTotal 204800kB —— 全是假的      ▼
                               LLM 调用经 /llm 代理（broker token 60s）
```

## 目录结构

```
src/       app.js 启动入口 + bashgate.js 网关核心（npm start，零 npm 依赖）
native/    seccomp-wrap.c —— 32 条 syscall 封禁的 C 源（部署时编译）
config/    env-bait.json —— 租户 env 饵配置（已脱敏，占位值）
deploy/    systemd 单元 ×2 / rootfs 构建脚本 / apparmor 历史件 / 443+endlessh 部署
tools/     红队客户端（tui-shell）
docs/      设计文档(15节) / 入侵应急响应 / 攻击手法图鉴 / 挑战书 / 七轮战报
           CANARY-REGISTRY.md 为防守方内部件（已 gitignore，勿提交）
archive-r4/  v4 时代红队测试残骸
backups/    服务器取证备份（已 gitignore，勿入库）
```

> **关于 challenges / pwn-reports**：均为靶场运营与历轮攻防的原始记录，
> 已对 IP、域名、个人出口 IP、实例指纹等敏感信息做脱敏抹除（服务器 IP
> 以 `49.*.*.*` 形式呈现，域名以 `sandbox.example.com` 占位）。

## 快速开始

```bash
# 1. 构建 rootfs 与租户卷，安装 systemd 单元（deploy/bashgate-setup.sh）
# 2. 编译 seccomp 过滤器
gcc -O2 -o /usr/local/sbin/seccomp-wrap native/seccomp-wrap.c -lseccomp
# 3. 启动
npm start
# 4. （可选）443 + endlessh tarpit 一键部署：占位符替换为你的值后执行
sed -i 's/<YOUR_SERVER_IP>/1.2.3.4/; s/sandbox.example.com/your.domain/' deploy/deploy-443.sh
```

```bash
# 使用
TOKEN=$(curl -s -X POST https://your.domain/login -H 'Content-Type: application/json' \
  -d '{"user":"userA","pass":"123456"}' | grep -oP '(?<="authToken":")[a-f0-9]+')

curl -s -X POST https://your.domain/shell \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"cmd":"id; ls -la"}'
```

租户 env 中的 LLM 凭据为 60 秒短时 token，经 `/llm/*` 代理转发上游（真 key
只在网关内存）。`config/env-bait.json` 可配置诱饵变量（靶场运营用）。

## 文档

- [设计文档（15 节全档）](docs/AGENT-SANDBOX-DESIGN.md)——威胁模型、三段式
  exec 链、v9 密钥代理、零环境变量原则、Dirty Frag 判定反转
- [七轮攻防战报](docs/pwn-reports/)——每次修复背后的真实攻击记录
- [攻击手法图鉴](docs/SECURITY-TRICKS.md)
- [CHANGELOG](CHANGELOG.md)——v1 到 v9.1 的完整演进

## 免责声明

本项目仅用于**授权测试环境**：你自己的服务器、你运营的公开靶场、或获得
书面授权的目标。将 bashGate 用于未授权访问他人系统所产生的一切后果，与
本项目作者无关。租户视角下的"完整操作系统"是刻意营造的隔离体验，不是
真实权限。

## License

[MIT](LICENSE)
