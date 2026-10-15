# 安全手法图鉴（Tricks & Techniques）

> 学习卡片集：攻击面/伪装手法 + 对应检测方法。每一条尽量配一次真实 encounter。
> 排序按遇到时间倒序，逐渐积累成手册。

---

## 001 · svchost 藏匿（Windows 服务伪装）

**Encounter**: 2026-09-28 本机排查，抖音的 `douyin_performance_service` 用此手法常驻后台，任务管理器中只显示为普通 svchost.exe。

### 原理

Windows 服务有两种形态：
1. **独立 EXE 服务**——任务管理器里直接显示自己的进程名（好认）
2. **DLL 服务**——注册为 svchost 组的成员，由系统宿主进程 `svchost.exe -k <组名>` 加载执行

DLL 服务在任务管理器里**只显示宿主 svchost.exe**，一台机器本来就有十几个 svchost，谁也看不出第 13 个里跑的是谁。

```
注册位置：
HKLM\SYSTEM\CurrentControlSet\Services\<服务名>\Parameters
    └─ ServiceDll = "E:\Entertainment\douyin\...\xxx.dll"   ← 真身在这里
组声明：
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost
    └─ douyin_performance_service = ...                     ← 挂进哪个 -k 组
```

### 谁在用

| 使用者 | 目的 |
|--------|------|
| 微软自家服务 | 正常形态（RPC、DHCP 等大量系统服务就是 DLL 服务） |
| 商业软件（抖音/各种全家桶） | **保活 + 防卸载**——用户在任务管理器找不到它 |
| 恶意软件 | **隐蔽持久化**——混在几十个 svchost 里躲排查 |

同一个手法，三个阵营，机制完全一样——**手法无善恶，用途见人心**。

### 检测方法

```powershell
# 1. 列出每个 svchost 宿主里装着哪些服务（一键脱衣服）
tasklist /svc /fi "imagename eq svchost.exe"

# 2. 服务的真身 DLL 路径（注册表）
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\<名>\Parameters" | select ServiceDll

# 3. 对 DLL 验证数字签名（微软的才有正当性）
Get-AuthenticodeSignature "<ServiceDll路径>" | fl SignerCertificate, Status
```

**判定原则**：服务名 ↔ DLL 路径 ↔ 发布者签名，三者对应不上就有猫腻：
- 微软服务 → DLL 在 `C:\Windows\System32\` → 签名 = Microsoft
- 抖音服务 → DLL 在 `E:\Entertainment\` → 签名 = 北京字节跳动（商业诚实）
- 恶意服务 → DLL 在 `%AppData%`/`%Temp%`/怪路径 → 无签名 ⚠️

### Linux 世界的同构手法

| Windows | Linux | 一次真实 encounter |
|---------|-------|--------------------|
| 藏进 svchost | **伪装系统进程名**（起名 systemd-worker、kworker 之类） | 服务器事件：`/bin/systemd-worker` 冒充系统组件 |
| Run 键/服务自启 | systemd service / cron / rc.local | `systemd-worker.service` 开机自启 |

**通用检测公理**（跨平台适用）：

> **名字可以抄，但路径、签名/属主、父进程、行为骗不了人。**
> - Windows：签名验证、路径白名单（系统 DLL 只该在 System32）
> - Linux：`rpm -V` 校验二进制、`dpkg -V`、路径检查（正版 systemd-worker 根本不存在于 `/bin`）
> - 行为面：谁在监听/外连（`ss`）、谁在高 CPU（`ps aux --sort`）、文件 mtime 异常簇

---

## 002 · openssh 升级断链（自定义端口的隐藏耦合）

**Encounter**: 2026-09-28 服务器部署日，apt 全量升级后 SSH 断连 40 分钟。

**事故链**：自定义端口（socket override）→ 升级 openssh-server → 重启后端口配置丢失且 socket 退化为 **IPv6-only 监听**（`[::]:52121`，无 IPv4）→ IPv4 全断，SSH 溢回 22（被安全组挡）。

**检测点**：升级后验证 `ss -tlnp` 的**监听地址族**——`[::]` only = IPv4 全断，需 override 显式双栈：
```
ListenStream=0.0.0.0:52121
ListenStream=[::]:52121
```

**预防**：升级 openssh 前预设自愈（`echo 'systemctl restart ssh.socket' | at now + 10 minutes`，确认后取消）；保持已有会话不断开；控制台 VNC 永远先确认可用。

## 003 · PrivateTmp 的语义陷阱（服务级 ≠ 租户级）

**Encounter**: 2026-09-29 bashGate 沙箱攻击测试，`/tmp` 投放未被拦截。

**原理**：`PrivateTmp=yes` 创建的是**服务与系统其余部分之间**的私有 tmpfs——该服务**所有**子进程共享同一个私有 /tmp。多租户网关（每请求 spawn 子进程）场景下，租户 A 和租户 B 的 /tmp 是**同一个**：跨租户文件投递、符号链接竞争都可行。

**正确姿势**：租户间隔离需要 **per-spawn** 的 mount namespace（`systemd-run --uid=X` 每会话一单元，或 `unshare -m` 包装），而不是服务级 PrivateTmp。

**通用教训**：评估任何隔离原语时先问一句——**它隔离的边界画在哪两个主体之间？**"有隔离"不等于"隔对了地方"。

---
