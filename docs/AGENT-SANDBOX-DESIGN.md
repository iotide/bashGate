# NAS 多租户 Agent 沙箱设计（内核级隔离方案）

> 创建于 2026-09-27 · 配套学习路线见 STUDY-ROADMAP.md（第三层结业项目）
> 设计原则：**认证在网关、权限在内核、隔离在文件系统、失控只烧自己配额**

---

## 一、目录布局与权限位

```
/agentworks/
├── share/              root:root   0755   所有租户只读（others 只有 r-x）
└── user/
    ├── userA/          userA:userA 0700   租户间完全不可见
    └── userB/          userB:userB 0700
```

**关键细节：租户目录必须 0700，不要用 0711**

- 目录的 **x 位（search permission）控制路径解析**：userA 访问 `userB/xxx` 时内核在路径穿过 userB 目录那一步直接返回 EACCES
- 0700 下错误是 EACCES 而非 ENOENT —— 扫盘脚本**连"文件是否存在"都无法探测**，零信息泄露
- 0711（x 有 r 无）会泄露路径存在性：已知路径名可以 stat 成功 —— 不要用

## 二、执行器：fork + setuid 模型（sshd 同款）

```
Agent 网关（root，只做认证：这个请求是谁）
    │ fork()
    ├─ 子进程降权：setgroups → setgid(userA) → setuid(userA)
    │             （顺序固定：先弃组再弃 uid，降完回不去）
    ├─ chdir("/agentworks/user/userA")（chroot 可选）
    └─ execve("/bin/bash", [...])
        ↓ 从此 bash 及所有子孙进程以 userA 身份运行，DAC 自动生效
```

### 三条工程红线（出事故的全栽在这）

1. **绝不 root 进程直接执行用户内容** —— 先 fork、降权、再 exec；降权必须在 exec 之前完成
2. **命令传参数组，不拼字符串** —— `execve("bash", ["-c", cmd])` 安全；`"bash -c " + userInput` 是命令注入
3. **环境变量白名单传入** —— exec 时显式构造 envp（只带 HOME/PATH/LANG），**绝不继承 root 环境**（后端的 API key 会躺在租户的 env 里）

## 三、资源限制（cgroup）：失控只烧自己

```bash
systemd-run --uid=userA --pipe \
  -p MemoryMax=512M -p MemorySwapMax=0 \     # 内存封顶，OOM 只杀该 cgroup
  -p CPUQuota=50% \                           # 最多半核
  -p TasksMax=64 \                            # 防 fork 炸弹
  -p IOReadMaxBandwidth="/dev/sda 50M" \      # 防磁盘带宽拖死他人
  -p PrivateTmp=yes \                         # 独立 /tmp
  -p ProtectProc=invisible \                  # /proc 看不见别人的进程
  -p ProtectHome=yes \                        # /root /home 不可见
  -p NoNewPrivileges=yes \                    # 阻断 setuid 提权路径
  --working-directory=/agentworks/user/userA \
  python3 agent_task.py
```

事后补限（cgroup 是活的）：`systemctl set-property <unit> MemoryMax=512M`

## 四、四种"扫盘/干扰"与对应挡法

| 扫法 | 挡法 |
|------|------|
| 直接读 userB 文件 | DAC：目录 0700，路径解析即拒绝（见第一节） |
| /proc 偷看 userB 进程参数 | `hidepid=2` 挂载 /proc，或 `ProtectProc=invisible` |
| I/O 型攻击（打满磁盘带宽） | `IOReadMaxBandwidth` / `IOWriteMaxBandwidth` |
| 空间耗尽（写满磁盘） | 文件系统配额：`setquota -u userA 0 20G 0 0 /agentworks`（cgroup 管不了磁盘空间） |

## 五、内核级隔离的能力边界（重要！）

**能确保**：任何语言（py/node/java/go/...）的正常代码与绝大多数漏洞利用（含 web RCE 后的提权尝试）**无法绕过**——检查发生在 syscall 边界，不存在"不走内核就操作文件"的代码。

**唯一例外：内核自身的漏洞**（Dirty Pipe / Dirty Cow 类内核提权）。所有租户共享同一内核，内核被打穿 = 隔离失效。这是包括 Docker 在内一切容器方案的共同边界。

### 升级阶梯（按隔离强度）

```
1. DAC + cgroup（本方案）        挡 99% 场景，零开销
2. + seccomp + ProtectSystem     收窄 syscall 面，减少可打的内核接口
3. gVisor（用户态内核）          syscall 全部经用户态拦截层
4. microVM（Firecracker/QEMU）   每租户独立内核，内核洞也逃不出 VM
```

加固习惯：NoNewPrivileges 必开（断 setuid 路）；租户进程能触达的内核接口越少，内核漏洞越难利用。

## 六、验证清单（搭好后逐条跑）

```bash
# 1. 租户互不可见
sudo -u userA ls /agentworks/user/userB     # 期待: Permission denied
sudo -u userA cat /agentworks/user/userB/*  # 期待: Permission denied

# 2. 存在性探测无信息
sudo -u userA stat /agentworks/user/userB/whatever  # 期待: EACCES（不是"不存在"）

# 3. share 只读
sudo -u userA touch /agentworks/share/x     # 期待: Permission denied

# 4. 环境隔离
sudo -u userA env | grep -i key             # 期待: 空（无 root 环境残留）
su - userA -c env | diff - <(sudo -u userA env)   # 对比两种切换方式的环境差异

# 5. 资源限制生效
sudo -u userA systemd-run --scope -p MemoryMax=100M python3 -c "x=[0]*10**9"
# 期待: 该进程被 OOM kill，系统无恙
```

## 七、性能预算与实现选型（2026-09-27 定稿）

约束：agent 命令（如 `echo 123`）忍耐度 **10ms**。

### 各方案真实延迟

| 方案 | 冷启动 | 结论 |
|------|--------|------|
| Docker | 100~300ms | ❌ |
| Firecracker microVM | ~125ms | ❌ |
| systemd-run（dbus 中转） | 10~50ms | ❌ 易被忽略的坑，只用于低频管理操作 |
| **自研 dispatcher：fork+降权+execve 直调** | **1~3ms** | ✅ |
| （参考）bash 自身初始化 | 2~5ms | 其实是最大头，优化重点不在隔离层 |

**机制 vs 工具**：隔离力来自内核原语（uid/DAC/setuid/cgroup/seccomp/rlimit/prctl），systemd-run/docker/自研 dispatcher 都只是调用同一批原语的包装，隔离效果等价，差在延迟——内核是发动机，工具是出租车/赛车。

### 零成本隔离原语清单

| 原语 | 每命令成本 | 提供 |
|------|-----------|------|
| DAC 权限位 | 0 | 目录隔离 |
| setgroups/setgid/setuid | ~3 syscall | 身份隔离 |
| rlimit（RLIMIT_AS/NPROC/CPU） | 1 syscall，fork 继承 | 单进程维度限额 |
| prctl NoNewPrivileges | 1 syscall | 断提权路 |
| 预建 cgroup.procs 写入 | 1 write | 跨进程聚合限额 |
| seccomp-bpf | 加载1次，syscall+几十ns | syscall 面收窄 |
| namespace（可选） | ~0.5ms | /tmp、/proc 视图隔离 |

### dispatcher 骨架（Python）

```python
pid = os.fork()
if pid == 0:
    os.setgroups([]); os.setgid(gid); os.setuid(uid)          # 降权（顺序固定）
    resource.setrlimit(resource.RLIMIT_AS, (512*1024*1024,)*2)
    resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
    os.prctl(prctl.PR_SET_NO_NEW_PRIVS, 1)                    # 断 setuid 路
    open(cgroup_procs_path,'w').write(str(os.getpid()))       # 进会话 cgroup
    os.chdir(homedir)
    os.execve("/bin/bash", ["bash"], whitelist_env)           # envp 白名单
```

## 八、会话级架构（已定稿：会话复用，非每命令）

会话创建付一次 10ms，会话内每条命令 <1ms（管道读写）。

### 四个会话级特有课题

1. **命令边界协议**：`cmd; echo __DONE_<uuid>_$?`，读到标记行=命令结束+退出码回传；每命令设超时，防交互/死循环卡会话
2. **孤儿回收**：网关 prctl(PR_SET_CHILD_SUBREAPER) 或 double-fork 归属 systemd；空闲超时 + 绝对时长上限双保险（如 15min 空闲 / 2h 上限）
3. **限额口径=会话**：rlimit 管不了聚合（bash+pipe 子进程），会话 cgroup 统一预算（512M/半核/会话），OOM 杀整个会话
4. **回收杀进程组**：`kill(-pgid, SIGKILL)`（bash 可能留后台子进程），确认 cgroup.procs 清空

### 生命周期状态机

```
[创建] fork→降权→进会话cgroup→exec bash   （10ms 一次）
[执行] 写stdin+标记协议+读stdout（<1ms/条，超时兜底；会话内 cwd/env 持续=特性）
[回收] 超时/关闭 → kill(-pgid) → cgroup清零 → （可选）工作目录归档
```

## 九、与学习路线的对应

## 十、实战验证记录（bashGate v1，2026-09-29 服务器实测）

**部署**：`/opt/bashgate.js`（零依赖 Node，:8080）+ systemd（TCB root，ProtectSystem=strict + NoNewPrivileges + PrivateTmp）。
租户：sandbox-a(1001) / sandbox-b(1002)，目录 0700，login→token→POST /bash{cmd,reason}→spawn(uid/gid/cwd/env白名单/10s超时/进程组kill)。

**攻击测试（sandbox-a 发起 9 项）**：

| # | 攻击 | 结果 | 拦截层 |
|---|------|------|--------|
| 1 | cat userB 机密 | ✅ Permission denied | DAC 0700 |
| 2 | ls userB 目录 | ✅ denied（存在性零泄露） | DAC |
| 3 | /etc/shadow | ✅ denied | DAC |
| 4 | 写 share | ✅ Read-only → 修 RW 后由 DAC 拒 | 双层 |
| 5 | sudo 提权 | ✅ "no new privileges flag" 直接废掉 | NoNewPrivileges |
| 6 | pkill 网关 | ✅ Operation not permitted | uid 隔离 |
| 7 | env 窃取 | ✅ 仅白名单 5 变量 | envp 白名单 |
| 8 | /tmp 投放 | ❌ **租户间共享同一 tmpfs** | 见缺口① |
| 9 | 探测本机端口 | ❌ **curl 127.0.0.1:18888 → 200** | 见缺口② |

**踩坑与修正**：
- 服务级 `ProtectSystem=strict` 连租户自目录也只读 → unit 补 `ReadWritePaths=/var/log /agentworks`（配置疏漏，自目录写恢复、share 仍被 DAC 拒）
- **PrivateTmp 语义陷阱**：它隔离"服务 vs 系统"，**不隔离"租户 vs 租户"**——所有 spawn 子进程共享同一私有 tmpfs，/tmp 成为跨租户投递通道

**缺口与升级路线（v2 待办）**：
1. 租户级 /tmp 隔离 → per-spawn mount namespace（`systemd-run --uid=X` per-session 或 `unshare -m` 包装）
2. 网络隔离（租户可达宿主全部本机端口，含网关自身 8080）→ per-spawn net namespace（`unshare -n` 仅留 lo，或 IPAddressAllow 白名单）

## 十一、v2 实测记录（2026-09-29，按产品需求重构）

**需求落地**：`/data/{share,userA,userB}` · 登录名 userA/userB（123456）→ authToken · `POST /shell {cmd, reason?}` · 30s 超时 · reason 可选仅入审计 · **cgroup v2 200M/人 + pids 64**（`/sys/fs/cgroup/bashgate/<user>/`，spawn 后写 cgroup.procs，毫秒级竞态窗口为已知权衡）· node v22 / python3 沙箱内可跑。

**验收结果**：
| 需求 | 实测 |
|------|------|
| 身份/目录 | uid=1001(usera)，cwd=/data/userA ✅ |
| node / python | `{"runtime":"node","v":"v22.23.3"}` / `python 21` ✅ |
| 自目录读写 / share 只读 | a.txt 写读 OK；userB 读取 Permission denied ✅ |
| 内存 200M/人 | 100M 分配 OK；**300M 被 cgroup OOM-kill（exitCode=null, 195ms）** ✅ |
| 超时 30s | sleep 31 → TIMEOUT_KILLED @30029ms ✅ |
| 审计 | 每条含 user/exit/dur/reason/cmd ✅ |

**实现要点**：cgroup v2 手动管理——先 `+memory +pids` 写入组级 `cgroup.subtree_control`（子组的 memory.max 文件才会出现），再设 `memory.max`；bashGate 服务沙箱由 `ProtectSystem=strict` 调整为 `full`（cgroupfs 需要写权限）。

## 十二、v4 攻防闭环（2026-09-29，红方复测 PWN-REPORT-BASHGATE-V4）

**v4 架构**（红方设计+蓝方部署协作）：unshare -m 每请求私有 mount ns（/tmp /var/tmp /dev/shm 独立 tmpfs）+ setpriv 降权链（CapEff=0 + NNP）+ 每请求 cgroup 子组（200M/pids 64/半核 + oom.group）+ cgroup.kill 必杀 + AmbientCapabilities 三能力位替代 sudo + fail-closed 启动自检。

**部署中填的四个环境坑**（全部图鉴级）：
1. no-internal-process：delegate 组内有进程时启用 controllers 必 EBUSY → 网关先自迁移进 gateway/ 子组
2. Node spawn 的 cwd chdir 失败被误报为 "spawn EACCES" → cwd 用程序目录 + 脚本首行 cd "$HOME"
3. util-linux mount 的 SUID 逻辑与 NNP 冲突（"drop permissions failed"）→ busybox mount
4. Ubuntu util-linux 2.39 无 --clear-caps，且非 root 换 uid 不自动清 caps → --clear-groups --inh-caps=-all --ambient-caps=-all

**红方复测结论**：v2 全部突破口已修复（跨租户 /tmp/审计/源码/CPU 冻结/横向面全封），防守方大胜。

**v4.2 复测遗留处置**：
- P0 磁盘无配额 → **loop 卷方案**：/srv/quota/<user>.img 各 2G ext4，挂载为租户 home（天然硬上限，fallocate 3G 实测 ENOSPC），setup 幂等开机挂载
- v2 旧审计日志（644 世界可读）→ 已删
- io_uring_disabled=1（sysctl 持久）；setup 脚本 700、unit 文件 600（布防蓝图不再可读）
- 接受项：cgroupfs 时序侧信道（元数据级）、后台进程拖响应（自伤）

**剩余升级阶梯**（共享内核天花板之上）：per-spawn user namespace（AppArmor 租户 profile）→ gVisor → microVM。

## 十三、v5 战报与 v6 容器级视角（2026-09-29 晚）

**v5 红方发现**（PWN-REPORT-BASHGATE-V5）：隔离本体全守住（文件系统/cgroup/API fuzz/资源/提权全拒），但"宿主视角"泄露——①云元数据 100.100.100.200 可达，user-data 泄露 admin 公钥+NOPASSWD sudoers（高危）②wtmp/lastlog 世界可读，管理员 IP/作息全暴露 ③token 近永续+无 logout+登录无限速 ④.bak 备份泄露架构 ⑤OLDPWD 泄露网关路径。

**设计哲学修正**（用户定调）：真正的隔离 = **租户以为独占一台操作系统**。此前是"宿主机+补丁式隔离"，改为"容器式虚拟视角"。

**v6 实现**：exec 链升级为**六命名空间**——
`unshare --mount --pid --net --ipc --uts --cgroup --fork --mount-proc`
- pid ns + proc 重挂：租户 ps 只见自己（实测 4 个进程）
- **net ns（只剩 down 的 lo）**：断网沙箱——云元数据/任意外联/本机端口全部从租户宇宙中消失（战报 1.1 结构性根治）
- uts ns：hostname=sandbox
- mount/cgroup ns：tmpfs×3 + cgroup2 ns 视图（沿用 v4.3）
- 宿主文件权限：wtmp/lastlog 661、kexec_cmd 640、.bak 移除、sysstat 收紧
- API：token TTL 1h、POST /logout、登录限速 10 次/分/IP、cwd→/data（OLDPWD 去信息量）

**实测租户视角**：uid=1001、pwd=/data/userA、hostname=sandbox、ps=4 进程、网络只有 lo（0 流量）、cgroup=0::/、/tmp=tmpfs、wtmp denied、node 正常。

## 十四、第二赛季：AI 红队六轮攻防（2026-09-29，终局）

**战绩曲线**：内存限额回归(v7 迁移竞态) → 假墙被拆(v8 ns-root 能力矛盾) → **0 洞（第六轮防守方获胜）**

**v8 终态架构**（三段式 exec 链，~70-140ms）：
```
① 带caps: self迁组(cgroup ns根=r-xxx,零竞态) → mounts+pivot_root+假文件入新根
② 降权: setpriv → usera(宿主视角), 零caps
③ userns(map-root-user 0→1001) + mount/pid/net/ipc/uts 全套二次建立
   → ns-root 重盖 /proc 假文件 ×8(含 /proc/sys 三件)
   → seccomp-wrap(31 syscall 黑名单: mount全族含新API+fspick/mknod/ptrace/bpf/...)
   → bash
```

**六轮关键修复清单**：内存限额迁移顺序(v7.1) · E2BIG 槽位 try/finally · 超时真杀(cgroup.kill) · 错误脱敏+413 · 假 /proc 假 /etc 假 /proc/sys · seccomp 层("钥匙保留锁换内核的") · 镜像 /etc unmapped 属主。

**关键教训（图鉴级）**：
1. `--cgroup` 提前到外层 → ns 根锁死 gateway → 迁移静默拒绝 → 限额全废（顺序即命门）
2. userns 的 CAP_SYS_ADMIN + 未封 mount = 拆假墙一条命令（能力与机制必须配套）
3. `mount --bind` self-bind 不递归（rbind 才带子挂载）；bind 目标须预建
4. busybox sh 的 `2>/dev/null` 重定向在链内会中止整条命令（I/O error 之谜）
5. 内核全局表(meminfo/diskstats)无 per-uid 副本——假文件 bind 是唯一原生遮蔽法

**残余（诚实终局）**：/usr ro bind 可见（标准系统文件）、mountinfo 架构痕迹、内核 6.8 共享边界（seccomp 已缩面）。**共享内核方案理论天花板达成。**


| 本方案组件 | 对应知识层 | 教材 |
|-----------|-----------|------|
| 权限位 / setuid | 第二层 | How Linux Works / 鸟哥 |
| fork/setuid/execve、envp | 第三层 | TLPI |
| cgroup / namespace | 第五层 | 深入 Linux 内核架构 |
| 沙箱原语实战 | 演练机第四课 | systemd.direct 文档 |

---

## 第十五节 · v9 密钥代理与零环境变量原则（2026-10-14 定稿）

### 演进背景（当晚实战）

- env 注入 key 的出货实测：饵放入租户 env 后 **23 秒**内被攻击者 AI `env` 全量 dump——env 是广播层,注入即交付
- 对照实验（金丝雀）：宿主真 secret（systemd `Environment=`、宿主 `/etc/environment`）**五路零泄露**——env 白名单 + pid ns + 假 rootfs 三堵墙全部站住
- 结论:防线防的是"宿主漏给租户",防不了"管理员递给租户";后者只能靠原则消灭

### v9 落地（密钥代理）

```
租户 env(与 K8s envFrom 形态逐字段一致):
  DEEPSEEK_API_KEY=broker-<user>-<exp>-<hmac>   ← 60s TTL,dump 走即死
  DEEPSEEK_BASE_URL=https://sandbox.example.com/llm
  DEEPSEEK_MODEL=deepseek-flash

网关(应用侧): /llm/* 端点 → 验 broker token(HMAC) → 注入真 key → 转发上游
真 key 全程只活: secrets/llm.key(600 webshell) + 网关内存
审计: audit.log 新增 llm 记账行(用户/IP/路径/状态码)
验证矩阵: 200 真响应 ✅ | 篡改 token 401 ✅ | 61s 过期 401 ✅ | /etc/environment 无 key ✅
```

### 零环境变量原则（终态,最高优先级架构约束）

**沙箱是纯代码执行层:命令进、结果出,无凭据、无身份、无业务环境变量。**
业务凭据归应用层;沙箱内程序需要调用外部服务时,经网关代理按需使用(占位凭证+短时 token),凭据永不进入租户可见层。

### K8s 生产映射(student-agent)

| 方案 | 改动 | 防护 |
|---|---|---|
| spawn env 白名单 + 降 uid(setpriv 65534) | 一行 | 防 env 继承 + 防 /proc/<pid>/environ 同 uid 侧信道 |
| secret volume(defaultMode 0400)替代 envFrom | YAML | env 无物可泄,应用读文件进内存 |
| bash 工具接沙箱网关(本方案靶场) | 架构 | pid ns 物理隔离 + cgroup + audit + broker 代理 |

### 遗留(Phase 2)

slirp4netns 单点网络通道:沙箱内进程直连网关代理端口(只通一跳,DNS/其余路由全无)——完成后沙箱内 agent 可持占位凭证直接调 BASE_URL,零 env 原则的完整形态。

### v9.1 · Dirty Frag 判定反转与 netlink 封禁（2026-10-14 深夜）

**事件**：CVE-2026-43284(Dirty Frag/XFRM-ESP) 攻击链要件在沙箱内实测**全部可达**——
NETLINK_XFRM socket 可建(此前误判不可用,系测试参数错误:netlink 仅支持 SOCK_RAW)、
ns 内 CAP_NET_ADMIN、lo 可被租户自行拉起后 UDP 回环收发成功、splice 可达、
/usr ro bind 提供共享 page-cache 目标、内核 6.8.0-63 无修复、公开 PoC 存在。
唯一未做的就是组装 exploit 本身——要件全活即按"可达"处置。

**缓解(已部署)**：seccomp 参数级过滤 `socket(AF_NETLINK,*) → EAFNOSUPPORT`(第 32 条规则)。
拆掉 XFRM SA 配置通道 = Dirty Frag 断链;连带拆掉 nf_tables 系列 LPE(CVE-2024-1086 等)
的配置面——netfilter 规则同样走 netlink 下发。租户 bash 不使用 netlink,零业务影响。

**意外加固**：此前每请求新 net ns 中 lo 默认 down 但租户可用 NETLINK_ROUTE 拉起
(未被发现的口子);封禁后 lo 永久 down,沙箱从"可自建回环"收紧为"绝对无网络"。

**教训两条**：
1. seccomp 黑名单按"攻击前提链"思维维护,不止封 syscall 本身,更要封配置通道(netlink 是
   XFRM/nft/路由三族 LPE 的共同咽喉);
2. 安全测试的参数错误会得出致命的错误结论(ENOTSUP 系参数不当,非权限拒绝)——
   判定生死的测试必须复核参数正确性。

**局限(诚实)**：拆链≠修洞。splice+AF_INET 仍可达,未来出现不依赖 netlink 的
page-cache write 路径(如 CopyFail CVE-2026-31431 家族)时此缓解无效。
内核升级是唯一根治,优先级：本周。
