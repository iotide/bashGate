# bashGate v4 部署与自检（2026-09-29）

> v4 = 视图隔离（每请求独立 mount ns）+ 特权面归零（NNP 恢复 + 全量弃权能）+ 资源硬隔离（每请求 cgroup + cgroup.kill 必杀）
> 逐项对应两轮攻击实证的缺口，每条修复都附"攻击者视角"自检命令——部署完照跑一遍，跑过才算修好。

---

## 一、文件清单与去向

| 本目录文件 | 服务器去向 | 变更 |
|-----------|-----------|------|
| bashgate.js | /software/web-shell/bashgate.js | **重写**：sudo 链 → unshare+setpriv exec 链；每请求 cgroup 子组；cgroup.kill 超时；启动自检 fail-closed |
| bashgate.service | /etc/systemd/system/bashgate.service | Delegate=+cpu；AmbientCapabilities 三能力位；NoNewPrivileges=yes 恢复；CPUQuota/TasksMax 兜底 |
| bashgate-setup.sh | /usr/local/sbin/bashgate-setup.sh | audit 600（保留）；家目录对齐；/proc hidepid=2；**清除 sudoers 残片** |
| bashgate-setup.service | （不变） | —— |
| sudoers-webshell | **删除**（服务器与本地） | AmbientCapabilities 方案下 sudo 链整体废弃 |
| apparmor-tenant | 可选：/etc/apparmor.d/bashgate.tenant | 附录，默认不启用（策略层锦上添花） |

## 二、部署步骤（root）

```bash
# 0) 备份现网版本
cp -a /software/web-shell /software/web-shell.bak-$(date +%s)
cp /etc/systemd/system/bashgate.service /etc/systemd/system/bashgate.service.bak

# 1) 放置新文件（scp 上传后）
install -m 644 bashgate.service   /etc/systemd/system/bashgate.service
install -m 755 bashgate-setup.sh  /usr/local/sbin/bashgate-setup.sh
install -m 644 bashgate.js        /software/web-shell/bashgate.js
chown webshell:webshell /software/web-shell/bashgate.js

# 2) 跑初始化(audit/tmp/家目录/hidepid/清 sudoers)
systemctl daemon-reload            # ★ v3.1 的教训:不 reload 等于白改
systemctl restart bashgate-setup.service
systemctl restart bashgate.service

# 3) 起来了没有(cgroup 自检失败会拒绝启动并打日志——这是故意的 fail-closed)
systemctl status bashgate.service --no-pager
journalctl -u bashgate -n 20 --no-pager
```

**注意**：
- `systemctl show bashgate -p Delegate --value` 必须输出 `memory pids cpu`。若还是空，说明 daemon-reload 没吃进去——v3.1 的"限额静默失效"就是这个原因。
- 不要给这个 unit 加 `ProtectControlGroups=yes` 或 `ProtectKernelTunables=yes`，会把 /sys/fs/cgroup 变只读、打断委派写。
- hidepid=2 对全机非 root 用户生效（eatwhat 也受影响），属预期。

## 三、自检清单（每条 = 一个曾经的攻击）

```bash
T=$(curl -s -X POST http://127.0.0.1:8080/login -H 'Content-Type: application/json' \
  -d '{"user":"userA","pass":"123456"}' | grep -oP '(?<="authToken":")[a-f0-9]+')
sh() { curl -s -X POST http://127.0.0.1:8080/shell -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d "{\"cmd\":\"$1\"}"; }
```

| # | 曾经的攻击 | 自检命令 | 期望 |
|---|-----------|---------|------|
| 1 | 跨租户 /tmp 投递 | userA: `echo A > /tmp/x`; userB: `cat /tmp/x` | **No such file**（每请求私有 tmpfs） |
| 2 | 跨租户读 /dev/shm | 同上换 /dev/shm | No such file |
| 3 | setsid 死循环超时杀不掉 | `setsid bash -c 'while :; do :; done' & sleep 1; pgrep -c -f "while"`，31s 后再 pgrep | **0**（cgroup.kill 必杀） |
| 4 | CPU 打满冻结整机 | 起 8 个死循环观察 loadavg | ≤1.5（半核/请求 + 服务 150% 双层封顶） |
| 5 | 每请求 CPU 限额存在 | `cat /sys/fs/cgroup/system.slice/bashgate.service/usera/*/cpu.max` | `50000 100000` |
| 6 | 内存 OOM 波及网关 | `python3 -c "x=bytearray(300*2**20)"` | 进程被杀、**网关存活**（200M/请求 + oom.group） |
| 7 | SUID 复活 | `grep NoNewPrivs /proc/self/status`; `su userb` 尝试 | NoNewPrivs **1**；su 失败 |
| 8 | /proc 全机裸奔 | `ls /proc \| grep -cE "^[0-9]+$"` | 数字骤减（只剩自己+内核） |
| 9 | 审计日志跨租户可读 | `cat /var/log/bashgate-audit.log`、`ls -l /software/web-shell/logs/audit.log` | 旧路径不存在；新文件 600 webshell |
| 10 | 读宿主其他服务数据 | `cat /www/wwwroot/eat-what/.env` | Permission denied |
| 11 | /data/userB 直读 | `ls /data/userB` | Permission denied（DAC 保持） |
| 12 | fs 视图确认 | `grep -E " /tmp \| /dev/shm " /proc/self/mounts` | 两行都是 **tmpfs**（不再是 vda3 ext4） |
| 13 | 快速可用性 | `echo ok`；`node -v`；`python3 -c "print(1)"` | 正常（<100ms 量级） |

## 四、v4 架构一页纸

```
HTTP /login → token(内存 Map, 2h)
HTTP /shell → 每请求:
  ├─ cgroup: /sys/fs/cgroup/system.slice/bashgate.service/<user>/r-<tag>/
  │          memory.max=200M pids.max=64 cpu.max=半核 oom.group=1
  ├─ exec 链(同一 PID, 零竞态):
  │    /usr/bin/unshare -m --propagation private     ← 独立 mount ns,阻断挂载回传
  │      └→ mount --make-rprivate /
  │      └→ mount tmpfs /tmp /var/tmp /dev/shm       ← 租户间临时文件互不可见
  │      └→ exec setpriv --reuid=1001 --regid=1001 --clear-caps --no-new-privs
  │            └→ bash -c "<cmd>"                    ← cwd=/data/userA, env 白名单
  ├─ 超时 30s → 写 cgroup.kill(uid 无关必杀,含 setsid) → 信号兜底
  └─ 审计 → logs/audit.log (600 webshell)
网关自身: webshell 用户, 仅 CAP_SYS_ADMIN/SETUID/SETGID, NNP=yes,
          ProtectSystem=full + ProtectHome=yes, CPUQuota=150% + MemoryMax=900M
残余边界: 内核自身漏洞(所有容器方案共同天花板); 租户互访由 DAC 0700(未变)
```

## 五、回滚

```bash
cp /etc/systemd/system/bashgate.service.bak /etc/systemd/system/bashgate.service
cp -a /software/web-shell.bak-<ts>/. /software/web-shell/
systemctl daemon-reload && systemctl restart bashgate
mount -o remount /proc    # 去掉 hidepid(或编辑 fstab 后重启)
```
