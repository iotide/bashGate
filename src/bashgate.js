// bashGate v4 —— 多租户受限 shell 网关（视图隔离 + 特权面归零 + 资源硬隔离）
//
// v4 三大支柱（对应攻击报告 P0）:
//   1. 视图隔离: 每次执行 unshare -m 独立 mount ns(--propagation private 防挂载回传宿主),
//      /tmp /var/tmp /dev/shm 换成请求私有 tmpfs —— 租户间临时文件彻底不可见
//   2. 特权面归零: NoNewPrivileges=yes 恢复 + setpriv 全量弃权能 → 租户内 SUID 全废
//      (v3 的 sudo 路径废弃; 网关凭 AmbientCapabilities 的 CAP_SETUID/SETGID 直接降权)
//   3. 资源硬隔离: 每请求独立 cgroup 子组(memory/pids/cpu) + 启动自检失败即拒绝服务
//      + 超时用 cgroup.kill 必杀(v3.1 的 process.kill 对 ruid=1001 进程是 EPERM,已废弃)
//
// 执行链(关键设计): unshare → sh(mount) → setpriv → bash 全程 exec 同一 PID,
// 因此写一次 cgroup.procs 即覆盖整条链,零竞态; bash 之后 fork 的孙进程天然继承所在组。
//
// 网关自身: webshell 用户 + 仅 CAP_SYS_ADMIN/SETUID/SETGID 三个能力位(特权原语集中地)。
const http = require('http');
const https = require('https');
const { spawn } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const { execSync } = require('child_process');

const PORT = 8080;
const CMD_TIMEOUT_MS = 30_000;
const OUTPUT_LIMIT = 128 * 1024;
const SESSION_TTL_MS = 60 * 60 * 1000; // v6: 1h(战报:token 近乎永续)
const MAX_CONCURRENT_PER_USER = 3;
// 部署根目录(可用环境变量 BASHGATE_HOME 覆盖,默认与生产 systemd 单元一致)
const APP_ROOT = process.env.BASHGATE_HOME || '/software/web-shell';
const AUDIT_LOG = APP_ROOT + '/logs/audit.log';
const CGROOT = '/sys/fs/cgroup/system.slice/bashgate.service'; // Delegate= 委派给 webshell 的组

const MEM_LIMIT = '209715200';        // 200M / 请求(租户级同值聚合)
const PIDS_LIMIT = '64';              // 64 / 请求(租户级聚合同值)
const CPU_LIMIT = '50000 100000';     // 半核 / 请求
const TENANT_CPU_LIMIT = '100000 100000'; // 租户聚合 1 核
const TMP_SIZE = '64m';               // 私有 /tmp /dev/shm 容量
// 租户 shell 路径。v11: AppArmor profile 附着点(宿主bash副本,pivot后新根内可见)
const TENANT_SHELL = '/usr/local/bin/tenant-bash';

// 登录名 → {pass, sysUser(系统用户), home}
const USERS = {
  'userA': { pass: '123456', sys: 'usera', home: '/data/userA' },
  'userB': { pass: '123456', sys: 'userb', home: '/data/userB' },
};
const UIDS = {}; // sysUser -> {uid, gid}

const CONTROLLERS = ['memory', 'pids', 'cpu'];

function readList(f) { try { return fs.readFileSync(f, 'utf8'); } catch (_) { return ''; } }

// ===== cgroup 初始化: 委派自检 + 控制器启用,失败即拒绝启动(fail-closed) =====
function ensureCgroups() {
  const problems = [];
  const rootSub = `${CGROOT}/cgroup.subtree_control`;
  // v4.1: no-internal-process 约束 —— 组内有进程时启用 subtree_control 必 EBUSY。
  // 网关先把自己迁入子组, 腾空本组后再启用控制器(lxc/docker 委托后的标准姿势)
  try {
    const selfDir = `${CGROOT}/gateway`;
    fs.mkdirSync(selfDir, { recursive: true });
    fs.writeFileSync(`${selfDir}/cgroup.procs`, String(process.pid));
  } catch (e) { problems.push(`self-migrate: ${e.message}`); }
  for (const c of CONTROLLERS) {
    if (!readList(rootSub).includes(c)) {
      try { fs.writeFileSync(rootSub, `+${c}`); } catch (e) { problems.push(`root subtree_control +${c}: ${e.message}`); }
    }
  }
  for (const u of Object.values(USERS).map(x => x.sys)) {
    const dir = `${CGROOT}/${u}`;
    try {
      fs.mkdirSync(dir, { recursive: true });
      // 租户组下还要建请求级子组 => 租户组自身的 subtree_control 也需启用控制器
      for (const c of CONTROLLERS) {
        if (!readList(`${dir}/cgroup.subtree_control`).includes(c)) fs.writeFileSync(`${dir}/cgroup.subtree_control`, `+${c}`);
      }
      fs.writeFileSync(`${dir}/memory.max`, MEM_LIMIT);
      fs.writeFileSync(`${dir}/pids.max`, PIDS_LIMIT);
      fs.writeFileSync(`${dir}/cpu.max`, TENANT_CPU_LIMIT);
    } catch (e) { problems.push(`${u}: ${e.message}`); continue; }
    if (!fs.existsSync(`${dir}/memory.max`)) problems.push(`${u}: memory.max 缺失——Delegate 未生效(检查 daemon-reload)`);
  }
  return problems;
}

function ensureAuditFile() {
  try {
    if (!fs.existsSync(AUDIT_LOG)) fs.writeFileSync(AUDIT_LOG, '');
    fs.accessSync(AUDIT_LOG, fs.constants.W_OK);
  } catch (e) { return `audit不可写: ${e.message}`; }
  return null;
}

// ===== 会话 =====
const sessions = new Map();
const loginRate = new Map(); // v6: ip -> [时间戳] 滑动窗口
function createSession(user) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { user, expires: Date.now() + SESSION_TTL_MS });
  return token;
}
function authSession(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (Date.now() > s.expires) { sessions.delete(token); return null; }
  return s.user;
}

function audit(user, reason, cmd, exitCode, durMs) {
  const line = `${new Date().toISOString()} user=${user} exit=${exitCode} dur=${durMs}ms reason="${String(reason || '').replace(/"/g, "'").slice(0, 200)}" cmd="${String(cmd).replace(/"/g, "'").slice(0, 500)}"\n`;
  fs.appendFile(AUDIT_LOG, line, () => {});
  process.stdout.write('[audit] ' + line); // 副本进 journald(root才能删,防篡改)
}

// v9: SQLite 全量留痕(执行+结果+来源IP) —— logs/audit.db, 事后 SQL 追查
//     node:sqlite 内置模块,失败仅降级为文本日志,不阻断业务
let db = null;
try {
  const { DatabaseSync } = require('node:sqlite');
  db = new DatabaseSync(AUDIT_LOG.replace(/audit\.log$/, 'audit.db'));
  db.exec(`CREATE TABLE IF NOT EXISTS ops (id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, type TEXT NOT NULL, user TEXT, ip TEXT, cmd TEXT,
    exit_code TEXT, dur_ms INTEGER, output TEXT)`);
  db.exec('CREATE INDEX IF NOT EXISTS idx_ops_ts ON ops(ts); CREATE INDEX IF NOT EXISTS idx_ops_user ON ops(user);');
} catch (e) { console.error('[db] sqlite 不可用,仅文本日志:', e.message); }
function dbLog(type, user, ip, cmd, exitCode, durMs, output) {
  if (!db) return;
  try {
    db.prepare('INSERT INTO ops (ts,type,user,ip,cmd,exit_code,dur_ms,output) VALUES (?,?,?,?,?,?,?,?)')
      .run(new Date().toISOString(), type, user || '', ip || '',
           cmd == null ? '' : String(cmd).slice(0, 2048),
           exitCode == null ? null : String(exitCode),
           durMs == null ? null : (Number(durMs) || 0),
           output == null ? null : String(output).slice(0, 65536));
  } catch (_) {}
}

// v9: 环境变量层饵 —— env-bait.json 注入租户 env(root/webshell 才可读,租户只见值不见文件)
let ENV_BAIT = {};
try { ENV_BAIT = JSON.parse(fs.readFileSync(APP_ROOT + '/env-bait.json', 'utf8')); }
catch (e) { console.warn('[env-bait] 未加载:', e.message); }

// v9: LLM 密钥代理 —— 真 key 只活在网关内存,租户 env 里只见 60s 短时 broker token
//   形态与 K8s envFrom secretRef 完全一致(变量名不变),dump 走的 token 出沙箱即死
const SECRET_DIR = APP_ROOT + '/secrets';
let BROKER_SECRET = '';
try { BROKER_SECRET = fs.readFileSync(`${SECRET_DIR}/broker-hmac.key`, 'utf8').trim(); }
catch (_) { console.warn('[llm-proxy] broker-hmac.key 未配置,/llm 代理将不可用'); }
let LLM_REAL_KEY = '';
try { LLM_REAL_KEY = fs.readFileSync(`${SECRET_DIR}/llm.key`, 'utf8').trim(); }
catch (_) { console.warn('[llm-proxy] 上游 key 未配置,/llm 将返回 503'); }
const LLM_UPSTREAM = 'https://newai.istudy.xin';

function mintBrokerToken(user, ttlMs = 60_000) {
  const exp = Date.now() + ttlMs;
  const sig = crypto.createHmac('sha256', BROKER_SECRET).update(`${user}.${exp}`).digest('base64url');
  return `broker-${user}-${exp}-${sig}`;
}
function verifyBrokerToken(tok) {
  const m = /^broker-(\w+)-(\d+)-([\w-]+)$/.exec(tok || '');
  if (!m) return null;
  if (Date.now() > +m[2]) return null; // 过期即废:dump 走也无意义
  const want = crypto.createHmac('sha256', BROKER_SECRET).update(`${m[1]}.${m[2]}`).digest('base64url');
  return (m[3] === want && USERS[m[1]]) ? m[1] : null;
}

// ===== 每请求 cgroup 子组 =====
function createReqCgroup(sysUser, tag) {
  const dir = `${CGROOT}/${sysUser}/r-${tag}`;
  fs.mkdirSync(dir);
  fs.writeFileSync(`${dir}/memory.max`, MEM_LIMIT);
  fs.writeFileSync(`${dir}/pids.max`, PIDS_LIMIT);
  fs.writeFileSync(`${dir}/cpu.max`, CPU_LIMIT);
  try { fs.writeFileSync(`${dir}/memory.oom.group`, '1'); } catch (_) {} // OOM 时整请求组灭,不殃及网关
  return dir;
}
function killReqCgroup(dir) {
  try { fs.writeFileSync(`${dir}/cgroup.kill`, '1'); } catch (_) {}
}

// ===== 核心: 视图隔离 + 降权 + 限额执行 =====
const running = new Map();
function runAsTenant(loginUser, cmd, onDone) {
  const conf = USERS[loginUser];
  if (!UIDS[conf.sys]) return onDone({ exitCode: 'TENANT_UNAVAILABLE', durMs: 0, output: `系统用户 ${conf.sys} 未配置(见启动日志),该租户不可执行` });
  const { uid, gid } = UIDS[conf.sys];

  // 每请求独立 cgroup: 建不起来 = 限额承诺失效 => 拒绝执行(fail-closed)
  const tag = crypto.randomBytes(6).toString('hex');
  let cgDir;
  try { cgDir = createReqCgroup(conf.sys, tag); }
  catch (e) {
    audit(loginUser, 'CGROUP_FAIL', e.message, '-', 0);
    return onDone({ exitCode: 'CGROUP_FAIL', durMs: 0, output: `sandbox init failed: ${e.message}` });
  }

  const rt = conf.home + '/.root'; // v7: 租户专属根(pivot_root 目标)
  // env 白名单(不继承 webshell 环境); v7: HOME/TMPDIR 均为新根内视角
  const env = {
    HOME: `/home/${conf.sys}`, PATH: '/usr/local/bin:/usr/bin:/bin',
    LANG: 'C.UTF-8', TERM: 'dumb', TMPDIR: '/tmp',
    DOUBAOAPIKEY: '你上当了，这里没有', // 饵:环境变量勘察时的嘲讽(见 CANARY-REGISTRY)
    ...ENV_BAIT, // v9: env-bait.json 的诱饵(DOUBAO/ARK/CLAUDE)
    DEEPSEEK_API_KEY: mintBrokerToken(loginUser), // v9: 覆盖静态值——每请求 60s 短时代理凭证,真 key 不再进 env
  };

  // v7.1: 两段式脚本 —— 顺序是 cgroup 限额的命门:
  //   第一段(还在初始 cgroup ns + 带 ambient CAP_SYS_ADMIN): self 迁入请求组
  //   第二段 unshare -C: 迁移完成后再建 cgroup ns(根=r-xxx, 租户只见 0::/)
  //   (v7 曾把 --cgroup 提到最外层 → ns 根锁在 gateway → 迁移被静默拒绝 → 限额失效)
  // v8: userns 终极形态 —— 三段式(顺序即命门):
  //   ① 带caps: self迁组 → cgroup ns → mounts+pivot+proc挂+假文件入新根
  //   ② 降权到 usera(零caps, 不带NNP——userns创建需要)
  //   ③ userns(map-root-user) + 全套ns二次建立 → ns内root重盖假proc → bash
  //      mount ns 归属新 userns → 租户在自己世界里是 root(容器体验)
  const inner =
    `/bin/busybox mount --make-rprivate / && ` +
    `/bin/busybox mount -o remount,rw / 2>/dev/null; ` +
    `/bin/busybox mount --rbind -o ro /usr ${rt}/usr && ` +
    `/bin/busybox mount --bind /srv/proc-mask ${rt}/opt/proc-mask && ` +
    `/bin/busybox mount -t tmpfs -o mode=1777,size=${TMP_SIZE} tmpfs ${rt}/tmp && ` +
    `/bin/busybox mount -t tmpfs -o mode=1777,size=32m tmpfs ${rt}/var/tmp && ` +
    `/bin/busybox mount -t tmpfs -o mode=1777,size=32m tmpfs ${rt}/dev/shm && ` +
    `/bin/busybox mount --rbind /dev/null ${rt}/dev/null && ` +
    `/bin/busybox mount --rbind /dev/zero ${rt}/dev/zero && ` +
    `/bin/busybox mount --rbind /dev/random ${rt}/dev/random && ` +
    `/bin/busybox mount --rbind /dev/urandom ${rt}/dev/urandom && ` +
    `/bin/busybox mount --bind ${conf.home}/workspace ${rt}/home/${conf.sys} && ` +
    `/bin/busybox mount --rbind ${rt} ${rt} && ` +
    `cd ${rt} && ` +
    `/bin/busybox pivot_root . .oldroot && ` +
    `/bin/busybox umount -l /.oldroot && ` +
    `cd / && unset OLDPWD && ` + // 抹掉链条 cd 痕迹,防 PID1 environ 泄露宿主路径(AI红队第7轮实证)
    `/bin/busybox mount -t proc proc /proc && ` +
    `hostname sandbox && ` +
    `exec /usr/bin/setpriv --reuid=${uid} --regid=${gid} --clear-groups --inh-caps=-all --ambient-caps=-all ` +
    `/usr/bin/unshare --user --map-root-user --mount --pid --net --ipc --uts --fork --mount-proc ` +
    `/bin/busybox sh -c "mkdir -p /proc/sys/kernel 2>/dev/null; /bin/busybox mount --bind /opt/proc-mask/meminfo /proc/meminfo; /bin/busybox mount --bind /opt/proc-mask/loadavg /proc/loadavg; /bin/busybox mount --bind /opt/proc-mask/stat /proc/stat; /bin/busybox mount --bind /opt/proc-mask/diskstats /proc/diskstats; /bin/busybox mount --bind /opt/proc-mask/uptime /proc/uptime; /bin/busybox mount --bind /opt/proc-mask/core_pattern /proc/sys/kernel/core_pattern; /bin/busybox mount --bind /opt/proc-mask/dmesg_restrict /proc/sys/kernel/dmesg_restrict; /bin/busybox mount --bind /opt/proc-mask/unprivileged_userns_clone /proc/sys/kernel/unprivileged_userns_clone; /bin/busybox mount --bind /opt/proc-mask/sysrq /proc/sys/kernel/sysrq; exec /usr/local/sbin/seccomp-wrap ${TENANT_SHELL} -c \\"\\$1\\" --" inner3 "$1"`;
  const mountScript =
    `echo $$ > ${cgDir}/cgroup.procs 2>/dev/null && ` +
    `exec /usr/bin/unshare --cgroup /bin/sh -c '${inner}' sh-inner "$1"`;

  // v7: pivot_root 换根 —— 租户的 "/" 是他卷内的 .root 骨架,宿主其他目录
  //     tmpfs 挂载点全部物理位于租户卷内(用户明确要求)。
  //     旧根 pivot 后立即卸载,断掉一切回望路径。
  const t0 = Date.now();
  const wrappedCmd = `cd -- "$HOME"\n` + cmd;
  // v8: 外层仅需 mount ns(bind/pivot 用); pid/net/ipc/uts/user 全移入
  //     第三段 userns 内建立(mount ns 归属新 userns → 租户容器式 root)
  // v8.1: spawn 同步异常(E2BIG等)路径必须释放槽位 —— 否则3次请求永久锁死账号(AI红队实证)
  let child;
  try {
    child = spawn('/usr/bin/unshare',
      ['--mount', '--propagation', 'private', '/bin/sh', '-c', mountScript, 'sh', wrappedCmd],
      { cwd: '/data', env, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    running.set(loginUser, Math.max(0, (running.get(loginUser) || 1) - 1));
    try { killReqCgroup(cgDir); fs.rmdirSync(cgDir); } catch (_) {}
    audit(loginUser, 'SPAWN_SYNC_FAIL', cmd, e.code || '-', 0);
    return onDone({ exitCode: 'SPAWN_ERROR', durMs: 0, output: '命令无法执行(参数过长或资源不足)' }); // 脱敏:不透传错误原文
  }

  try { fs.writeFileSync(`${cgDir}/cgroup.procs`, String(child.pid)); }
  catch (e) { audit(loginUser, 'CGROUP_FAIL', e.message, '-', 0); }

  let out = Buffer.alloc(0), killed = false;
  const gather = (d) => { if (out.length < OUTPUT_LIMIT) out = Buffer.concat([out, d]).subarray(0, OUTPUT_LIMIT); };
  child.stdout.on('data', gather);
  child.stderr.on('data', gather);

  // 超时: cgroup.kill 必杀(uid 无关,含 setsid 逃逸者),信号杀仅作兜底
  const timer = setTimeout(() => {
    killed = true;
    killReqCgroup(cgDir);
    try { process.kill(-child.pid, 'SIGKILL'); } catch (_) {}
  }, CMD_TIMEOUT_MS);

  const cleanup = () => {
    killReqCgroup(cgDir);
    setTimeout(() => { try { fs.rmdirSync(cgDir); } catch (_) {} }, 2000); // 等 procs 清空后摘组,失败仅留空组
  };
  child.on('close', (code) => {
    clearTimeout(timer);
    cleanup();
    running.set(loginUser, Math.max(0, (running.get(loginUser) || 1) - 1));
    onDone({ exitCode: killed ? 'TIMEOUT_KILLED' : code, durMs: Date.now() - t0, output: out.toString('utf8') });
  });
  child.on('error', (e) => {
    clearTimeout(timer);
    cleanup();
    running.set(loginUser, Math.max(0, (running.get(loginUser) || 1) - 1));
    onDone({ exitCode: 'SPAWN_ERROR', durMs: Date.now() - t0, output: '命令无法执行' });
  });
}

// ===== HTTP =====
function readBody(req, res) {
  return new Promise((resolve, rej) => {
    let b = Buffer.alloc(0), over = false;
    req.on('data', (d) => {
      if (over) return;
      if (b.length < 256 * 1024) b = Buffer.concat([b, d]);
      else { over = true; send(res, 413, { ok: false, error: '请求体过大' }); req.destroy(); }
    });
    req.on('end', () => { if (over) return; try { resolve(JSON.parse(b.toString() || '{}')); } catch (e) { rej(e); } });
    req.on('error', () => { if (!over) rej(new Error(' aborted')); });
  });
}
function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  try {
    if (req.method === 'POST' && url.pathname === '/login') {
      // v6: 登录限速(每 IP 每分钟 10 次)
      // v9: nginx 反代后 socket 全是 127.0.0.1 → 限速与日志改用 X-Real-IP
      const ip = req.headers['x-real-ip'] || req.socket.remoteAddress || '?';
      const now = Date.now();
      const bucket = loginRate.get(ip) || [];
      while (bucket.length && now - bucket[0] > 60_000) bucket.shift();
      if (bucket.length >= 10) return send(res, 429, { ok: false, error: '登录过于频繁,请 1 分钟后再试' });
      bucket.push(now); loginRate.set(ip, bucket);
      const { user, pass } = await readBody(req, res);
      const u = USERS[user];
      if (!u || u.pass !== pass) {
        dbLog('login', String(user || '?').slice(0, 64), ip, '-', 'FAIL', 0, null);
        return send(res, 401, { ok: false, error: '用户名或密码错误' });
      }
      dbLog('login', user, ip, '-', 'OK', 0, null);
      const token = createSession(user);
      return send(res, 200, { ok: true, authToken: token, user, home: u.home, timeoutSec: CMD_TIMEOUT_MS / 1000, sessionTtlMin: SESSION_TTL_MS / 60000 });
    }
    // v9: LLM 密钥代理 —— 验 broker token,注真 key 转发上游,按用户记账
    //     必须在 session 校验之前:broker token 是独立凭证,不走会话
    if (req.method === 'POST' && url.pathname.startsWith('/llm/')) {
      const tok = (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
      const u = verifyBrokerToken(tok);
      if (!u) return send(res, 401, { ok: false, error: 'token 无效或已过期(60s)' });
      if (!LLM_REAL_KEY) return send(res, 503, { ok: false, error: '上游 key 未配置' });
      let bodyObj;
      try { bodyObj = await readBody(req, res); } catch (e) { return send(res, 400, { ok: false, error: '请求格式错误' }); }
      const upstreamPath = url.pathname.replace(/^\/llm/, '') + (url.search || '');
      const proxied = await new Promise((resolve) => {
        const r = https.request(LLM_UPSTREAM + upstreamPath, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-api-key': LLM_REAL_KEY,
            'anthropic-version': req.headers['anthropic-version'] || '2023-06-01',
          },
          timeout: 25_000,
        }, (pr) => {
          const chunks = [];
          pr.on('data', (c) => chunks.push(c));
          pr.on('end', () => resolve({ status: pr.statusCode, body: Buffer.concat(chunks) }));
        });
        r.on('error', () => resolve({ status: 502, body: Buffer.from('{"error":"upstream unreachable"}') }));
        r.on('timeout', () => { r.destroy(); resolve({ status: 504, body: Buffer.from('{"error":"upstream timeout"}') }); });
        r.end(JSON.stringify(bodyObj));
      });
      dbLog('llm', u, req.headers['x-real-ip'] || req.socket.remoteAddress, upstreamPath, String(proxied.status), 0, null);
      res.writeHead(proxied.status, { 'Content-Type': 'application/json' });
      return res.end(proxied.body);
    }

    const auth = req.headers["authorization"] || '';
    const token = auth.replace(/^Bearer\s+/i, '');
    const user = authSession(token);
    if (!user) return send(res, 401, { ok: false, error: '未登录或会话过期' });

    if (req.method === 'POST' && url.pathname === '/logout') {
      sessions.delete(token);
      return send(res, 200, { ok: true, message: '已登出' });
    }

    if (req.method === 'GET' && url.pathname === '/whoami') {
      const c = USERS[user];
      return send(res, 200, { ok: true, user, uid: (UIDS[c.sys] || {}).uid, home: c.home, memLimit: '200M', cpuLimit: '0.5core', timeoutSec: CMD_TIMEOUT_MS / 1000 });
    }
    if (req.method === 'POST' && url.pathname === '/shell') {
      const { cmd, reason } = await readBody(req, res);
      if (typeof cmd !== 'string' || !cmd.trim()) return send(res, 400, { ok: false, error: 'cmd 必填' });
      if ((running.get(user) || 0) >= MAX_CONCURRENT_PER_USER) {
        return send(res, 429, { ok: false, error: `并发超限(每用户 ${MAX_CONCURRENT_PER_USER})` });
      }
      running.set(user, (running.get(user) || 0) + 1);
      runAsTenant(user, cmd, (result) => {
        audit(user, reason, cmd, result.exitCode, result.durMs);
        dbLog('exec', user, req.headers['x-real-ip'] || req.socket.remoteAddress,
              cmd, result.exitCode, result.durMs, result.output); // v9: 执行+结果入 SQLite
        send(res, 200, { ok: true, user, cmd, ...result });
      });
      return;
    }
    return send(res, 404, { ok: false, error: 'not found' });
  } catch (e) {
    send(res, 400, { ok: false, error: '请求格式错误' });
  }
});

// ===== 启动 =====
for (const c of Object.values(USERS)) {
  try {
    UIDS[c.sys] = {
      uid: Number(execSync(`id -u ${c.sys}`).toString().trim()),
      gid: Number(execSync(`id -g ${c.sys}`).toString().trim()),
    };
  } catch (e) {
    // 本地/非部署环境没有租户系统用户:服务可起(login/文档可看),/shell 执行时按用户缺失报错
    console.warn(`[init] 系统用户 ${c.sys} 不存在,该租户的 /shell 将不可用`);
    UIDS[c.sys] = null;
  }
}
const cgProblems = ensureCgroups();
if (cgProblems.length) {
  // fail-closed: 限额起不来的沙箱就是裸奔,宁可拒绝服务
  console.error('bashGate v4 init FAILED (fail-closed):', cgProblems);
  process.exit(1);
}
const auditProblem = ensureAuditFile();
if (auditProblem) console.warn(auditProblem);
server.listen(PORT, '127.0.0.1', () => { // v9: 对齐部署脚本(443 由 nginx 终结 TLS 后反代)
  console.log(`bashGate v4(mnt-ns + nnp + per-req cgroup) ready on :${PORT}, tenants:`, JSON.stringify(UIDS));
});
