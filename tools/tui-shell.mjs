#!/usr/bin/env node
// bashGate 靶场交互客户端 (Node ≥18, 零依赖)
// 用法:
//   node tui-shell.mjs                       # 默认 userA
//   node tui-shell.mjs userB                 # 指定账号
//   node tui-shell.mjs userA http://ip:8080  # 指定服务器
// 内置命令: /whoami  /switch <用户>  /relogin  /exit
import readline from 'node:readline/promises';
import { stdin, stdout, argv, exit } from 'node:process';

const C = {
  g: s => `\x1b[92m${s}\x1b[0m`, r: s => `\x1b[91m${s}\x1b[0m`,
  y: s => `\x1b[93m${s}\x1b[0m`, c: s => `\x1b[96m${s}\x1b[0m`,
  d: s => `\x1b[2m${s}\x1b[0m`, b: s => `\x1b[1m${s}\x1b[0m`,
};

const SERVER = (argv[3] || 'https://sandbox.example.com').replace(/\/$/, '');
const PASS = process.env.BASHGATE_PASS || '123456';
let user = argv[2] || 'userA';
let token = null, home = '?';

async function api(method, path, body, auth = true) {
  const res = await fetch(SERVER + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(auth && token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

async function login() {
  const r = await api('POST', '/login', { user, pass: PASS }, false);
  if (!r.ok) { console.log(C.r('登录失败: ' + r.error)); return false; }
  token = r.authToken; home = r.home || '?';
  return true;
}

async function shell(cmd) {
  try {
    let r = await api('POST', '/shell', { cmd });
    if (r.error && /未登录|过期/.test(r.error || '')) {
      console.log(C.y('[会话过期, 自动重登]'));
      if (await login()) r = await api('POST', '/shell', { cmd });
    }
    return r;
  } catch (e) {
    return { ok: false, error: String(e.cause || e.message) };
  }
}

function render(r) {
  if (!r.ok) return console.log(C.r('✗ ' + (r.error || '未知错误')));
  const out = r.output || '';
  if (out) process.stdout.write(out.endsWith('\n') ? out : out + '\n');
  else console.log(C.d('(无输出)'));
  const code = r.exitCode, dur = r.durMs;
  if (code === 'TIMEOUT_KILLED') console.log(C.r(`── ⏱ 超时被杀(30s) · ${dur}ms`));
  else if (code === 'SPAWN_ERROR') console.log(C.r(`── 执行链失败 · ${out.trim()}`));
  else if (code !== 0) console.log(C.y(`── exit=${code} · ${dur}ms`));
  else console.log(C.d(`── exit=0 · ${dur}ms`));
}

console.log(C.c(C.b(`
  ┌───────────────────────────────────────┐
  │   🔫 bashGate 攻击客户端 · web-shell  │
  └───────────────────────────────────────┘`)));
console.log(`  服务   : ${SERVER}`);
console.log(`  账号   : ${C.g(user)} (密码 ${PASS}, /switch 切换)`);
console.log(`  内置   : ${C.d('/whoami  /switch userB  /relogin  /exit')}`);

if (!(await login())) exit(1);
console.log(`  ${C.g('登录成功')} home=${home}\n`);

const rl = readline.createInterface({ input: stdin, output: stdout });
rl.on('close', () => { console.log(C.d('\nbye~')); exit(0); });

while (true) {
  const cmd = (await rl.question(`${C.g(`[${user}@bashgate]`)}$ `)).trim();
  if (!cmd) continue;
  if (cmd === '/exit' || cmd === '/quit') { rl.close(); break; }
  if (cmd === '/whoami') { render(await api('GET', '/whoami')); continue; }
  if (cmd === '/relogin') { console.log((await login()) ? C.g('重新登录成功') : C.r('失败')); continue; }
  if (cmd.startsWith('/switch')) {
    const t = cmd.split(/\s+/)[1];
    if (!t) { console.log(C.y('用法: /switch userB')); continue; }
    user = t;
    if (await login()) console.log(C.g(`已切换 ${user}, home=${home}\n`));
    continue;
  }
  render(await shell(cmd));
}
