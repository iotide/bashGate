// app.js —— bashGate 启动入口
// 用法: npm start（或 node src/app.js）
// 前置: 见 README"快速开始"——secrets/env-bait 缺省时服务可启动,/llm 等功能自动降级
'use strict';

require('./bashgate.js');

// 优雅退出: systemd stop / Ctrl-C 时立即收口,不留半开连接
process.on('SIGTERM', () => process.exit(0));
process.on('SIGINT', () => process.exit(0));
