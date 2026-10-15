#!/bin/bash
# bashGate 443 部署：sandbox.example.com → nginx(TLS) → 127.0.0.1:8080
# 幂等：重复执行安全。前置：DNS A 记录 @ → <YOUR_SERVER_IP> 已生效，安全组放行 80/443
set -euo pipefail

DOMAIN=sandbox.example.com
UPSTREAM=127.0.0.1:8080
WEBROOT=/var/www/html
HTTP_VHOST=/etc/nginx/sites-available/welog-http
HTTPS_VHOST=/etc/nginx/sites-available/welog
CATCHALL=/etc/nginx/sites-available/eat-what   # 既有的 444 全丢弃 default_server，保留但摘名

say() { echo -e "\n[deploy-443] $*"; }

[ "$(id -u)" = 0 ] || { echo "must run as root"; exit 1; }

# ---- Phase 0: 前置检查 --------------------------------------------------
say "Phase 0: 检查 DNS 解析"
RESOLVED=$(dig +short "$DOMAIN" @223.5.5.5 | tail -1)
if [ "$RESOLVED" != "$(curl -s --max-time 5 ifconfig.me || true)" ]; then
  echo "!! $DOMAIN 当前解析到 '${RESOLVED:-无}'，与本机公网 IP 不符"
  echo "   先在 DNSPod 控制台加 A 记录：@ → <YOUR_SERVER_IP>，等生效后重跑"
  exit 1
fi
echo "   DNS OK: $DOMAIN -> $RESOLVED"

# ---- Phase 1: 依赖 ------------------------------------------------------
say "Phase 1: 安装 nginx + certbot"
apt-get -qq update
DEBIAN_FRONTEND=noninteractive apt-get -qq install -y nginx certbot python3-certbot-nginx \
  || { echo "apt install 失败"; exit 1; }
systemctl enable --now nginx

# ---- Phase 2: HTTP vhost（ACME challenge + 跳转）------------------------
say "Phase 2: 写入 HTTP vhost"
cat > "$HTTP_VHOST" <<EOF
server {
    listen 80;
    server_name $DOMAIN;

    location /.well-known/acme-challenge/ { root $WEBROOT; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
ln -sf "$HTTP_VHOST" /etc/nginx/sites-enabled/welog-http
nginx -t 2>&1 | sed 's/^/   /'   # 与 eat-thing 闸门的 server_name 冲突警告属预期，Phase 3.5 摘除
systemctl reload nginx

# ---- Phase 3: 签发证书 --------------------------------------------------
say "Phase 3: certbot 签发（webroot HTTP-01）"
CERTDIR=$(ls -d /etc/letsencrypt/live/${DOMAIN}* 2>/dev/null | sort | tail -1 || true)
if [ -z "$CERTDIR" ]; then
  certbot certonly --webroot -w "$WEBROOT" -d "$DOMAIN" \
    --non-interactive --agree-tos --register-unsafely-without-email \
    || { echo "!! 签发失败：检查阿里云安全组是否放行 80 入方向"; exit 1; }
  CERTDIR=$(ls -d /etc/letsencrypt/live/${DOMAIN}* | sort | tail -1)
else
  echo "   证书已存在：$CERTDIR"
fi
echo "   使用血统：$CERTDIR"
systemctl list-timers certbot.timer --no-pager | sed -n '2p' | sed 's/^/   /'

# ---- Phase 3.5: 既有 444 闸门摘名（default_server 保留，让出域名）--------
if [ -f "$CATCHALL" ] && grep -q "${DOMAIN}" "$CATCHALL"; then
  say "Phase 3.5: 444 闸门摘除 ${DOMAIN} 显式占用"
  sed -i "s/server_name ${DOMAIN} www.${DOMAIN} _;/server_name _;/" "$CATCHALL"
  grep server_name "$CATCHALL" | sed 's/^/   /'
fi

# ---- Phase 4: HTTPS vhost（TLS 终结 + 反代 + 限流）----------------------
say "Phase 4: 写入 HTTPS vhost"
cat > "$HTTPS_VHOST" <<EOF
limit_req_zone \$binary_remote_addr zone=bg_login:10m rate=10r/m;

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate     ${CERTDIR}/fullchain.pem;
    ssl_certificate_key ${CERTDIR}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    server_tokens off;

    # 请求体上限：超限回 413（替代网关层的静默断连）
    client_max_body_size 512k;
    client_body_timeout 15s;
    client_header_timeout 15s;

    location /login {
        limit_req zone=bg_login burst=5 nodelay;
        proxy_pass http://${UPSTREAM};
        include /etc/nginx/snippet-bashgate-proxy.conf;
    }

    location / {
        proxy_pass http://${UPSTREAM};
        include /etc/nginx/snippet-bashgate-proxy.conf;
    }
}
EOF
cat > /etc/nginx/snippet-bashgate-proxy.conf <<'EOF'
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header Connection "";
proxy_set_header X-Real-IP $remote_addr;
proxy_connect_timeout 10s;
proxy_read_timeout    75s;   # > 网关 30s 执行超时 + 认证开销
proxy_send_timeout    30s;
proxy_buffering off;          # 流式回传，防大输出占用缓冲
EOF
ln -sf "$HTTPS_VHOST" /etc/nginx/sites-enabled/welog
nginx -t 2>&1 | sed 's/^/   /'
systemctl reload nginx

# ---- Phase 5: bashgate 收口到回环 ---------------------------------------
say "Phase 5: bashgate 监听改为 127.0.0.1"
BG=/software/web-shell/bashgate.js
if grep -q "server.listen(PORT, '0.0.0.0'" "$BG"; then
  sed -i "s/server.listen(PORT, '0.0.0.0'/server.listen(PORT, '127.0.0.1'/" "$BG"
  systemctl restart bashgate
  echo "   已改写并重启"
else
  echo "   已是 127.0.0.1（或写法不同），核对："
  grep -n "server.listen" "$BG" | sed 's/^/   /'
fi

# ufw（若启用则放行）
if ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 80/tcp  >/dev/null
  ufw allow 443/tcp >/dev/null
  echo "   ufw: 已放行 80/443"
fi

# ---- Phase 6: 验证 ------------------------------------------------------
say "Phase 6: 验证"
sleep 1
LOCAL=$(curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8080/login \
  -H 'Content-Type: application/json' -d '{"user":"probe","pass":"x"}')
TLS=$(curl -sk -o /dev/null -w '%{http_code}' --resolve ${DOMAIN}:443:127.0.0.1 \
  -X POST https://${DOMAIN}/login -H 'Content-Type: application/json' \
  -d '{"user":"probe","pass":"x"}')
echo "   回环 8080: $LOCAL (期望 401)"
echo "   本机 TLS : $TLS (期望 401)"
[ "$LOCAL" = 401 ] && [ "$TLS" = 401 ] && echo "=> 全部就绪" || echo "!! 有异常，检查 systemctl status nginx bashgate"

# ---- Phase 7: endlessh tarpit（22 端口，拖死爆破器）---------------------
say "Phase 7: endlessh tarpit"
apt-get -qq install -y endlessh
cat > /etc/endlessh.conf <<'EOF'
# 焦油坑：接受连接后每秒吐一行假 banner，永不完成握手
Port 22
Delay 1000
Length 8
MaxLineLength 32
BindFamily 0
EOF
systemctl enable endlessh >/dev/null 2>&1
systemctl restart endlessh
if ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 22/tcp >/dev/null
fi
if ss -tlnp | grep -q ':22 '; then
  echo "   22 端口已由 endlessh 监听"
else
  echo "   !! endlessh 未监听 22，查 systemctl status endlessh"
fi

say "完成。外网验证：curl https://sandbox.example.com/login"
echo "最后一步（确认外网通后做）：阿里云安全组关闭 8080 入方向，只留 22/80/443/<SSH_PORT>"
