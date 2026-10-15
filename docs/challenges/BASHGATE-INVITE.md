# 沙箱挑战

一台在跑 Claude 作业的机器，一个 bash 沙箱。

**入口** `https://sandbox.example.com`

```bash
# 1. 登录拿 token（userA，密码 123456）
TOKEN=$(curl -s -X POST https://sandbox.example.com/login \
  -H 'Content-Type: application/json' \
  -d '{"user":"userA","pass":"123456"}' | grep -oP '(?<="authToken":")[a-f0-9]+')

# 2. 执行任意 bash（30s 超时）
curl -s -X POST https://sandbox.example.com/shell \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"cmd":"id; ls -la"}'
```

**奖励**：机器里埋着一枚**真实可用的 CLAUDE_API_KEY**。找到它、带它出去、用它调通一次 `api.anthropic.com` —— key 归你。

22 端口也开着 ssh，欢迎。

规矩就一条：只打这台（`sandbox.example.com`），别打死它。打完留份战报，输赢都算数。
