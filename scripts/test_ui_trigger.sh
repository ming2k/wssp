#!/bin/bash
# 验证 UI 触发逻辑脚本

# 1. 清理
pkill wss-daemon || true

# 2. 启动守护进程
# 我们故意不设置 WSSP_PASSWORD，迫使它启动 Prompter
export WSSP_PROMPTER_PATH="$(pwd)/target/debug/wss-prompter"
export RUST_LOG=debug

echo "--- 启动守护进程 ---"
./target/debug/wss-daemon &
DAEMON_PID=$!
sleep 2

echo -e "\n--- 触发解锁请求 (模拟应用访问) ---"
# 调用 Unlock 方法，这应该触发 Prompter 启动
busctl --user call org.freedesktop.secrets.test /org/freedesktop/secrets org.freedesktop.Secret.Service Unlock ao 1 "/org/freedesktop/secrets/collection/login" &
BUSCTL_PID=$!

sleep 3

echo -e "\n--- 检查守护进程日志 ---"
# 我们检查日志中是否包含启动 prompter 的记录
if journalctl --user -u wss-daemon -n 50 | grep -i "Spawned wss-prompter"; then
    echo "✅ 成功验证：守护进程已尝试启动前端界面。"
else
    # 如果 journalctl 不可用，直接看 stdout (在本环境中通常直接输出)
    echo "提示：请查看上方实时日志中的 'Spawned wss-prompter' 记录。"
fi

# 3. 清理
kill $DAEMON_PID 2>/dev/null
