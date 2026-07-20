#!/bin/sh
# 监听共享 volume 中的信号文件，有信号时执行 nginx -s reload
# 由 entrypoint.sh 在后台启动，无需 Docker socket

SIGNAL_FILE="/etc/nginx/subscribe/.reload"
WHITELIST_SIGNAL="/etc/nginx/subscribe/.reload_whitelist"

while true; do
    sleep 2

    # 同时检查两个信号（不再 elif 互斥）
    RELOAD_WL=0
    RELOAD=0
    [ -f "$WHITELIST_SIGNAL" ] && { rm -f "$WHITELIST_SIGNAL"; RELOAD_WL=1; }
    [ -f "$SIGNAL_FILE" ]      && { rm -f "$SIGNAL_FILE";      RELOAD=1;    }

    # 白名单重建（内含 nginx reload）
    if [ "$RELOAD_WL" = "1" ]; then
        /scripts/reload_whitelist.sh 2>/dev/null || true
    # 仅普通 reload
    elif [ "$RELOAD" = "1" ]; then
        nginx -s reload 2>/dev/null || true
    fi
done
