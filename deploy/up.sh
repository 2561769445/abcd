#!/bin/bash
# ABCD 分布式扫描平台 一键部署脚本(主控侧)
# 用法: ./up.sh   (在 deploy/ 目录下执行)
set -e
cd "$(dirname "$0")"

if ! command -v docker >/dev/null; then
  echo "[!] 未安装 docker / docker compose"; exit 1
fi

echo "[*] 启动 PGSQL + Redis + 主控 ..."
docker compose up -d --build

echo ""
echo "=========================================="
echo " 主控Web:   http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '服务器IP'):8080"
echo " 默认账号:  admin / ${ABCD_ADMIN_PASS:-abcd@2026}"
echo " Redis:     $(hostname -I 2>/dev/null | awk '{print $1}' || echo '服务器IP'):6379"
echo " Redis密码: ${ABCD_REDIS_PASS:-abcd-redis-2026}"
echo ""
echo " 分节点接入(在任意扫描机执行):"
echo "   ./abcd -node -r <Redis地址>:6379 -rp ${ABCD_REDIS_PASS:-abcd-redis-2026} -n 节点名"
echo "=========================================="
