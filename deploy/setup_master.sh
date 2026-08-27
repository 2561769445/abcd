#!/bin/bash
# ABCD 分布式扫描平台 — 主控机部署脚本(由bootstrap.sh调用, 也可手动执行)
# 用法: 在源码根目录执行  bash deploy/setup_master.sh
set -e

# ===== 可按需修改的配置(均有安全默认, 生产环境务必改强) =====
ABCD_ADMIN_PASS="${ABCD_ADMIN_PASS:-abcd@2026}"        # Web登录密码
ABCD_REDIS_PASS="${ABCD_REDIS_PASS:-abcd-redis-2026}"  # Redis密码
ABCD_JWT_SECRET="${ABCD_JWT_SECRET:-$(head -c32 /dev/urandom | base64 | tr -d '/+=')}"
ABCD_INSTALL_KEY="${ABCD_INSTALL_KEY:-$(head -c16 /dev/urandom | base64 | tr -d '/+=')}"
PUBLIC_IP="${PUBLIC_IP:-$(curl -s --max-time 5 4.ipw.cn || curl -s --max-time 5 ifconfig.me || hostname -I | awk '{print $1}')}"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APP=/opt/abcd-distributed

echo "== [0/7] 环境检查"
command -v docker >/dev/null || { echo "缺少docker: curl -fsSL https://get.docker.com | sh"; exit 1; }
command -v go >/dev/null || { echo "缺少go1.25+: https://go.dev/dl/"; exit 1; }
echo "   主控IP: $PUBLIC_IP  源码: $SRC_DIR"

echo "== [1/7] 数据库(docker: PG16 + Redis7)"
mkdir -p $APP/pgdata
docker network create abcdnet 2>/dev/null || true
docker rm -f abcd-pg 2>/dev/null || true; docker rm -f abcd-redis 2>/dev/null || true
# 注意: PG映射到127.0.0.1:5433 — master是裸机进程, 容器名DNS只有容器内生效, 宿主机必须走端口直连
docker run -d --name abcd-pg --network abcdnet --restart unless-stopped \
  -p 127.0.0.1:5433:5432 \
  -e POSTGRES_USER=abcd -e POSTGRES_PASSWORD=abcd123 -e POSTGRES_DB=abcd \
  -v $APP/pgdata:/var/lib/postgresql/data postgres:16-alpine
docker run -d --name abcd-redis --network abcdnet --restart unless-stopped \
  -p 6390:6379 redis:7-alpine redis-server --requirepass $ABCD_REDIS_PASS --appendonly yes
sleep 4
docker exec abcd-redis redis-cli -a $ABCD_REDIS_PASS --no-auth-warning ping | grep -q PONG && echo "   Redis OK" || { echo "Redis启动失败"; exit 1; }
# PG就绪等待: 首次初始化建库要几秒, master抢跑会Fatal重启循环
echo -n "   等待PG就绪"
for i in $(seq 1 60); do
  docker exec abcd-pg pg_isready -U abcd -d abcd >/dev/null 2>&1 && break
  echo -n "."; sleep 1
done
echo ""
docker exec abcd-pg pg_isready -U abcd -d abcd >/dev/null 2>&1 && echo "   PG OK" || { echo "PG未就绪:"; docker logs abcd-pg --tail 10; exit 1; }

echo "== [2/7] 编译主控+节点二进制(前端产物已内置, 无需node)"
cd $SRC_DIR
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -trimpath -o $APP/abcd-master main.go || { echo "编译失败"; exit 1; }
mkdir -p $APP/dl
cp -f $APP/abcd-master $APP/dl/abcd_linux_amd64
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags='-s -w' -trimpath -o $APP/dl/abcd_linux_arm64 main.go || echo "   arm64编译失败(不影响amd64节点)"
cd $APP/dl && gzip -9 -kf abcd_linux_amd64 && gzip -9 -kf abcd_linux_arm64 2>/dev/null || true

echo "== [3/7] 主控 systemd 服务"
cat > /etc/systemd/system/abcd-master.service <<EOF
[Unit]
Description=ABCD Distributed Master
After=network.target docker.service
[Service]
WorkingDirectory=$APP
ExecStart=$APP/abcd-master -master
Environment=ABCD_LISTEN=:8080
Environment=ABCD_PG_DSN=postgres://abcd:abcd123@127.0.0.1:5433/abcd?sslmode=disable
Environment=ABCD_REDIS=127.0.0.1:6390
Environment=ABCD_REDIS_PASS=$ABCD_REDIS_PASS
Environment=ABCD_ADMIN_USER=admin
Environment=ABCD_ADMIN_PASS=$ABCD_ADMIN_PASS
Environment=ABCD_JWT_SECRET=$ABCD_JWT_SECRET
Environment=ABCD_INSTALL_KEY=$ABCD_INSTALL_KEY
Environment=ABCD_DL_DIR=$APP/dl
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

echo "== [4/7] portmux 单端口分流(6379=Web+Redis+纳管入口)"
cd $SRC_DIR/deploy/portmux && go build -o $APP/portmux . || { echo "portmux编译失败"; exit 1; }
cat > /etc/systemd/system/abcd-portmux.service <<EOF
[Unit]
Description=ABCD Portmux 6379
After=network.target
[Service]
ExecStart=$APP/portmux
Environment=MUX_LISTEN=:6379
Environment=MUX_HTTP=127.0.0.1:8080
Environment=MUX_REDIS=127.0.0.1:6390
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now abcd-master abcd-portmux
sleep 5

echo "== [5/7] 自检"
systemctl is-active --quiet abcd-master && echo "   master OK" || { journalctl -u abcd-master -n 20 --no-pager; exit 1; }
systemctl is-active --quiet abcd-portmux && echo "   portmux OK"
curl -s -o /dev/null -w "   Web入口: http://$PUBLIC_IP:6379  [%{http_code}]\n" http://127.0.0.1:6379/

echo "== [6/7] 完成! 登录信息"
echo "   --------------------------------------------------"
echo "   Web:        http://$PUBLIC_IP:6379"
echo "   账号:       admin / $ABCD_ADMIN_PASS"
echo "   JWT密钥:    $ABCD_JWT_SECRET"
echo "   纳管密钥:   $ABCD_INSTALL_KEY"
echo "   --------------------------------------------------"

echo "== [7/7] 节点接入(任意Linux机器root执行, 30秒上线):"
echo "   curl -s \"http://$PUBLIC_IP:6379/install.sh?k=$ABCD_INSTALL_KEY\" | bash"
echo ""
echo "   多节点批量: for h in \$(cat ips.txt); do ssh root@\$h 'curl -s \"http://$PUBLIC_IP:6379/install.sh?k=$ABCD_INSTALL_KEY\" | bash' & done; wait"
