#!/bin/bash
# ABCD 分布式扫描平台 — 一键全自动安装(在全新的 Ubuntu/Debian 主控机上执行)
# 用法: curl -fsSL https://raw.githubusercontent.com/2561769445/abcd/main/bootstrap.sh | bash
# 可选环境变量:
#   GITHUB_PROXY=https://gh-proxy.com/   (github慢时加速clone)
#   ABCD_ADMIN_PASS=xxx                 (自定义Web密码, 默认abcd@2026)
set -e
[ "$(id -u)" = 0 ] || { echo "请root执行"; exit 1; }
export GITHUB_PROXY="${GITHUB_PROXY:-}"
SRC=/opt/abcd-src

echo "== [1/6] 基础依赖(git/curl)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1 || yum makecache >/dev/null 2>&1 || true
apt-get install -y -qq git curl wget >/dev/null 2>&1 || yum install -y git curl wget >/dev/null 2>&1 || true

echo "== [2/6] Docker(没有则自动安装)"
if ! command -v docker >/dev/null; then
  echo "  未检测到Docker, 自动安装中(国内优先阿里镜像源)..."
  curl -fsSL https://get.docker.com | sh -s -- --mirror Aliyun >/dev/null 2>&1 || curl -fsSL https://get.docker.com | sh || { echo "Docker安装失败: 请手动安装 https://docs.docker.com/engine/install/"; exit 1; }
fi
systemctl enable --now docker >/dev/null 2>&1 || service docker start >/dev/null 2>&1 || true
if ! docker info 2>/dev/null | grep -A1 "Registry Mirrors" | grep -q http; then
  mkdir -p /etc/docker
  if [ ! -s /etc/docker/daemon.json ]; then
    echo '{"registry-mirrors":["https://docker.m.daocloud.io","https://docker.1ms.run"]}' > /etc/docker/daemon.json
    systemctl restart docker >/dev/null 2>&1 && sleep 3
    echo "  已配置docker镜像加速(国内拉取postgres/redis必需)"
  fi
fi
docker info >/dev/null 2>&1 && echo "  Docker OK: $(docker --version)" || { echo "Docker不可用, 请检查 systemctl status docker"; exit 1; }

echo "== [3/6] Go 1.25+"
need_go=0
if ! command -v go >/dev/null; then need_go=1; else
  gv=$(go version 2>/dev/null | grep -o 'go1\.[0-9]*' | head -1 | cut -d. -f2)
  [ -z "$gv" ] && gv=0; [ "$gv" -lt 25 ] && need_go=1
fi
if [ $need_go = 1 ]; then
  ARCH=$(uname -m); case $ARCH in x86_64) GOARCH=amd64;; aarch64) GOARCH=arm64;; *) echo "不支持$ARCH"; exit 1;; esac
  GOVER=1.25.0
  echo "  安装Go${GOVER}(国内优先golang.google.cn)..."
  (wget -q "https://golang.google.cn/dl/go${GOVER}.linux-${GOARCH}.tar.gz" -O /tmp/go.tgz || wget -q "https://go.dev/dl/go${GOVER}.linux-${GOARCH}.tar.gz" -O /tmp/go.tgz) || { echo "Go下载失败"; exit 1; }
  rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz
  ln -sf /usr/local/go/bin/go /usr/local/bin/go
fi
go version

echo "== [4/6] 拉取源码(直连慢自动切镜像)"
rm -rf $SRC
clone_ok=0
if [ -n "$GITHUB_PROXY" ]; then
  git clone --depth 1 ${GITHUB_PROXY}https://github.com/2561769445/abcd.git $SRC && clone_ok=1
else
  echo "  直连GitHub中(120秒内完不成判慢)..."
  timeout 120 git clone --depth 1 https://github.com/2561769445/abcd.git $SRC 2>/dev/null && clone_ok=1
  if [ $clone_ok = 0 ]; then
    for M in "https://gh-proxy.com/" "https://ghfast.top/"; do
      echo "  直连慢, 切换镜像: $M"
      rm -rf $SRC
      timeout 600 git clone --depth 1 ${M}https://github.com/2561769445/abcd.git $SRC && { clone_ok=1; break; }
    done
  fi
fi
[ $clone_ok = 1 ] || { echo "源码拉取失败: 手动指定镜像重试  export GITHUB_PROXY=https://gh-proxy.com/ && bash bootstrap.sh"; exit 1; }
cd $SRC

echo "== [5/6] 部署主控(docker数据库+编译+systemd+portmux)"
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
bash deploy/setup_master.sh

echo "== [6/6] 完成! 本机也可作为第一个扫描节点, 执行上面打印的纳管命令即可"
