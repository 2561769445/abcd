# ABCD 分布式扫描平台

**月落安全自研**的主控-多节点分布式资产测绘与漏洞扫描平台。

## 功能

- **分布式集群**: 一条命令纳管任意 Linux 节点(gz 压缩分发, 30 秒上线); 节点级并发(默认 2 任务/节点, 子进程隔离); 任务停止秒杀(进程组级 kill)
- **扫描引擎**: 端口扫描(SYN/TCP)、指纹识别、Nuclei+GoPoc 指纹驱动 PoC(workflow 映射表精准匹配)、弱口令爆破 15+ 协议独立凭据台账、目录爆破、测绘引擎(Hunter/FOFA/Quake, Web 设置页配 key 即配即用+一键验证)
- **🏢 单位收集**: 输入公司名 → 自动转鹰图 `icp.name` 语法(近一年) → 拉备案资产接标准扫描
- **vshell 式节点运维**: Web 交互终端(cd 会话保持/命令历史) + 文件管理(浏览/上传/下载/重命名/删除)
- **数据与报告**: 资产/漏洞(带完整请求响应数据包)/凭据三大台账, 任务聚合展示, HTML/Excel/CSV 导出, 勾选导出/聚合导出
- **通知**: 企业微信/钉钉 webhook(高危漏洞防抖推送+任务完成通知)
- **系统设置**: Webhook/测绘Key/登录密码全部页面内配置, 即改即生效

## 一键部署(全新 Ubuntu/Debian 主控机)

```bash
curl -fsSL https://raw.githubusercontent.com/2561769445/abcd/main/bootstrap.sh | bash
```

自动完成: git/docker(国内阿里源+镜像加速)/go 安装 → 拉源码(直连慢自动切镜像) → 编译 → 起数据库(docker, 含就绪等待) → systemd 服务 → 单端口分流(6379=Web+Redis+纳管) → 打印节点纳管命令。

GitHub 慢的机器: `export GITHUB_PROXY=https://gh-proxy.com/` 后再执行。已有环境手动部署见 `DEPLOY.md`。

## 节点接入

在任意 Linux 服务器(amd64/arm64) root 执行部署完成时打印的命令:

```bash
curl -s "http://<主控IP>:6379/install.sh?k=<纳管密钥>" | bash
```

自动下载二进制+装 masscan+注册, 重复执行=升级。

## 修改密码

优先级: **设置页修改 > systemd 环境变量 > 源码默认值**。

**方式〇: 设置页直接改(最简单)** — Web登录 → 系统设置 → 修改登录密码: 即改即生效, 持久化存储重启不丢。

**方式一: 改环境变量(免重编译)** — 编辑 `/etc/systemd/system/abcd-master.service`:

```
ABCD_ADMIN_PASS=你的新密码      # Web登录
ABCD_REDIS_PASS=...            # Redis密码(需与docker redis启动一致)
ABCD_INSTALL_KEY=...           # 节点纳管密钥
ABCD_JWT_SECRET=...            # JWT签名密钥
```

改后 `systemctl daemon-reload && systemctl restart abcd-master`。

**方式二: 改源码** — `master/config.go` 末尾 `LoadConfig()` 里的默认值(如 `"abcd@2026"`)。⚠️ 需同时删掉 service 文件里对应的 `Environment=` 行(否则环境变量覆盖源码), 再重编译部署。

## ⚠️ 安全提醒

- 默认密码(`admin/abcd@2026`、Redis、纳管密钥)仅用于首次启动, 生产环境务必修改(bootstrap 模式下 JWT/纳管密钥已自动随机)
- 6379 端口对外 = Web+Redis+纳管三合一入口, 建议安全组限制来源 IP

## 架构

```
节点 ──纳管/任务/心跳──▶ 6379 portmux ──▶ 8080 master(裸机) ──▶ PG16(docker, 127.0.0.1:5433)
浏览器 ──Web/API──▶ 6379            └──▶ Redis7(docker, 127.0.0.1:6390, 认证)
```

宿主机进程与容器通信一律走 127.0.0.1 端口映射(容器名 DNS 仅容器内生效)。

源码: `cluster/`(协议) `node/`(节点) `master/`(主控+API+前端) `engine/`(扫描引擎) `frontend/`(Vue3, 产物已嵌入无需 node)
