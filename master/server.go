package master

import (
	"context"
	"encoding/base64"
	"strconv"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"abcd/cluster"

	"github.com/projectdiscovery/gologger"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

func marshalJSON(v interface{}) ([]byte, error) { return json.Marshal(v) }

var (
	cfg *Config
	rdb *redis.Client
)

// Run -master 模式入口
func Run() {
	cfg = LoadConfig()
	gin.SetMode(gin.ReleaseMode)
	stdLog("启动中: 加载配置完成 pg=%s redis=%s", maskDSN(cfg.PgDSN), cfg.RedisAddr)

	if err := initDB(cfg.PgDSN); err != nil {
		stdFatal("PGSQL初始化失败: %v", err)
	}
	stdLog("PGSQL就绪, 开始建表...")
	if err := migrate(); err != nil {
		stdFatal("建表失败: %v", err)
	}
	stdLog("建表完成")
	rdb = redis.NewClient(&redis.Options{Addr: cfg.RedisAddr, Password: cfg.RedisPass})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		stdFatal("Redis连接失败 %s: %v", cfg.RedisAddr, err)
	}
	loadAdminPass() // settings里改过的密码优先
	loadSettingsOnBoot() // 在Redis就绪后: webhook热载+apiconfig写Redis(防nil)
	stdLog("Redis就绪, 启动消费者与调度引擎...")

	startConsumer(ctx, rdb)
	go startScheduler(ctx, rdb)

	r := gin.New()
	r.MaxMultipartMemory = 64 << 20 // 文件上传50MB(中间缓冲64MB)
	r.Use(gin.Recovery())

	// 登录
	r.POST("/api/login", handleLogin)

	// 节点自助纳管: 安装脚本 + 二进制下载(安装密钥鉴权)
	r.GET("/install.sh", handleInstallScript)
	r.GET("/dl/:file", handleNodeBinary)

	api := r.Group("/api", authMW())
	{
		api.GET("/stats", handleStats)
		api.GET("/activity", handleActivity)

		api.GET("/tasks", handleListTasks)
		api.POST("/tasks", handleCreateTask)
		api.GET("/tasks/:id", handleGetTask)
		api.DELETE("/tasks/:id", handleDeleteTask)
		api.POST("/tasks/:id/stop", handleStopTask)
		api.POST("/tasks/:id/retry", handleRetryTask)

		api.GET("/nodes", handleListNodes)
		api.GET("/install-cmd", handleInstallCmd)
		api.POST("/nodes/:id/weight", handleNodeWeight)
		api.POST("/nodes/:id/offline", handleNodeOffline)
		api.POST("/nodes/:id/exec", handleNodeExec)
		api.GET("/nodes/:id/ls", handleNodeLs)
		api.POST("/nodes/:id/file", handleNodeFileUpload)
		api.GET("/nodes/:id/file", handleNodeFileDownload)
		api.DELETE("/nodes/:id", handleNodeDelete)

		api.GET("/assets", handleListAssets)
		api.GET("/credentials", handleListCreds)
		api.PATCH("/assets/:id", handlePatchAsset)

		api.GET("/vulns", handleListVulns)
		api.GET("/vulns/:id", handleGetVuln)
		api.PATCH("/vulns/:id", handlePatchVuln)

		api.GET("/settings", handleGetSettings)
		api.PUT("/settings", handlePutSettings)
		api.POST("/settings/webhook-test", handleWebhookTest)
		api.POST("/settings/map-test", handleMapKeyTest)
		api.POST("/settings/password", handleChangePassword)

		api.POST("/exports", handleCreateExport)
		api.GET("/exports", handleListExports)
		api.GET("/exports/:id/download", handleDownloadExport)
	}

	// 前端静态托管(embed dist, 不存在时给提示)
	registerFrontend(r)

	stdLog("abcd 主控启动: http://%s  (admin / %s)", cfg.ListenAddr, cfg.AdminPass)
	if err := http.ListenAndServe(cfg.ListenAddr, r); err != nil {
		stdFatal("Web服务启动失败: %v", err)
	}
}

// ---------- 节点自助纳管 ----------

// dlDir 二进制分发目录(主控机 /opt/abcd-distributed/dl)
var dlDir = getenv2("ABCD_DL_DIR", "/opt/abcd-distributed/dl")
var installKey = getenv2("ABCD_INSTALL_KEY", "abcd-install-2026")

func getenv2(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// handleInstallScript 生成一键安装脚本(自动嵌入主控地址)
func handleInstallScript(c *gin.Context) {
	if c.Query("k") != installKey {
		c.String(401, "invalid install key")
		return
	}
	script := `#!/bin/bash
# ABCD 节点一键纳管脚本
# 用法: curl -s "http://MASTER/install.sh?k=KEY" | bash
#       节点名默认自动取 node-公网IP(多台机器发同一条命令, 名字天然唯一)
#       手动指定: 末尾加  -- -n 自定义名字
set -e
MASTER="__MASTER__"
KEY="__KEY__"
NAME=""
for ep in 4.ipw.cn ifconfig.me ip.sb; do
  V=$(curl -s --max-time 4 "$ep" 2>/dev/null | tr -d '[:space:]')
  case "$V" in ''|*[!0-9.]*) ;; *) NAME="node-$V"; break;; esac
done
if [ -z "$NAME" ]; then
  V=$(hostname -I 2>/dev/null | awk '{print $1}')
  case "$V" in ''|*[!0-9.]*) NAME=$(hostname);; *) NAME="node-$V";; esac
fi
while getopts "n:" o; do case $o in n) NAME=$OPTARG;; esac; done
[ "$(id -u)" = 0 ] || { echo "run as root please"; exit 1; }
ARCH=$(uname -m)
case $ARCH in
  x86_64) BIN=abcd_linux_amd64;;
  aarch64) BIN=abcd_linux_arm64;;
  *) echo "unsupported arch $ARCH"; exit 1;;
esac
echo "[1/5] install masscan..."
command -v masscan >/dev/null 2>&1 || (apt-get install -y -qq masscan 2>/dev/null || yum install -y masscan 2>/dev/null || echo "masscan install failed, fallback to TCP scan")
echo "[2/5] download node binary ($BIN, prefer gz ~1/3 size)..."
mkdir -p /opt/abcd-node-dl
DLURL="http://$MASTER/dl"
rm -f /opt/abcd-node-dl/"$BIN".gz /opt/abcd-node-dl/"$BIN"
if curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 -o /opt/abcd-node-dl/"$BIN".gz "$DLURL/$BIN.gz?k=$KEY"; then
  gunzip -f /opt/abcd-node-dl/"$BIN".gz && mv -f /opt/abcd-node-dl/"$BIN" /opt/abcd-node
else
  echo "  gz not available, fallback to raw binary (slow)..."
  curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 -C - -o /opt/abcd-node "$DLURL/$BIN?k=$KEY" || { echo "download failed: check network / key k"; exit 1; }
fi
chmod +x /opt/abcd-node
head -c 4 /opt/abcd-node | grep -q ELF || { echo "binary check failed (not ELF, truncated?)"; exit 1; }
echo "  downloaded: $(du -h /opt/abcd-node | cut -f1)"
echo "[3/5] write systemd service..."
cat > /etc/systemd/system/abcd-node.service <<EOF
[Unit]
Description=ABCD Scan Node
After=network.target
[Service]
WorkingDirectory=/opt
ExecStart=/opt/abcd-node -node -r $MASTER -rp __REDISPASS__ -n $NAME
# 并发任务数: 每个任务fork子进程隔离执行, 同节点可同时跑N个任务(改N后daemon-reload+restart生效)
Environment=ABCD_NODE_CONCURRENCY=2
Restart=always
RestartSec=5
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
echo "[4/5] start..."
# restart而非enable --now: --now对已运行服务不生效, 升级场景旧进程会继续跑旧二进制
systemctl daemon-reload && systemctl enable abcd-node && systemctl restart abcd-node
sleep 5
echo "[5/5] status: $(systemctl is-active abcd-node)"
echo "node [$NAME] registered to $MASTER , check Web node page"
`
	script = strings.ReplaceAll(script, "__MASTER__", c.Request.Host)
	script = strings.ReplaceAll(script, "__KEY__", installKey)
	script = strings.ReplaceAll(script, "__REDISPASS__", cfg.RedisPass)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(200, script)
}

// handleNodeBinary 下发节点二进制
func handleNodeBinary(c *gin.Context) {
	if c.Query("k") != installKey {
		c.String(401, "invalid install key")
		return
	}
	f := c.Param("file")
	if !strings.HasPrefix(f, "abcd_linux_") && !strings.HasPrefix(f, "abcd_windows_") {
		c.String(400, "file not allowed")
		return
	}
	p := dlDir + "/" + f
	if _, err := os.Stat(p); err != nil {
		c.String(404, "binary not found, 请先放到主控 "+dlDir)
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+f)
	c.File(p)
}

// handleInstallCmd 返回一键纳管命令(节点管理页展示用)
func handleInstallCmd(c *gin.Context) {
	cmd := "curl -s \"http://" + c.Request.Host + "/install.sh?k=" + installKey + "\" | bash"
	c.JSON(200, gin.H{"cmd": cmd})
}

// ---------- 登录密码(设置页可改, 持久化settings表) ----------

var adminPassVal string // settings表覆盖值; 空=回落env/源码默认(cfg.AdminPass)

func getAdminPass() string {
	if adminPassVal != "" {
		return adminPassVal
	}
	return cfg.AdminPass
}

// loadAdminPass 启动时从settings恢复(设置页改过的密码重启不丢)
func loadAdminPass() {
	var v string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='admin_pass'`).Scan(&v); err == nil && v != "" {
		adminPassVal = v
		stdLog("登录密码: 使用设置页修改过的密码")
	}
}

// handleChangePassword 设置页修改Web登录密码
func handleChangePassword(c *gin.Context) {
	var req struct {
		OldPass string `json:"old_pass"`
		NewPass string `json:"new_pass"`
	}
	if err := c.BindJSON(&req); err != nil || len(req.NewPass) < 6 {
		c.JSON(400, gin.H{"error": "新密码至少6位"})
		return
	}
	if req.OldPass != getAdminPass() {
		c.JSON(401, gin.H{"error": "旧密码错误"})
		return
	}
	adminPassVal = req.NewPass
	putSetting("admin_pass", req.NewPass)
	c.JSON(200, gin.H{"ok": true, "note": "已生效(重启不丢), 新密码立即使用"})
}

// ---------- 鉴权 ----------

func handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if req.Username != cfg.AdminUser || req.Password != getAdminPass() {
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": req.Username,
		"exp":  time.Now().Add(24 * time.Hour).Unix(),
	})
	s, _ := token.SignedString([]byte(cfg.JWTSecret))
	c.JSON(200, gin.H{"token": s})
}

func authMW() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		t := ""
		if strings.HasPrefix(h, "Bearer ") {
			t = strings.TrimPrefix(h, "Bearer ")
		} else if qt := c.Query("token"); qt != "" {
			// 下载链接等浏览器直连场景
			t = qt
		}
		if t == "" {
			c.AbortWithStatusJSON(401, gin.H{"error": "未登录"})
			return
		}
		claims := jwt.MapClaims{}
		if _, err := jwt.ParseWithClaims(t, claims, func(tk *jwt.Token) (interface{}, error) {
			return []byte(cfg.JWTSecret), nil
		}); err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "令牌无效"})
			return
		}
		c.Next()
	}
}

// ---------- 任务 ----------

func handleListTasks(c *gin.Context) {
	rows, err := db.Query(`SELECT id,name,targets,target_count,ports,options,assigned_node,status,progress,found_assets,found_vulns,cron_expr,stage,created_by,created_at,started_at,finished_at
		FROM tasks ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	out := []TaskRow{} // 初始化为空数组: nil会序列化成null, 前端遍历崩溃
	for rows.Next() {
		var t TaskRow
		if err := rows.Scan(&t.ID, &t.Name, &t.Targets, &t.TargetCount, &t.Ports, &t.Options,
			&t.AssignedNode, &t.Status, &t.Progress, &t.FoundAssets, &t.FoundVulns, &t.CronExpr, &t.Stage,
			&t.CreatedBy, &t.CreatedAt, &t.StartedAt, &t.FinishedAt); err == nil {
			out = append(out, t)
		} else {
			gologger.Error().Msgf("任务行解析失败(跳过): %v", err)
		}
	}
	c.JSON(200, out)
}

func handleCreateTask(c *gin.Context) {
	var req struct {
		Name      string             `json:"name"`
		Targets   []string           `json:"targets"`
		Ports     string             `json:"ports"`
		Options   cluster.ScanOptions `json:"options"`
		NodeID    string             `json:"node_id"`    // 空=自动分配
		CronExpr  string             `json:"cron_expr"`  // 空=立即
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误: " + err.Error()})
		return
	}
	if len(req.Targets) == 0 {
		c.JSON(400, gin.H{"error": "目标不能为空"})
		return
	}
	tb, _ := marshalJSON(req.Targets)
	ob, _ := marshalJSON(req.Options)
	id := "t" + time.Now().Format("20060102150405") + randSuffix()
	status := "pending"
	var nextRun interface{}
	if req.CronExpr != "" {
		status = "scheduled"
		nextRun = time.Now().Add(time.Hour) // 简化: 周期任务每小时评估, v1支持固定间隔
	}
	_, err := db.Exec(`INSERT INTO tasks (id,name,targets,target_count,ports,options,assigned_node,status,cron_expr,next_run)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		id, req.Name, tb, len(req.Targets), req.Ports, ob, req.NodeID, status, req.CronExpr, nextRun)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"id": id})
}

func handleGetTask(c *gin.Context) {
	var t TaskRow
	err := db.QueryRow(`SELECT id,name,targets,target_count,ports,options,assigned_node,status,progress,found_assets,found_vulns,cron_expr,stage,created_by,created_at,started_at,finished_at
		FROM tasks WHERE id=$1`, c.Param("id")).
		Scan(&t.ID, &t.Name, &t.Targets, &t.TargetCount, &t.Ports, &t.Options,
			&t.AssignedNode, &t.Status, &t.Progress, &t.FoundAssets, &t.FoundVulns, &t.CronExpr, &t.Stage,
			&t.CreatedBy, &t.CreatedAt, &t.StartedAt, &t.FinishedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "任务不存在"})
		return
	}
	// 附加实时状态
	state, _ := rdb.HGetAll(c, cluster.ProgressPrefix+t.ID).Result()
	c.JSON(200, gin.H{"task": t, "live": state})
}

func handleDeleteTask(c *gin.Context) {
	db.Exec(`DELETE FROM tasks WHERE id=$1`, c.Param("id"))
	// 同步清理Redis残留, 否则progress key靠TTL过期前会被前端/实时页读到脏数据
	rdb.Del(c, cluster.ProgressPrefix+c.Param("id"), cluster.TaskStatePrefix+c.Param("id"))
	c.JSON(200, gin.H{"ok": true})
}

func handleStopTask(c *gin.Context) {
	id := c.Param("id")
	var node string
	db.QueryRow(`SELECT assigned_node FROM tasks WHERE id=$1`, id).Scan(&node)
	// 广播到指定节点+全体
	msg, _ := marshalJSON(cluster.CtrlMessage{Action: "stop", TaskID: id})
	rdb.Publish(c, cluster.CtrlChannelPre+node, msg)
	rdb.Publish(c, cluster.CtrlChannelPre+"all", msg)
	db.Exec(`UPDATE tasks SET status='stopping' WHERE id=$1 AND status IN ('pending','queued','scanning')`)
	c.JSON(200, gin.H{"ok": true})
}

func handleRetryTask(c *gin.Context) {
	db.Exec(`UPDATE tasks SET status='pending', progress=0, started_at=NULL, finished_at=NULL WHERE id=$1`, c.Param("id"))
	c.JSON(200, gin.H{"ok": true})
}

// ---------- 节点 ----------

func handleListNodes(c *gin.Context) {
	rows, err := db.Query(`SELECT id,name,ip,os,version,online,cpu_percent,mem_percent,running_task,weight,last_heartbeat,created_at
		FROM nodes ORDER BY online DESC, last_heartbeat DESC`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type nodeRow struct {
		ID           string    `json:"id"`
		Name         string    `json:"name"`
		IP           string    `json:"ip"`
		OS           string    `json:"os"`
		Version      string    `json:"version"`
		Online       bool      `json:"online"`
		CPUPercent   float64   `json:"cpu_percent"`
		MemPercent   float64   `json:"mem_percent"`
		RunningTask  string    `json:"running_task"`
		Weight       int       `json:"weight"`
		LastHeartbeat *time.Time `json:"last_heartbeat"`
		CreatedAt    time.Time `json:"created_at"`
	}
	var out []nodeRow
	for rows.Next() {
		var n nodeRow
		if err := rows.Scan(&n.ID, &n.Name, &n.IP, &n.OS, &n.Version, &n.Online, &n.CPUPercent,
			&n.MemPercent, &n.RunningTask, &n.Weight, &n.LastHeartbeat, &n.CreatedAt); err == nil {
			out = append(out, n)
		}
	}
	c.JSON(200, out)
}

func handleNodeWeight(c *gin.Context) {
	var req struct {
		Weight int `json:"weight"`
	}
	if err := c.BindJSON(&req); err != nil || req.Weight < 1 || req.Weight > 100 {
		c.JSON(400, gin.H{"error": "权重范围1-100"})
		return
	}
	db.Exec(`UPDATE nodes SET weight=$1 WHERE id=$2`, req.Weight, c.Param("id"))
	c.JSON(200, gin.H{"ok": true})
}

func handleNodeOffline(c *gin.Context) {
	msg, _ := marshalJSON(cluster.CtrlMessage{Action: "shutdown"})
	rdb.Publish(c, cluster.CtrlChannelPre+c.Param("id"), msg)
	c.JSON(200, gin.H{"ok": true})
}

// nodeCtrlRound 发布指令并轮询回执(文件/目录操作共用)
func nodeCtrlRound(c *gin.Context, action, path string, wait time.Duration) string {
	execID := "e" + time.Now().Format("20060102150405") + randSuffix()
	msg, _ := marshalJSON(cluster.CtrlMessage{Action: action, Cmd: path, ExecID: execID})
	rdb.Publish(c, cluster.CtrlChannelPre+c.Param("id"), msg)
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if v, err := rdb.Get(c, cluster.ExecResultPrefix+execID).Result(); err == nil {
			rdb.Del(c, cluster.ExecResultPrefix+execID)
			return v
		}
		time.Sleep(400 * time.Millisecond)
	}
	return "ERR timeout: node offline or old version"
}

// handleNodeFileUpload 上传文件到节点(multipart, ≤50MB, Redis中转base64)
func handleNodeFileUpload(c *gin.Context) {
	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "缺少file"})
		return
	}
	path := c.PostForm("path")
	if path == "" {
		path = "/tmp/" + fh.Filename
	}
	if fh.Size > 50<<20 {
		c.JSON(400, gin.H{"error": "文件超过50MB限制"})
		return
	}
	f, _ := fh.Open()
	defer f.Close()
	b := make([]byte, fh.Size)
	_, _ = f.Read(b)
	execID := "e" + time.Now().Format("20060102150405") + randSuffix()
	rdb.Set(c, cluster.FileTmpPrefix+execID, base64.StdEncoding.EncodeToString(b), 5*time.Minute)
	msg, _ := marshalJSON(cluster.CtrlMessage{Action: "putfile", Cmd: path, ExecID: execID})
	rdb.Publish(c, cluster.CtrlChannelPre+c.Param("id"), msg)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if v, err := rdb.Get(c, cluster.ExecResultPrefix+execID).Result(); err == nil {
			rdb.Del(c, cluster.ExecResultPrefix+execID)
			if strings.HasPrefix(v, "OK") {
				c.JSON(200, gin.H{"output": v})
			} else {
				c.JSON(500, gin.H{"error": v})
			}
			return
		}
		time.Sleep(400 * time.Millisecond)
	}
	c.JSON(504, gin.H{"error": "节点无响应"})
}

// handleNodeFileDownload 从节点下载文件
func handleNodeFileDownload(c *gin.Context) {
	path := c.Query("path")
	if path == "" {
		c.JSON(400, gin.H{"error": "缺少path"})
		return
	}
	v := nodeCtrlRound(c, "getfile", path, 30*time.Second)
	if !strings.HasPrefix(v, "OK ") {
		c.JSON(500, gin.H{"error": v})
		return
	}
	data, err := base64.StdEncoding.DecodeString(v[3:])
	if err != nil {
		c.JSON(500, gin.H{"error": "解码失败"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+filepath.Base(path))
	c.Data(200, "application/octet-stream", data)
}

// handleNodeLs 节点目录列表
func handleNodeLs(c *gin.Context) {
	v := nodeCtrlRound(c, "lsdir", c.DefaultQuery("path", "/"), 30*time.Second)
	if !strings.HasPrefix(v, "OK ") {
		c.JSON(500, gin.H{"error": v})
		return
	}
	var entries []map[string]interface{}
	if err := json.Unmarshal([]byte(v[3:]), &entries); err != nil {
		c.JSON(500, gin.H{"error": "解析失败"})
		return
	}
	c.JSON(200, gin.H{"path": c.DefaultQuery("path", "/"), "entries": entries})
}

// handleNodeExec 对节点远程执行命令(Web运维通道): 发布exec指令 → 轮询回执
func handleNodeExec(c *gin.Context) {
	var req struct {
		Cmd     string `json:"cmd"`
		Timeout int    `json:"timeout"` // 秒, 默认120
	}
	if err := c.BindJSON(&req); err != nil || req.Cmd == "" {
		c.JSON(400, gin.H{"error": "命令不能为空"})
		return
	}
	if req.Timeout <= 0 {
		req.Timeout = 120
	}
	execID := "e" + time.Now().Format("20060102150405") + randSuffix()
	msg, _ := marshalJSON(cluster.CtrlMessage{Action: "exec", Cmd: req.Cmd, ExecID: execID, Timeout: req.Timeout})
	rdb.Publish(c, cluster.CtrlChannelPre+c.Param("id"), msg)
	// 轮询回执(最长等 cmd超时+10s)
	deadline := time.Now().Add(time.Duration(req.Timeout+10) * time.Second)
	for time.Now().Before(deadline) {
		if v, err := rdb.Get(c, cluster.ExecResultPrefix+execID).Result(); err == nil {
			rdb.Del(c, cluster.ExecResultPrefix+execID)
			c.JSON(200, gin.H{"output": v})
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	c.JSON(504, gin.H{"error": "节点执行超时/无响应(节点离线或旧版本不支持)"})
}

// handleNodeDelete 删除节点: 在线则先下发shutdown, 再清Redis心跳+PG行
func handleNodeDelete(c *gin.Context) {
	id := c.Param("id")
	msg, _ := marshalJSON(cluster.CtrlMessage{Action: "shutdown"})
	rdb.Publish(c, cluster.CtrlChannelPre+id, msg)
	rdb.HDel(c, cluster.HashNodes, id)
	if _, err := db.Exec(`DELETE FROM nodes WHERE id=$1`, id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"ok": true})
}

// ---------- 设置 ----------

// loadSettingsOnBoot 启动时把settings表里的webhook热载入(env只是初始默认)
func loadSettingsOnBoot() {
	var v string
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='webhook_url'`).Scan(&v); err == nil && v != "" {
		SetWebhook(v)
	}
	// 测绘key恢复到Redis: master重启/Redis清空后节点仍能拉到(平时只在设置页保存时写)
	syncAPIConfigRedis()
}

func handleGetSettings(c *gin.Context) {
	c.JSON(200, gin.H{
		"webhook_url": GetWebhook(),
		"hunter_key":  getSetting("hunter_key"),
		"fofa_key":    getSetting("fofa_key"),
		"quake_key":   getSetting("quake_key"),
	})
}

func getSetting(k string) string {
	var v string
	_ = db.QueryRow(`SELECT value FROM settings WHERE key=$1`, k).Scan(&v)
	return v
}

func putSetting(k, v string) {
	db.Exec(`INSERT INTO settings (key,value,updated_at) VALUES ($1,$2,now())
		ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_at=now()`, k, v)
}

// syncAPIConfigRedis 测绘key变更后生成api-config.yaml写Redis, 节点执行任务前拉取覆盖本地
func syncAPIConfigRedis() {
	yml := ""
	if v := getSetting("hunter_key"); v != "" {
		yml += "hunter:\n  - \"" + v + "\"\n"
	}
	if v := getSetting("fofa_key"); v != "" {
		yml += "fofa:\n  - \"" + v + "\"\n"
	}
	if v := getSetting("quake_key"); v != "" {
		yml += "quake:\n  - \"" + v + "\"\n"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rdb.Set(ctx, "cluster:apiconfig", yml, 0)
}

func handlePutSettings(c *gin.Context) {
	var req struct {
		WebhookURL string `json:"webhook_url"`
		HunterKey  string `json:"hunter_key"`
		FofaKey    string `json:"fofa_key"`
		QuakeKey   string `json:"quake_key"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	SetWebhook(req.WebhookURL)
	putSetting("webhook_url", req.WebhookURL)
	putSetting("hunter_key", req.HunterKey)
	putSetting("fofa_key", req.FofaKey)
	putSetting("quake_key", req.QuakeKey)
	syncAPIConfigRedis()
	c.JSON(200, gin.H{"ok": true})
}

// handleWebhookTest 发测试消息验证连通
func handleWebhookTest(c *gin.Context) {
	if GetWebhook() == "" {
		c.JSON(400, gin.H{"error": "请先保存webhook地址"})
		return
	}
	pushWebhook("连通性测试", "> ABCD通知通道OK\n> "+time.Now().Format("2006-01-02 15:04:05"))
	c.JSON(200, gin.H{"ok": true, "note": "已发送, 检查群消息"})
}

// ---------- 资产 ----------

func handleListAssets(c *gin.Context) {
	where, args := buildAssetFilter(c)
	// 分页: page从1起, page_size默认50最大500, 返回total
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	ps, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if ps < 1 || ps > 500 {
		ps = 50
	}
	var total int
	_ = db.QueryRow(`SELECT count(*) FROM assets `+where, args...).Scan(&total)
	rows, err := db.Query(`SELECT id,task_id,node_id,asset_type,ip,port,protocol,uri,domain,title,status_code,finger,tag,remark,first_seen,last_seen
		FROM assets `+where+` ORDER BY last_seen DESC LIMIT `+itoa(ps)+` OFFSET `+itoa((page-1)*ps), args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []AssetRow
	for rows.Next() {
		var a AssetRow
		if err := rows.Scan(&a.ID, &a.TaskID, &a.NodeID, &a.AssetType, &a.IP, &a.Port, &a.Protocol,
			&a.URI, &a.Domain, &a.Title, &a.StatusCode, &a.Finger, &a.Tag, &a.Remark, &a.FirstSeen, &a.LastSeen); err == nil {
			out = append(out, a)
		}
	}
	c.JSON(200, gin.H{"rows": out, "total": total, "page": page, "page_size": ps})
}

// handleListCreds 凭据台账(弱口令/未授权)
func handleListCreds(c *gin.Context) {
	conds := []string{"1=1"}
	var args []interface{}
	n := 1
	if in := safeIDIn(c.Query("task_ids")); in != "" {
		conds = append(conds, "task_id IN ("+in+")")
	} else if v := c.Query("task_id"); v != "" {
		conds = append(conds, "task_id = $"+itoa(n))
		args = append(args, v)
		n++
	}
	if v := c.Query("search"); v != "" {
		conds = append(conds, "(target ILIKE $"+itoa(n)+" OR detail ILIKE $"+itoa(n)+" OR service ILIKE $"+itoa(n)+")")
		args = append(args, "%"+v+"%")
		n++
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	ps, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if page < 1 {
		page = 1
	}
	if ps < 1 || ps > 500 {
		ps = 50
	}
	where := strings.Join(conds, " AND ")
	var total int
	_ = db.QueryRow(`SELECT count(*) FROM credentials WHERE `+where, args...).Scan(&total)
	rows, err := db.Query(`SELECT id,task_id,node_id,service,target,detail,first_seen,last_seen
		FROM credentials WHERE `+where+` ORDER BY last_seen DESC LIMIT `+itoa(ps)+` OFFSET `+itoa((page-1)*ps), args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type credRow struct {
		ID        int64     `json:"id"`
		TaskID    string    `json:"task_id"`
		NodeID    string    `json:"node_id"`
		Service   string    `json:"service"`
		Target    string    `json:"target"`
		Detail    string    `json:"detail"`
		FirstSeen time.Time `json:"first_seen"`
		LastSeen  time.Time `json:"last_seen"`
	}
	out := []credRow{}
	for rows.Next() {
		var r credRow
		if err := rows.Scan(&r.ID, &r.TaskID, &r.NodeID, &r.Service, &r.Target, &r.Detail, &r.FirstSeen, &r.LastSeen); err == nil {
			out = append(out, r)
		}
	}
	c.JSON(200, gin.H{"rows": out, "total": total, "page": page, "page_size": ps})
}

func buildAssetFilter(c *gin.Context) (string, []interface{}) {
	conds := []string{"1=1"}
	addTaskIDsFilter(&conds, c)
	var args []interface{}
	n := 1
	add := func(col, op, val string) {
		conds = append(conds, col+" "+op+" $"+itoa(n))
		args = append(args, val)
		n++
	}
	if v := c.Query("ip"); v != "" {
		add("ip", "=", v)
	}
	if v := c.Query("finger"); v != "" {
		add("finger", "LIKE", "%"+v+"%")
	}
	if v := c.Query("type"); v != "" {
		add("asset_type", "=", v)
	}
	if v := c.Query("domain"); v != "" {
		add("domain", "LIKE", "%"+v+"%")
	}
	if v := c.Query("task_id"); v != "" {
		add("task_id", "=", v)
	}
	if v := c.Query("search"); v != "" {
		conds = append(conds, "(uri ILIKE $"+itoa(n)+" OR title ILIKE $"+itoa(n)+" OR ip ILIKE $"+itoa(n)+")")
		args = append(args, "%"+v+"%")
		n++
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func handlePatchAsset(c *gin.Context) {
	var req struct {
		Tag    *string `json:"tag"`
		Remark *string `json:"remark"`
	}
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if req.Tag != nil {
		db.Exec(`UPDATE assets SET tag=$1 WHERE id=$2`, *req.Tag, c.Param("id"))
	}
	if req.Remark != nil {
		db.Exec(`UPDATE assets SET remark=$1 WHERE id=$2`, *req.Remark, c.Param("id"))
	}
	c.JSON(200, gin.H{"ok": true})
}

// ---------- 漏洞 ----------

func handleListVulns(c *gin.Context) {
	where, args := buildVulnFilter(c)
	rows, err := db.Query(`SELECT id,task_id,node_id,source,vuln_id,severity,target,detail,status,first_seen,last_seen
		FROM vulns `+where+` ORDER BY first_seen DESC LIMIT 500`, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var out []VulnRow
	for rows.Next() {
		var v VulnRow
		if err := rows.Scan(&v.ID, &v.TaskID, &v.NodeID, &v.Source, &v.VulnID, &v.Severity,
			&v.Target, &v.Detail, &v.Status, &v.FirstSeen, &v.LastSeen); err == nil {
			out = append(out, v)
		}
	}
	c.JSON(200, out)
}

// handleGetVuln 漏洞详情: 含从extra提取的请求数据包
func handleGetVuln(c *gin.Context) {
	var v struct {
		VulnRow
		Extra string `json:"-"`
	}
	err := db.QueryRow(`SELECT id,task_id,node_id,source,vuln_id,severity,target,detail,status,first_seen,last_seen,extra
		FROM vulns WHERE id=$1`, c.Param("id")).
		Scan(&v.ID, &v.TaskID, &v.NodeID, &v.Source, &v.VulnID, &v.Severity,
			&v.Target, &v.Detail, &v.Status, &v.FirstSeen, &v.LastSeen, &v.Extra)
	if err != nil {
		c.JSON(404, gin.H{"error": "漏洞不存在"})
		return
	}
	req, resp, curl, desc, refs := extractVulnPkt(v.Extra)
	c.JSON(200, gin.H{"vuln": v.VulnRow, "pkt": gin.H{
		"request": req, "response": resp, "curl": curl, "description": desc, "reference": refs,
	}})
}

// safeIDIn 逗号分隔任务ID转安全的IN子句: 'a','b' (只留字母数字-_)
func safeIDIn(v string) string {
	var out []string
	for _, id := range strings.Split(v, ",") {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		ok := true
		for _, r := range id {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, "'"+id+"'")
		}
	}
	return strings.Join(out, ",")
}

// addTaskIDsFilter 给asset/vuln筛选加聚合任务多选过滤(task_ids=逗号分隔子任务ID)
func addTaskIDsFilter(conds *[]string, c *gin.Context) {
	if v := c.Query("task_ids"); v != "" {
		if in := safeIDIn(v); in != "" {
			*conds = append(*conds, "task_id IN ("+in+")")
		}
	}
}

func buildVulnFilter(c *gin.Context) (string, []interface{}) {
	conds := []string{"1=1"}
	addTaskIDsFilter(&conds, c)
	var args []interface{}
	n := 1
	add := func(col, op, val string) {
		conds = append(conds, col+" "+op+" $"+itoa(n))
		args = append(args, val)
		n++
	}
	if v := c.Query("severity"); v != "" {
		add("severity", "=", v)
	}
	if v := c.Query("status"); v != "" {
		add("status", "=", v)
	}
	if v := c.Query("source"); v != "" {
		add("source", "=", v)
	}
	if v := c.Query("task_id"); v != "" {
		add("task_id", "=", v)
	}
	if v := c.Query("search"); v != "" {
		add("(target ILIKE", "pattern", "%"+v+"%")
		conds[len(conds)-1] = "(target ILIKE $" + itoa(n-1) + " OR vuln_id ILIKE $" + itoa(n-1) + " OR detail ILIKE $" + itoa(n-1) + ")"
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func handlePatchVuln(c *gin.Context) {
	var req struct {
		Status *string `json:"status"` // open/fixed/ignored
	}
	if err := c.BindJSON(&req); err != nil || req.Status == nil {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if *req.Status != "open" && *req.Status != "fixed" && *req.Status != "ignored" {
		c.JSON(400, gin.H{"error": "状态必须是 open/fixed/ignored"})
		return
	}
	db.Exec(`UPDATE vulns SET status=$1 WHERE id=$2`, *req.Status, c.Param("id"))
	c.JSON(200, gin.H{"ok": true})
}

// ---------- 实时动态 ----------

// handleActivity 最近发现的资产/漏洞混合流(实时日志页数据源)
func handleActivity(c *gin.Context) {
	rows, err := db.Query(`
		SELECT 'asset' AS kind, id, task_id, node_id,
			CASE
				WHEN COALESCE(uri,'') <> '' THEN uri || CASE WHEN COALESCE(title,'')<>'' THEN ' ['||title||']' ELSE '' END
				WHEN COALESCE(port,'') <> '' THEN asset_type || ' ' || ip || ':' || port
				ELSE asset_type || ' ' || ip
			END AS text,
			asset_type AS tag, last_seen
		FROM assets ORDER BY id DESC LIMIT 30`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type act struct {
		Kind    string    `json:"kind"`
		ID      int       `json:"id"`
		TaskID  string    `json:"task_id"`
		NodeID  string    `json:"node_id"`
		Text    string    `json:"text"`
		Tag     string    `json:"tag"`
		Time    time.Time `json:"time"`
	}
	var out []act
	for rows.Next() {
		var a act
		if err := rows.Scan(&a.Kind, &a.ID, &a.TaskID, &a.NodeID, &a.Text, &a.Tag, &a.Time); err == nil {
			out = append(out, a)
		}
	}
	vrows, err := db.Query(`
		SELECT 'vuln', id, task_id, node_id, vuln_id || ' @ ' || target, severity, first_seen
		FROM vulns ORDER BY id DESC LIMIT 20`)
	if err == nil {
		defer vrows.Close()
		for vrows.Next() {
			var a act
			if err := vrows.Scan(&a.Kind, &a.ID, &a.TaskID, &a.NodeID, &a.Text, &a.Tag, &a.Time); err == nil {
				out = append(out, a)
			}
		}
	}
	// 按时间倒序
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Time.After(out[i].Time) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	if len(out) > 50 {
		out = out[:50]
	}
	c.JSON(200, out)
}

// ---------- 统计 ----------

func handleStats(c *gin.Context) {
	var nodesTotal, nodesOnline, tasksTotal, tasksRunning, assetsTotal, vulnsTotal, vulnsHigh int
	db.QueryRow(`SELECT count(*) FROM nodes`).Scan(&nodesTotal)
	db.QueryRow(`SELECT count(*) FROM nodes WHERE online=true`).Scan(&nodesOnline)
	db.QueryRow(`SELECT count(*) FROM tasks`).Scan(&tasksTotal)
	db.QueryRow(`SELECT count(*) FROM tasks WHERE status IN ('queued','scanning')`).Scan(&tasksRunning)
	db.QueryRow(`SELECT count(*) FROM assets`).Scan(&assetsTotal)
	db.QueryRow(`SELECT count(*) FROM vulns`).Scan(&vulnsTotal)
	db.QueryRow(`SELECT count(*) FROM vulns WHERE severity IN ('critical','high') AND status='open'`).Scan(&vulnsHigh)
	c.JSON(200, gin.H{
		"nodes_total": nodesTotal, "nodes_online": nodesOnline,
		"tasks_total": tasksTotal, "tasks_running": tasksRunning,
		"assets_total": assetsTotal, "vulns_total": vulnsTotal, "vulns_high_open": vulnsHigh,
	})
}

// ---------- 工具 ----------

func stdLog(f string, a ...interface{}) {
	println("[master]", fmtSprintf(f, a...))
}

func stdFatal(f string, a ...interface{}) {
	println("[master][FATAL]", fmtSprintf(f, a...))
	os.Exit(1)
}
