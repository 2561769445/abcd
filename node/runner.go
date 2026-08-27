package node

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"abcd/cluster"
	"abcd/common"
	"abcd/ddout"
	"abcd/engine"
	"abcd/structs"

	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
)

var (
	currentTaskID    atomic.Value // string
	currentCancel    atomic.Value // context.CancelFunc
	runningFlag      atomic.Bool
	progressCounters atomic.Int64   // 已上报结果条数
	runningSet       = sync.Map{}   // taskID -> struct{}{} 在跑任务集合(并发模式心跳聚合)
	childCancels     = sync.Map{}   // taskID -> context.CancelFunc 并发子进程取消器
)

// ExecRun -node-exec 子进程入口: 读任务JSON跑单任务退出(与父节点进程全局状态隔离)
func ExecRun(args []string) {
	if len(args) < 1 {
		os.Exit(2)
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		os.Exit(3)
	}
	var task cluster.Task
	if err := json.Unmarshal(b, &task); err != nil {
		os.Exit(4)
	}
	opt.nodeID = os.Getenv("ABCD_NODE_ID")
	opt.nodeName = opt.nodeID
	db := 0
	if v := os.Getenv("ABCD_EXEC_REDIS_DB"); v != "" {
		db, _ = strconv.Atoi(v)
	}
	rdb = redis.NewClient(&redis.Options{
		Addr:     os.Getenv("ABCD_EXEC_REDIS_ADDR"),
		Password: os.Getenv("ABCD_EXEC_REDIS_PASS"),
		DB:       db,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		os.Exit(5)
	}
	runTask(ctx, &task)
}

// execChild 并发模式: fork子进程跑任务, 全局状态进程级隔离
func execChild(pctx context.Context, task *cluster.Task) {
	raw, _ := json.Marshal(task)
	tmp := filepath.Join(os.TempDir(), "abcd-task-"+task.ID+".json")
	if err := os.WriteFile(tmp, raw, 0600); err != nil {
		gologger.Error().Msgf("任务文件写入失败: %v", err)
		return
	}
	defer os.Remove(tmp)

	cctx, cancel := context.WithCancel(pctx)
	defer cancel() // 正常完成路径也要释放: 否则kill-waiter goroutine按任务数泄漏
	childCancels.Store(task.ID, cancel)
	defer childCancels.Delete(task.ID)
	runningSet.Store(task.ID, struct{}{})
	defer runningSet.Delete(task.ID)

	gologger.Info().Msgf("子进程执行: %s (%s) 目标数=%d", task.ID, task.Name, len(task.Targets))
	exe, _ := os.Executable()
	cmd := exec.CommandContext(cctx, exe, "-node-exec", tmp)
	setPgid(cmd) // 独立进程组: kill连masscan孙进程一起收
	// ctx取消(停止/超时)时升级为组杀, 秒停引擎任意阶段
	go func() {
		<-cctx.Done()
		killGroup(cmd)
	}()
	cmd.Env = append(os.Environ(),
		"ABCD_NODE_ID="+opt.nodeID,
		"ABCD_EXEC_REDIS_ADDR="+opt.redisAddr,
		"ABCD_EXEC_REDIS_PASS="+opt.redisPass,
		"ABCD_EXEC_REDIS_DB="+strconv.Itoa(opt.redisDB))
	cmd.Stdout = os.Stdout // 子进程日志透传到journalctl
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if cctx.Err() != nil {
		// 被stop指令/父退出kill: 补终态(子进程可能没来得及上报)
		setTaskState(task.ID, "stopped", "killed")
	}
	gologger.Info().Msgf("子进程结束: %s err=%v", task.ID, err)
}

func cancelCurrentTask() {
	if f, ok := currentCancel.Load().(context.CancelFunc); ok && f != nil {
		f()
	}
}

func runTask(parent context.Context, task *cluster.Task) {
	if runningFlag.Load() {
		// 不应发生(串行), 防御
		gologger.Error().Msg("任务冲突: 上一任务未结束")
		return
	}
	runningFlag.Store(true)
	defer runningFlag.Store(false)
	progressCounters.Store(0) // 每个任务重置进度计数
	runningSet.Store(task.ID, struct{}{})
	defer runningSet.Delete(task.ID)

	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	currentTaskID.Store(task.ID)
	currentCancel.Store(cancel)
	defer currentCancel.Store(context.CancelFunc(nil))
	defer currentTaskID.Store("") // 清残留: done后心跳running_task不再挂旧ID

	setTaskState(task.ID, "scanning", "")
	start := time.Now()

	err := executeScan(ctx, task)

	status := "done"
	if ctx.Err() != nil || err == context.Canceled {
		status = "stopped"
	} else if err != nil {
		status = "failed"
	}
	setTaskState(task.ID, status, time.Since(start).String())
	gologger.Info().Msgf("任务结束: %s status=%s 耗时=%s", task.ID, status, time.Since(start))
}

// executeScan 填GlobalConfig→初始化→跑扫描, hook实时上报结果
func executeScan(ctx context.Context, task *cluster.Task) error {
	// 阶段hook: 上报扫描阶段进度
	engine.SetStageHook(func(stage string) {
		pct := engine.StagePct(stage)
		if pct < 0 {
			return
		}
		cctx, cc := context.WithTimeout(context.Background(), 3*time.Second)
		defer cc()
		rdb.HSet(cctx, cluster.ProgressPrefix+task.ID, map[string]interface{}{
			"stage":     stage,
			"stage_cn":  engine.StageCN(stage),
			"progress":  pct,
			"update_ts": time.Now().Unix(),
		})
	})

	// 结果hook: 每条结果包信封LPUSH到结果队列
	ddout.SetOutputHook(func(o ddout.OutputMessage) {
		progressCounters.Add(1)
		raw, err := o.ToJson()
		if err != nil {
			return
		}
		env := cluster.ResultEnvelope{
			TaskID: task.ID,
			NodeID: opt.nodeID,
			Msg:    json.RawMessage(raw),
		}
		b, _ := json.Marshal(env)
		// 带短超时, 不阻塞扫描主流程; 失败重试一次
		cctx, cc := context.WithTimeout(ctx, 5*time.Second)
		defer cc()
		if err := rdb.LPush(cctx, cluster.QueueResults, string(b)).Err(); err != nil {
			_ = rdb.LPush(context.Background(), cluster.QueueResults, string(b)).Err()
		}
	})
	defer ddout.SetOutputHook(nil)

	// 填GlobalConfig
	o := task.Options
	cfg := &structs.GlobalConfig
	*cfg = structs.Config{} // 清零, 防上一任务残留
	cfg.Targets = append(cfg.Targets, task.Targets...)
	cfg.Ports = task.Ports
	cfg.PortScanType = o.PortScanType
	if cfg.PortScanType == "" {
		cfg.PortScanType = "syn" // 默认SYN, 无masscan自动降级TCP
	}
	cfg.TCPPortScanThreads = o.TCPPortScanThreads
	cfg.WebThreads = o.WebThreads
	cfg.WebTimeout = o.WebTimeout
	// 线程/超时默认值(与命令行flag默认一致)
	if cfg.TCPPortScanThreads <= 0 {
		cfg.TCPPortScanThreads = 1000
	}
	if cfg.SYNPortScanThreads <= 0 {
		cfg.SYNPortScanThreads = 20000 // masscan rate: 实测50k丢包反而漏(89<128条), 20k+retries2为该带宽最优
	}
	if cfg.WebThreads <= 0 {
		cfg.WebThreads = 200
	}
	if cfg.WebTimeout <= 0 {
		cfg.WebTimeout = 10
	}
	if cfg.GetBannerThreads <= 0 {
		cfg.GetBannerThreads = 500
	}
	if cfg.GetBannerTimeout <= 0 {
		cfg.GetBannerTimeout = 5
	}
	if cfg.TCPPortScanTimeout <= 0 {
		cfg.TCPPortScanTimeout = 6
	}
	if cfg.PortsThreshold <= 0 {
		cfg.PortsThreshold = 300
	}
	if cfg.SubdomainBruteForceThreads <= 0 {
		cfg.SubdomainBruteForceThreads = 600 // dnsx多resolver分摊, 150太保守
	}
	if cfg.GoPocThreads <= 0 {
		cfg.GoPocThreads = 50
	}
	cfg.NoPoc = o.NoPoc
	cfg.NoGolangPoc = o.NoGolangPoc
	cfg.DisableGeneralPoc = o.DisableGeneralPoc
	cfg.PocNameForSearch = o.PocNameForSearch
	cfg.NoDirSearch = o.NoDirSearch
	cfg.NoServiceBruteForce = o.NoServiceBrute
	cfg.Subdomain = o.Subdomain
	cfg.NoSubdomainBruteForce = o.NoSubdomainBruteForce
	cfg.NoSubFinder = o.NoSubFinder
	cfg.AllowLocalAreaDomain = o.AllowLocalAreaDomain
	cfg.AllowCDNAssets = o.AllowCDNAssets
	cfg.NoHostBind = o.NoHostBind
	cfg.NoICMPPing = o.NoICMPPing
	cfg.TCPPing = o.TCPPing
	cfg.SkipHostDiscovery = o.SkipHostDiscovery
	cfg.NoPortString = o.NoPortString
	cfg.MasscanPath = o.MasscanPath
	if cfg.MasscanPath == "" {
		cfg.MasscanPath = "masscan"
	}
	cfg.AdaptiveTCPScan = o.AdaptiveTCP
	cfg.Hunter = o.Hunter
	cfg.Fofa = o.Fofa
	cfg.Quake = o.Quake
	cfg.HunterPageSize = o.HunterPageSize
	cfg.HunterMaxPageCount = o.HunterMaxPage
	cfg.FofaMaxCount = o.FofaMaxCount
	cfg.QuakeSize = o.QuakeSize
	// 测绘分页默认值兜底: 不传(0)时翻页循环一次都不跑, Hunter拉0条
	if cfg.HunterPageSize <= 0 {
		cfg.HunterPageSize = 10 // 个人账号page_size过大会429限流, 10为安全值(VIP可在任务里调大)
	}
	if cfg.HunterMaxPageCount <= 0 {
		cfg.HunterMaxPageCount = 50 // ps=10: 默认拉前500条0 // page_size=10: 50页=默认拉前500条资产
	}
	if cfg.FofaMaxCount <= 0 {
		cfg.FofaMaxCount = 500 // extended账号单次500实测OK
	}
	if cfg.QuakeSize <= 0 {
		cfg.QuakeSize = 500 // quake实测size=500正常
	}
	cfg.LowPerceptionMode = o.LowPerception
	cfg.OnlyIPPort = o.OnlyIPPort
	cfg.Severities = o.Severities
	cfg.ExcludeTags = o.ExcludeTags
	cfg.NoInteractsh = o.NoInteractsh
	cfg.InteractshURL = o.InteractshURL
	cfg.InteractshToken = o.InteractshToken
	cfg.HTTPProxy = o.HTTPProxy
	cfg.HTTPProxyTest = false
	cfg.Password = o.Password
	cfg.PasswordFile = o.PasswordFile
	cfg.Xray = o.Xray
	cfg.Xscan = o.Xscan
	cfg.OssBucket = o.Oss
	cfg.Findre = o.Findre
	cfg.JSAPIScan = o.JSAPIScan
	// 节点模式不落本地文件/不生成HTML报告
	cfg.OutputFile = ""
	cfg.OutputType = "text"
	cfg.ReportName = ""
	cfg.NoBanner = true
	// prepare()依赖的默认路径
	cfg.APIConfigFilePath = "config/api-config.yaml"

	// 拉取主控设置页配置的测绘key → 覆盖本地api-config.yaml(即配即用, 全节点生效)
	if yml, err := rdb.Get(ctx, "cluster:apiconfig").Result(); err == nil && strings.TrimSpace(yml) != "" {
		_ = os.MkdirAll("config", 0755)
		_ = os.WriteFile(cfg.APIConfigFilePath, []byte(yml), 0644)
	}
	// 域名目标自动开测绘收集: 全端口/标准扫描砍掉子域爆破后, 用测绘引擎补子域与资产
	if !cfg.Hunter && !cfg.Fofa && !cfg.Quake {
		engines := availableMapEngines()
		if hasDomainTarget(task.Targets) && len(engines) > 0 {
			for _, e := range engines {
				if e == "hunter" {
					cfg.Hunter = true
				} else if e == "fofa" {
					cfg.Fofa = true
				} else if e == "quake" {
					cfg.Quake = true
				}
			}
			gologger.Info().Msg("检测到域名目标且测绘key已配置: 自动开启" + strings.Join(engines, "+") + "资产收集")
		}
	}
	cfg.NucleiTemplate = "config/pocs"
	cfg.WorkflowYamlPath = "config/workflow.yaml"
	cfg.FingerConfigFilePath = "config/finger.yaml"
	cfg.DirSearchYaml = "config/dir.yaml"
	cfg.SubdomainWordListFile = "config/subdomains.txt"

	common.SetTargetString(joinTargets(task.Targets))
	common.SetPortString(task.Ports)

	// 初始化(指纹库/hmap等)
	common.InitPrepare()

	return engine.RunScan(ctx)
}

func setTaskState(taskID, status, extra string) {
	ctx, cc := context.WithTimeout(context.Background(), 3*time.Second)
	defer cc()
	rdb.Set(ctx, cluster.TaskStatePrefix+taskID, status+"|"+extra, 24*time.Hour)
	rdb.HSet(ctx, cluster.ProgressPrefix+taskID, map[string]interface{}{
		"status":    status,
		"node":      opt.nodeID,
		"results":   progressCounters.Load(),
		"update_ts": time.Now().Unix(),
	})
}

func collectHeartbeat() cluster.Heartbeat {
	cpu, mem := loadStats()
	hb := cluster.Heartbeat{
		NodeID:  opt.nodeID,
		Name:    opt.nodeName,
		IP:      localIP(),
		OS:      runtime.GOOS + "/" + runtime.GOARCH,
		Version: "abcd-node-1.0",
		CPUPercent: cpu,
		MemPercent: mem,
		Ts:      time.Now().Unix(),
	}
	if t, ok := currentTaskID.Load().(string); ok {
		hb.RunningTask = t
	}
	// 并发模式: 聚合所有在跑任务(逗号串), master/前端按逗号拆
	var tasks []string
	runningSet.Range(func(k, v interface{}) bool {
		if s, ok := k.(string); ok {
			tasks = append(tasks, s)
		}
		return true
	})
	if len(tasks) > 0 {
		hb.RunningTask = strings.Join(tasks, ",")
	}
	return hb
}

func joinTargets(ts []string) string {
	s := ""
	for i, t := range ts {
		if i > 0 {
			s += ","
		}
		s += t
	}
	return s
}

// hasDomainTarget 目标里是否含域名(非纯IP/CIDR/URL也算)
func hasDomainTarget(targets []string) bool {
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if i := strings.Index(t, "://"); i >= 0 {
			t = t[i+3:]
		}
		if i := strings.IndexAny(t, "/"); i >= 0 {
			t = t[:i]
		}
		if i := strings.LastIndex(t, ":"); i >= 0 {
			t = t[:i]
		}
		for _, r := range t {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
				return true // 含字母=域名
			}
		}
	}
	return false
}

// availableMapEngines 从Redis apiconfig提取已配key的引擎列表
func availableMapEngines() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	yml, err := rdb.Get(ctx, "cluster:apiconfig").Result()
	if err != nil {
		return nil
	}
	var engines []string
	if strings.Contains(yml, "hunter:") {
		engines = append(engines, "hunter")
	}
	if strings.Contains(yml, "fofa:") {
		engines = append(engines, "fofa")
	}
	if strings.Contains(yml, "quake:") {
		engines = append(engines, "quake")
	}
	return engines
}
