package node

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"


	"abcd/cluster"

	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
)

type nodeOptions struct {
	redisAddr   string
	redisPass   string
	redisDB     int
	nodeName    string
	nodeID      string
	maxTasks    int // 预留: 当前版本串行=1
	pollTimeout int // 领任务阻塞秒数
}

var (
	opt      nodeOptions
	rdb      *redis.Client
	nodeCtx  context.Context
	stopChan = make(chan os.Signal, 1)
	sessions = sync.Map{} // 终端会话ID → 工作目录
)

// shQuote shell单引号安全包裹
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// Run -node 模式入口
func Run() {
	fs := flag.NewFlagSet("abcd-node", flag.ExitOnError)
	fs.StringVar(&opt.redisAddr, "r", "127.0.0.1:6379", "Redis地址(主控)")
	fs.StringVar(&opt.redisPass, "rp", "", "Redis密码")
	fs.IntVar(&opt.redisDB, "rdb-n", 0, "Redis DB编号")
	fs.StringVar(&opt.nodeName, "n", "", "节点名称(默认主机名)")
	fs.IntVar(&opt.pollTimeout, "poll", 5, "领任务阻塞超时(秒)")
	_ = fs.Parse(os.Args[2:])

	if opt.nodeName == "" {
		h, _ := os.Hostname()
		opt.nodeName = h
	}
	// 稳定ID=节点名: 重启不换ID, 不产生重复节点行(命名需保证唯一, 一键脚本默认 node-公网IP)
	opt.nodeID = opt.nodeName

	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
	nodeCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	rdb = redis.NewClient(&redis.Options{
		Addr:     opt.redisAddr,
		Password: opt.redisPass,
		DB:       opt.redisDB,
	})
	if err := rdb.Ping(nodeCtx).Err(); err != nil {
		gologger.Fatal().Msgf("连接Redis失败 %s: %v", opt.redisAddr, err)
	}

	gologger.Info().Msgf("abcd 节点启动: id=%s name=%s redis=%s", opt.nodeID, opt.nodeName, opt.redisAddr)

	// 心跳goroutine
	go heartbeatLoop(nodeCtx, cancel)
	// 控制指令订阅
	go ctrlLoop(nodeCtx, cancel)
	// 主循环: 领任务执行(串行)
	go taskLoop(nodeCtx)

	// 消费退出信号(SIGTERM/SIGINT/控制指令) → 优雅退出
	select {
	case <-stopChan:
		gologger.Info().Msg("收到退出信号")
	case <-nodeCtx.Done():
	}
	cancel()
	// 给在跑任务/心跳清理一点时间
	time.Sleep(500 * time.Millisecond)
	gologger.Info().Msg("节点退出")
}

func heartbeatLoop(ctx context.Context, cancel context.CancelFunc) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	send := func() {
		hb := collectHeartbeat()
		b, _ := json.Marshal(hb)
		if err := rdb.HSet(ctx, cluster.HashNodes, opt.nodeID, string(b)).Err(); err != nil {
			gologger.Warning().Msgf("心跳上报失败: %v", err)
		}
	}
	send()
	for {
		select {
		case <-ctx.Done():
			// 优雅下线: 清理自己的心跳
			_ = rdb.HDel(context.Background(), cluster.HashNodes, opt.nodeID).Err()
			cancel()
			return
		case <-ticker.C:
			send()
		}
	}
}

func ctrlLoop(ctx context.Context, cancel context.CancelFunc) {
	sub := rdb.Subscribe(ctx, cluster.CtrlChannelPre+opt.nodeID, cluster.CtrlChannelPre+"all")
	defer sub.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-sub.Channel():
			if !ok {
				return
			}
			var cm cluster.CtrlMessage
			if err := json.Unmarshal([]byte(msg.Payload), &cm); err != nil {
				continue
			}
			switch cm.Action {
			case "exec":
				// 远程命令执行(主控Web终端): 带session维持工作目录(cd持久)
				go func(cm cluster.CtrlMessage) {
					timeout := time.Duration(cm.Timeout) * time.Second
					if timeout <= 0 || timeout > 300*time.Second {
						timeout = 120 * time.Second
					}
					ectx, ecancel := context.WithTimeout(context.Background(), timeout)
					defer ecancel()
					cmdStr := cm.Cmd
					if cm.Session != "" {
						wd := ""
						if v, ok := sessions.Load(cm.Session); ok {
							wd, _ = v.(string)
						}
						cmdStr = "cd " + shQuote(wd) + " 2>/dev/null; " + cm.Cmd + "; echo __CWD__:$(pwd)"
					}
					out, err := exec.CommandContext(ectx, "/bin/bash", "-c", cmdStr).CombinedOutput()
					result := string(out)
					if cm.Session != "" {
						if i := strings.LastIndex(result, "__CWD__:"); i >= 0 {
							wd := strings.TrimSpace(result[i+len("__CWD__:"):])
							if j := strings.IndexByte(wd, '\n'); j >= 0 {
								wd = wd[:j]
							}
							wd = strings.TrimRight(wd, "\r ")
							if wd != "" {
								sessions.Store(cm.Session, wd)
							}
							result = result[:i]
						}
					}
					if len(result) > 64*1024 {
						result = result[:64*1024] + "\n...[truncated 64KB]"
					}
					if err != nil {
						result += "\n[exit error: " + err.Error() + "]"
					}
					rctx, rc := context.WithTimeout(context.Background(), 5*time.Second)
					defer rc()
					rdb.Set(rctx, cluster.ExecResultPrefix+cm.ExecID, result, 10*time.Minute)
				}(cm)
			case "putfile":
				// 文件上传: Redis取base64写盘
				go func(cm cluster.CtrlMessage) {
					fctx, fc := context.WithTimeout(context.Background(), 60*time.Second)
					defer fc()
					result := "ERR no content"
					if b64, err := rdb.Get(fctx, cluster.FileTmpPrefix+cm.ExecID).Result(); err == nil {
						rdb.Del(fctx, cluster.FileTmpPrefix+cm.ExecID)
						if data, err := base64.StdEncoding.DecodeString(b64); err == nil {
							if err := os.MkdirAll(filepath.Dir(cm.Cmd), 0755); err == nil {
								if err := os.WriteFile(cm.Cmd, data, 0755); err != nil {
									result = "ERR write: " + err.Error()
								} else {
									result = "OK saved " + cm.Cmd + " (" + strconv.Itoa(len(data)) + " bytes)"
								}
							} else {
								result = "ERR mkdir: " + err.Error()
							}
						} else {
							result = "ERR b64: " + err.Error()
						}
					}
					rdb.Set(fctx, cluster.ExecResultPrefix+cm.ExecID, result, 10*time.Minute)
				}(cm)
			case "getfile":
				// 文件下载: 读文件base64回传(<=50MB)
				go func(cm cluster.CtrlMessage) {
					fctx, fc := context.WithTimeout(context.Background(), 60*time.Second)
					defer fc()
					result := "ERR read: " + cm.Cmd
					if data, err := os.ReadFile(cm.Cmd); err == nil {
						if len(data) > 50<<20 {
							result = "ERR too large >50MB"
						} else {
							result = "OK " + base64.StdEncoding.EncodeToString(data)
						}
					}
					rdb.Set(fctx, cluster.ExecResultPrefix+cm.ExecID, result, 10*time.Minute)
				}(cm)
			case "lsdir":
				// 目录列表(Go原生): JSON条目
				go func(cm cluster.CtrlMessage) {
					fctx, fc := context.WithTimeout(context.Background(), 30*time.Second)
					defer fc()
					type entry struct {
						Name string `json:"name"`
						Size int64  `json:"size"`
						Dir  bool   `json:"dir"`
						Mod  string `json:"mod"`
					}
					var out []entry
					dir := cm.Cmd
					if dir == "" {
						dir = "/"
					}
					if ents, err := os.ReadDir(dir); err == nil {
						for _, e := range ents {
							info, _ := e.Info()
							sz, mt := int64(0), ""
							if info != nil {
								sz = info.Size()
								mt = info.ModTime().Format("01-02 15:04")
							}
							out = append(out, entry{e.Name(), sz, e.IsDir(), mt})
						}
						b, _ := json.Marshal(out)
						rdb.Set(fctx, cluster.ExecResultPrefix+cm.ExecID, "OK "+string(b), 10*time.Minute)
					} else {
						rdb.Set(fctx, cluster.ExecResultPrefix+cm.ExecID, "ERR "+err.Error(), 10*time.Minute)
					}
				}(cm)
			case "stop":
				// 并发模式: 按taskID精确kill对应子进程
				if cm.TaskID != "" {
					if f, ok := childCancels.Load(cm.TaskID); ok {
						gologger.Info().Msgf("停止并发子任务: %s", cm.TaskID)
						f.(context.CancelFunc)()
					}
				}
				if cur, ok := currentTaskID.Load().(string); ok && (cm.TaskID == "" || cm.TaskID == cur) {
					gologger.Info().Msgf("收到主控停止指令: task=%s", cm.TaskID)
					cancelCurrentTask()
				}
			case "shutdown":
				gologger.Info().Msg("收到主控远程下线指令")
				// systemd管理下直接退出会被Restart=always拉起, 必须systemctl stop自身
				if os.Getenv("INVOCATION_ID") != "" {
					_ = exec.Command("/bin/sh", "-c", "systemctl stop abcd-node").Run()
				}
				cancel()
				return
			}
		}
	}
}

// nodeConcurrency 并发任务数: ABCD_NODE_CONCURRENCY, 默认1(串行, 旧行为); >1时任务fork子进程执行(全局状态进程隔离)
func nodeConcurrency() int {
	if v := os.Getenv("ABCD_NODE_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 1
}

func taskLoop(ctx context.Context) {
	cc := nodeConcurrency()
	if cc > 1 {
		gologger.Info().Msgf("节点并发模式: 最多同时执行 %d 个任务(子进程隔离)", cc)
	}
	sem := make(chan struct{}, cc)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// 优先自己节点专属队列, 再公共队列
		res, err := rdb.BRPop(ctx, time.Duration(opt.pollTimeout)*time.Second,
			cluster.QueueNodePrefix+opt.nodeID, cluster.QueueTasks).Result()
		if err != nil {
			if err == redis.Nil || ctx.Err() != nil {
				continue
			}
			if err.Error() == "context canceled" {
				return
			}
			gologger.Warning().Msgf("领任务异常: %v", err)
			time.Sleep(3 * time.Second)
			continue
		}
		if len(res) < 2 {
			continue
		}
		var task cluster.Task
		if err := json.Unmarshal([]byte(res[1]), &task); err != nil {
			gologger.Error().Msgf("任务解析失败: %v", err)
			continue
		}
		// 全部走子进程: 信号量限并发, 进程级隔离(停止=kill进程组秒停, 引擎阶段内不响应取消的问题根除)
		sem <- struct{}{}
		go func(t cluster.Task) {
			defer func() { <-sem }()
			execChild(ctx, &t)
		}(task)
	}
}

func localIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}
