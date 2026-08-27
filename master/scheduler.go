package master

import (
	"strings"

	"context"
	"encoding/json"
	"time"

	"abcd/cluster"

	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
)

// nodeLive 心跳快照(来自Redis)
type nodeLive struct {
	ID         string  `json:"node_id"`
	Name       string  `json:"name"`
	IP         string  `json:"ip"`
	OS         string  `json:"os"`
	Version    string  `json:"version"`
	CPUPercent float64 `json:"cpu_percent"`
	MemPercent float64 `json:"mem_percent"`
	RunningTask string `json:"running_task"`
	MaxConcurrent int `json:"max_concurrent"`
	Ts         int64   `json:"ts"`
}

// startScheduler 调度引擎: 每5s把pending任务派发到最优节点; 同步节点心跳到PG; 回收超时任务
func startScheduler(ctx context.Context, rdb *redis.Client) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncNodes(ctx, rdb)
			dispatchScheduled(ctx)
			dispatchTasks(ctx, rdb)
			syncProgress(ctx, rdb)
			recoverStalled(ctx, rdb)
			finishScanning(ctx, rdb)
		}
	}
}

// syncNodes Redis心跳 → PG nodes表 + 离线检测
func syncNodes(ctx context.Context, rdb *redis.Client) {
	all, err := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	var stale []string
	for id, raw := range all {
		var probe nodeLive
		if json.Unmarshal([]byte(raw), &probe) == nil && now-probe.Ts > 3600 {
			stale = append(stale, id) // 1小时无心跳的残留节点记录清理
			continue
		}
		var n nodeLive
		if json.Unmarshal([]byte(raw), &n) != nil {
			continue
		}
		online := now-n.Ts < 60
		var weight int
		_ = db.QueryRow(`SELECT weight FROM nodes WHERE id=$1`, id).Scan(&weight)
		_, err := db.Exec(`INSERT INTO nodes (id,name,ip,os,version,online,cpu_percent,mem_percent,running_task,last_heartbeat)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,now())
			ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, ip=EXCLUDED.ip, os=EXCLUDED.os,
				version=EXCLUDED.version, online=EXCLUDED.online, cpu_percent=EXCLUDED.cpu_percent,
				mem_percent=EXCLUDED.mem_percent, running_task=EXCLUDED.running_task, last_heartbeat=now()`,
			id, n.Name, n.IP, n.OS, n.Version, online, n.CPUPercent, n.MemPercent, n.RunningTask)
		if err != nil {
			gologger.Warning().Msgf("节点落库失败 %s: %v", id, err)
		}
	}
	// PG里在线但心跳已消失的 → 置离线
	_, _ = db.Exec(`UPDATE nodes SET online=false WHERE online=true AND last_heartbeat < now() - interval '60 seconds'`)
	// 心跳消失超1小时的死节点行(换ID重启/退役) → 删除, 与Redis stale清理对齐
	_, _ = db.Exec(`DELETE FROM nodes WHERE last_heartbeat < now() - interval '1 hour'`)
	if len(stale) > 0 {
		rdb.HDel(ctx, cluster.HashNodes, stale...)
	}
}

// pickBestNode 按负载评分选节点: (100-cpu) + (100-mem) + weight*5, 空闲优先
func pickBestNode(ctx context.Context, rdb *redis.Client, excludeBusy bool) (string, bool) {
	all, err := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err != nil {
		return "", false
	}
	now := time.Now().Unix()
	best := ""
	bestScore := -1.0
	for id, raw := range all {
		var n nodeLive
		if json.Unmarshal([]byte(raw), &n) != nil {
			continue
		}
		if now-n.Ts >= 60 {
			continue // 离线
		}
		scorePenalty := 0.0
		if excludeBusy && n.RunningTask != "" {
			// 并发节点未达上限仍有接单余量(降权但不禁入)
			running := len(strings.Split(n.RunningTask, ","))
			if n.MaxConcurrent <= 0 || running >= n.MaxConcurrent {
				continue
			}
			scorePenalty = 30
		}
		var weight int
		_ = db.QueryRow(`SELECT weight FROM nodes WHERE id=$1`, id).Scan(&weight)
		if weight <= 0 {
			weight = 10
		}
		score := (100-n.CPUPercent)*0.4 + (100-n.MemPercent)*0.2 + float64(weight)*4 - float64(scorePenalty)
		if score > bestScore {
			bestScore = score
			best = id
		}
	}
	return best, best != ""
}

// dispatchScheduled 定时/周期任务到期转pending
// cron_expr格式: 纯数字N = 每N分钟循环重跑; "@once 时间"未支持; 空串=一次性
func dispatchScheduled(ctx context.Context) {
	// scheduled状态 → next_run到期 → pending
	db.Exec(`UPDATE tasks SET status='pending' WHERE status='scheduled' AND next_run IS NOT NULL AND next_run <= now()`)
	// 周期任务: done + cron_expr为纯数字分钟数 + 结束超过周期 → 生成新一轮pending
	rows, err := db.Query(`SELECT id, name, targets, target_count, ports, options, assigned_node, cron_expr FROM tasks WHERE status='done' AND cron_expr ~ '^[0-9]+$' AND finished_at < now() - (cron_expr || ' minutes')::interval`)
	if err != nil {
		return
	}
	type rt struct {
		id, name, targets, ports, options, assigned, cron string
		count                                              int
	}
	var list []rt
	for rows.Next() {
		var r rt
		_ = rows.Scan(&r.id, &r.name, &r.targets, &r.count, &r.ports, &r.options, &r.assigned, &r.cron)
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		newID := r.id + "-r" + time.Now().Format("0102150405")
		_, err := db.Exec(`INSERT INTO tasks (id,name,targets,target_count,ports,options,assigned_node,status,cron_expr,next_run)
			VALUES ($1,$2,$3,$4,$5,$6,$7,'pending',$8, now() + ($8 || ' minutes')::interval)`,
			newID, r.name, r.targets, r.count, r.ports, r.options, r.assigned, r.cron)
		if err == nil {
			// 母任务标记为已完成周期轮, 不再重复克隆
			db.Exec(`UPDATE tasks SET status='archived' WHERE id=$1`, r.id)
		}
	}
}

// dispatchTasks pending任务入Redis队列(指定节点专属队列或公共队列)
func dispatchTasks(ctx context.Context, rdb *redis.Client) {
	rows, err := db.Query(`SELECT id, assigned_node, targets, ports, options FROM tasks WHERE status='pending' LIMIT 50`)
	if err != nil {
		return
	}
	defer rows.Close()
	type pending struct {
		id, assigned, targets, ports, options string
	}
	var list []pending
	for rows.Next() {
		var p pending
		_ = rows.Scan(&p.id, &p.assigned, &p.targets, &p.ports, &p.options)
		list = append(list, p)
	}
	rows.Close()

	for _, p := range list {
		var targets []string
		if json.Unmarshal([]byte(p.targets), &targets) != nil {
			targets = []string{p.targets}
		}
		var opts cluster.ScanOptions
		_ = json.Unmarshal([]byte(p.options), &opts)

		task := cluster.Task{
			ID:      p.id,
			Targets: targets,
			Ports:   p.ports,
			Options: opts,
		}
		// 指定节点但离线 → 保持pending等待
		queue := cluster.QueueTasks
		if p.assigned != "" {
			if !nodeOnline(ctx, rdb, p.assigned) {
				continue
			}
			queue = cluster.QueueNodePrefix + p.assigned
		}
		b, _ := json.Marshal(task)
		if err := rdb.LPush(ctx, queue, string(b)).Err(); err != nil {
			gologger.Warning().Msgf("任务入队失败 %s: %v", p.id, err)
			continue
		}
		db.Exec(`UPDATE tasks SET status='queued', started_at=now() WHERE id=$1`, p.id)
		gologger.Info().Msgf("任务已派发: %s -> %s", p.id, queue)
	}
}

func nodeOnline(ctx context.Context, rdb *redis.Client, nodeID string) bool {
	raw, err := rdb.HGet(ctx, cluster.HashNodes, nodeID).Result()
	if err != nil {
		return false
	}
	var n nodeLive
	if json.Unmarshal([]byte(raw), &n) != nil {
		return false
	}
	return time.Now().Unix()-n.Ts < 60
}

// syncProgress 节点上报的阶段进度(Redis hash) → PG tasks.progress/stage
func syncProgress(ctx context.Context, rdb *redis.Client) {
	rows, err := db.Query(`SELECT id FROM tasks WHERE status IN ('queued','scanning','stopping')`)
	if err != nil {
		return
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		m, err := rdb.HGetAll(ctx, cluster.ProgressPrefix+id).Result()
		if err != nil || len(m) == 0 {
			continue
		}
		pct, stage := "", ""
		if v, ok := m["progress"]; ok {
			pct = v
		}
		if v, ok := m["stage_cn"]; ok {
			stage = v
		}
		if pct != "" || stage != "" {
			if pct == "" {
				pct = "0"
			}
			db.Exec(`UPDATE tasks SET progress=$1, stage=$2 WHERE id=$3 AND status IN ('queued','scanning','stopping')`, pct, stage, id)
		}
	}
}

// recoverStalled 卡死任务回收: queued超30分钟无人领 / scanning超6小时且节点已不在线跑它
func recoverStalled(ctx context.Context, rdb *redis.Client) {
	// queued: 派发后30分钟仍在队列(节点全挂/掉任务)
	db.Exec(`UPDATE tasks SET status='pending', assigned_node=''
		WHERE status='queued' AND started_at < now() - interval '30 minutes'`)
	// scanning: 6小时无结束 + 节点心跳里没人正在跑它 → 回收(避免长任务被误杀)
	rows, err := db.Query(`SELECT id FROM tasks WHERE status='scanning' AND started_at < now() - interval '6 hours'`)
	if err != nil {
		return
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	if len(ids) == 0 {
		return
	}
	all, err := rdb.HGetAll(ctx, cluster.HashNodes).Result()
	if err != nil {
		return
	}
	now := time.Now().Unix()
	running := map[string]bool{}
	for _, raw := range all {
		var n nodeLive
		if json.Unmarshal([]byte(raw), &n) == nil && now-n.Ts < 60 && n.RunningTask != "" {
			running[n.RunningTask] = true
		}
	}
	for _, id := range ids {
		if !running[id] {
			db.Exec(`UPDATE tasks SET status='pending', assigned_node='' WHERE id=$1 AND status='scanning'`, id)
		}
	}
}

// finishScanning 节点上报state=done/failed/stopped → 更新PG任务状态
func finishScanning(ctx context.Context, rdb *redis.Client) {
	// 注意包含stopping: 停止指令下发后节点回报stopped也要能落状态
	rows, err := db.Query(`SELECT id FROM tasks WHERE status IN ('queued','scanning','stopping')`)
	if err != nil {
		return
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	rows.Close()
	for _, id := range ids {
		state, err := rdb.Get(ctx, cluster.TaskStatePrefix+id).Result()
		if err != nil {
			continue
		}
		// state格式: status|extra
		st := state
		if i := indexOf(st, '|'); i >= 0 {
			st = st[:i]
		}
		switch st {
		case "scanning":
			db.Exec(`UPDATE tasks SET status='scanning' WHERE id=$1`, id)
		case "done":
			db.Exec(`UPDATE tasks SET status='done', finished_at=now() WHERE id=$1`, id)
			notifyTaskDone(id) // webhook任务完成通知
			rdb.Del(ctx, cluster.TaskStatePrefix+id)
		case "failed":
			db.Exec(`UPDATE tasks SET status='failed', finished_at=now() WHERE id=$1`, id)
			rdb.Del(ctx, cluster.TaskStatePrefix+id)
		case "stopped":
			db.Exec(`UPDATE tasks SET status='stopped', finished_at=now() WHERE id=$1`, id)
			rdb.Del(ctx, cluster.TaskStatePrefix+id)
		}
	}
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
