package master

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"abcd/cluster"
	"abcd/ddout"

	"github.com/projectdiscovery/gologger"
	"github.com/redis/go-redis/v9"
)

// resultBuf 内存攒批缓冲, 定时/定量批量写PG
type assetInsert struct {
	taskID, nodeID, assetType, ip, port, protocol, uri, domain, title, statusCode, finger, extra string
}

type vulnInsert struct {
	taskID, nodeID, source, vulnID, severity, target, detail, extra string
}

type credInsert struct {
	taskID, nodeID, service, target, detail string
}

// isCredential 判断GoPoc结果是否为弱口令/未授权类凭据
func isCredential(g ddout.GoPocsResultType) bool {
	kw := g.PocName + g.Description
	return strings.Contains(kw, "弱口令") || strings.Contains(kw, "未授权") || strings.Contains(kw, "Login") || strings.Contains(kw, "爆破成功")
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

var (
	assetChan = make(chan assetInsert, 20000)
	vulnChan  = make(chan vulnInsert, 20000)
	credChan  = make(chan credInsert, 20000)
)

// startConsumer 结果异步消费者: BLPOP结果队列 → 解析 → 攒批批量写PG
func startConsumer(ctx context.Context, rdb *redis.Client) {
	go consumeQueue(ctx, rdb)
	go batchWriter(ctx, assetChan, "asset", 500, 2*time.Second)
	go batchWriter(ctx, vulnChan, "vuln", 500, 2*time.Second)
	go batchWriter(ctx, credChan, "cred", 500, 2*time.Second)
}

func consumeQueue(ctx context.Context, rdb *redis.Client) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		res, err := rdb.BRPop(ctx, 3*time.Second, cluster.QueueResults, cluster.QueueResultsRetry).Result()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if len(res) < 2 {
			continue
		}
		handleResult(res[1])
	}
}

func handleResult(payload string) {
	var env cluster.ResultEnvelope
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		gologger.Warning().Msgf("结果信封解析失败: %v", err)
		return
	}
	var msg ddout.OutputMessage
	if err := json.Unmarshal(env.Msg, &msg); err != nil {
		gologger.Warning().Msgf("结果消息解析失败: %v", err)
		return
	}

	switch msg.Type {
	case "GoPoc":
		vulnChan <- vulnInsert{
			taskID: env.TaskID, nodeID: env.NodeID, source: "gopoc",
			vulnID: msg.GoPoc.PocName, severity: normSeverity(msg.GoPoc.Security),
			target: msg.GoPoc.Target, detail: msg.GoPoc.ShowMsg,
			extra: string(env.Msg),
		}
		// 弱口令/未授权凭据独立台账
		if isCredential(msg.GoPoc) {
			credChan <- credInsert{
				taskID: env.TaskID, nodeID: env.NodeID,
				service: msg.GoPoc.PocName, target: msg.GoPoc.Target,
				detail: firstNonEmpty(msg.GoPoc.InfoLeft, msg.GoPoc.ShowMsg),
			}
		}
	case "Nuclei":
		// msg.Nuclei 字段带完整 ResultEvent JSON, 从中精提severity/templateID/target
		vulnID, sev, target := parseNucleiJSON(msg.Nuclei, msg.Show, msg.URI)
		vulnChan <- vulnInsert{
			taskID: env.TaskID, nodeID: env.NodeID, source: "nuclei",
			vulnID: vulnID, severity: sev,
			target: target, detail: msg.Show,
			extra: string(env.Msg),
		}
	default:
		assetChan <- assetInsert{
			taskID: env.TaskID, nodeID: env.NodeID, assetType: msg.Type,
			ip: msg.IP, port: msg.Port, protocol: msg.Protocol,
			uri: msg.URI, domain: msg.Domain,
			title: msg.Web.Title, statusCode: msg.Web.Status,
			finger: strings.Join(msg.Finger, ","),
			extra: string(env.Msg),
		}
	}
}

// normSeverity 统一等级为critical/high/medium/low/info(兼容中文)
func normSeverity(s string) string {
	t := strings.ToLower(strings.TrimSpace(s))
	switch t {
	case "严重", "危急", "critical":
		return "critical"
	case "高危", "高", "high":
		return "high"
	case "中危", "中", "medium", "moderate":
		return "medium"
	case "低危", "低", "low":
		return "low"
	case "提示", "信息", "info", "informational", "unknown", "":
		return "info"
	}
	return t
}

// parseNucleiJSON 从ResultEvent JSON提取 templateID/severity/target
func parseNucleiJSON(raw, show, fallbackTarget string) (name, sev, target string) {
	name, sev, target = "", "", fallbackTarget
	if raw != "" {
		var ev struct {
			TemplateID string `json:"TemplateID"`
			Matched     string `json:"Matched"`
			Info        struct {
				Name string `json:"Name"`
				SeverityHolder struct {
					Severity string `json:"severity"`
				} `json:"SeverityHolder"`
			} `json:"Info"`
			// 兼容小写序列化
			TemplateID2 string `json:"template-id"`
			Host        string `json:"host"`
		}
		if err := json.Unmarshal([]byte(raw), &ev); err == nil {
			if ev.TemplateID != "" {
				name = ev.TemplateID
			} else if ev.TemplateID2 != "" {
				name = ev.TemplateID2
			}
			if ev.Info.SeverityHolder.Severity != "" {
				sev = normSeverity(ev.Info.SeverityHolder.Severity)
			}
			if ev.Matched != "" {
				target = ev.Matched
			}
		}
	}
	// 兜底: Show格式 "[template-id] [severity] matched"
	if name == "" || sev == "" {
		if f := strings.Fields(strings.TrimPrefix(show, "[Nuclei] ")); len(f) >= 3 && strings.HasPrefix(show, "[") {
			if name == "" {
				name = strings.Trim(f[0], "[]")
			}
			if sev == "" {
				sev = normSeverity(strings.Trim(f[1], "[]"))
			}
		}
	}
	if sev == "" {
		sev = "info"
	}
	return
}

// batchWriter 攒批写入: 每N条或每interval落地一次
func batchWriter(ctx context.Context, ch interface{}, kind string, max int, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	switch c := ch.(type) {
	case chan assetInsert:
		buf := make([]assetInsert, 0, max)
		flush := func() {
			if len(buf) == 0 {
				return
			}
			if err := insertAssets(buf); err != nil {
				gologger.Warning().Msgf("资产批量写入失败(%d条): %v", len(buf), err)
			}
			buf = buf[:0]
		}
		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case a := <-c:
				buf = append(buf, a)
				if len(buf) >= max {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	case chan credInsert:
		buf := make([]credInsert, 0, max)
		flush := func() {
			if len(buf) == 0 {
				return
			}
			if err := insertCreds(buf); err != nil {
				gologger.Warning().Msgf("凭据批量写入失败(%d条): %v", len(buf), err)
			}
			buf = buf[:0]
		}
		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case v := <-c:
				buf = append(buf, v)
				if len(buf) >= max {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	case chan vulnInsert:
		buf := make([]vulnInsert, 0, max)
		flush := func() {
			if len(buf) == 0 {
				return
			}
			if err := insertVulns(buf); err != nil {
				gologger.Warning().Msgf("漏洞批量写入失败(%d条): %v", len(buf), err)
			}
			buf = buf[:0]
		}
		for {
			select {
			case <-ctx.Done():
				flush()
				return
			case v := <-c:
				buf = append(buf, v)
				if len(buf) >= max {
					flush()
				}
			case <-ticker.C:
				flush()
			}
		}
	}
}

func insertAssets(rows []assetInsert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO assets
		(task_id,node_id,asset_type,ip,port,protocol,uri,domain,title,status_code,finger,extra,last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,now())
		ON CONFLICT (asset_type,ip,port,uri,finger)
		DO UPDATE SET last_seen=now(), task_id=EXCLUDED.task_id, title=EXCLUDED.title`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.taskID, r.nodeID, r.assetType, r.ip, r.port, r.protocol,
			r.uri, r.domain, r.title, r.statusCode, r.finger, r.extra); err != nil {
			return err
		}
	}
	// 任务发现资产计数
	_, _ = tx.Exec(`UPDATE tasks SET found_assets=(SELECT count(*) FROM assets WHERE task_id=tasks.id)`)
	return tx.Commit()
}

func insertVulns(rows []vulnInsert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO vulns
		(task_id,node_id,source,vuln_id,severity,target,detail,extra,last_seen)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
		ON CONFLICT (source,vuln_id,target,detail)
		DO UPDATE SET last_seen=now(), task_id=EXCLUDED.task_id`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.taskID, r.nodeID, r.source, r.vulnID, r.severity,
			r.target, r.detail, r.extra); err != nil {
			return err
		}
	}
	_, _ = tx.Exec(`UPDATE tasks SET found_vulns=(SELECT count(*) FROM vulns WHERE task_id=tasks.id)`)
	if err := tx.Commit(); err != nil {
		return err
	}
	notifyVulns(rows) // webhook推送高危(异步防抖)
	return nil
}

func insertCreds(rows []credInsert) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO credentials (task_id,node_id,service,target,detail,last_seen)
		VALUES ($1,$2,$3,$4,$5,now())
		ON CONFLICT (service,target,detail)
		DO UPDATE SET last_seen=now(), task_id=EXCLUDED.task_id`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.taskID, r.nodeID, r.service, r.target, r.detail); err != nil {
			return err
		}
	}
	return tx.Commit()
}
