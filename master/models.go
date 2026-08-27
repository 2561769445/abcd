package master

import (
	"database/sql"
	"time"

	_ "github.com/lib/pq"
)

var db *sql.DB

func initDB(dsn string) error {
	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(time.Hour)
	if err = db.Ping(); err != nil {
		return err
	}
	return migrate()
}

func migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS nodes (
			id TEXT PRIMARY KEY,
			name TEXT, ip TEXT, os TEXT, version TEXT,
			online BOOLEAN DEFAULT FALSE,
			cpu_percent REAL DEFAULT 0, mem_percent REAL DEFAULT 0,
			running_task TEXT DEFAULT '',
			weight INT DEFAULT 10,
			last_heartbeat TIMESTAMPTZ,
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS tasks (
			id TEXT PRIMARY KEY,
			name TEXT,
			targets TEXT,
			target_count INT DEFAULT 0,
			ports TEXT DEFAULT '',
			options JSONB DEFAULT '{}',
			assigned_node TEXT DEFAULT '',
			status TEXT DEFAULT 'pending',
			progress INT DEFAULT 0,
			found_assets INT DEFAULT 0,
			found_vulns INT DEFAULT 0,
			cron_expr TEXT DEFAULT '',
			stage TEXT DEFAULT '',
			next_run TIMESTAMPTZ,
			created_by TEXT DEFAULT 'admin',
			created_at TIMESTAMPTZ DEFAULT now(),
			started_at TIMESTAMPTZ,
			finished_at TIMESTAMPTZ
		)`,
		`CREATE TABLE IF NOT EXISTS assets (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT, node_id TEXT,
			asset_type TEXT,           -- ip_alive/port/web/domain/finger...
			ip TEXT DEFAULT '', port TEXT DEFAULT '',
			protocol TEXT DEFAULT '', uri TEXT DEFAULT '',
			domain TEXT DEFAULT '',
			title TEXT DEFAULT '', status_code TEXT DEFAULT '',
			finger TEXT DEFAULT '',     -- 逗号分隔指纹
			extra JSONB DEFAULT '{}',   -- 原始OutputMessage
			tag TEXT DEFAULT '', remark TEXT DEFAULT '',
			first_seen TIMESTAMPTZ DEFAULT now(),
			last_seen TIMESTAMPTZ DEFAULT now(),
			UNIQUE(asset_type, ip, port, uri, finger)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip)`,
		`CREATE INDEX IF NOT EXISTS idx_assets_finger ON assets(finger)`,
		`CREATE TABLE IF NOT EXISTS settings (
			key TEXT PRIMARY KEY,
			value TEXT,
			updated_at TIMESTAMPTZ DEFAULT now()
		)`,
		`CREATE TABLE IF NOT EXISTS credentials (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT,
			node_id TEXT,
			service TEXT,
			target TEXT,
			detail TEXT,
			first_seen TIMESTAMPTZ DEFAULT now(),
			last_seen TIMESTAMPTZ DEFAULT now(),
			UNIQUE(service,target,detail)
		)`,
		`CREATE TABLE IF NOT EXISTS vulns (
			id BIGSERIAL PRIMARY KEY,
			task_id TEXT, node_id TEXT,
			source TEXT DEFAULT '',     -- gopoc/nuclei
			vuln_id TEXT DEFAULT '',    -- poc名/CVE
			severity TEXT DEFAULT '',   -- critical/high/medium/low/info
			target TEXT DEFAULT '',     -- ip:port 或 uri
			detail TEXT DEFAULT '',     -- 展示消息/描述
			extra JSONB DEFAULT '{}',
			status TEXT DEFAULT 'open', -- open/fixed/ignored
			first_seen TIMESTAMPTZ DEFAULT now(),
			last_seen TIMESTAMPTZ DEFAULT now(),
			UNIQUE(source, vuln_id, target, detail)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_vulns_sev ON vulns(severity)`,
		`CREATE TABLE IF NOT EXISTS export_records (
			id BIGSERIAL PRIMARY KEY,
			export_type TEXT, file_path TEXT, fields TEXT,
			row_count INT DEFAULT 0,
			created_by TEXT DEFAULT 'admin',
			created_at TIMESTAMPTZ DEFAULT now()
		)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			return err
		}
	}
	return nil
}

// TaskRow 任务表行
type TaskRow struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Targets      string     `json:"targets"`
	TargetCount  int        `json:"target_count"`
	Ports        string     `json:"ports"`
	Options      string     `json:"options"`
	AssignedNode string     `json:"assigned_node"`
	Status       string     `json:"status"`
	Progress     int        `json:"progress"`
	FoundAssets  int        `json:"found_assets"`
	FoundVulns   int        `json:"found_vulns"`
	CronExpr     string     `json:"cron_expr"`
	Stage       string     `json:"stage"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	StartedAt    sql.NullTime `json:"started_at"`
	FinishedAt   sql.NullTime `json:"finished_at"`
}

// AssetRow 资产表行
type AssetRow struct {
	ID         int64          `json:"id"`
	TaskID     string         `json:"task_id"`
	NodeID     string         `json:"node_id"`
	AssetType  string         `json:"asset_type"`
	IP         string         `json:"ip"`
	Port       string         `json:"port"`
	Protocol   string         `json:"protocol"`
	URI        string         `json:"uri"`
	Domain     string         `json:"domain"`
	Title      string         `json:"title"`
	StatusCode string         `json:"status_code"`
	Finger     string         `json:"finger"`
	Tag        string         `json:"tag"`
	Remark     string         `json:"remark"`
	FirstSeen  time.Time      `json:"first_seen"`
	LastSeen   time.Time      `json:"last_seen"`
}

// VulnRow 漏洞表行
type VulnRow struct {
	ID        int64     `json:"id"`
	TaskID    string    `json:"task_id"`
	NodeID    string    `json:"node_id"`
	Source    string    `json:"source"`
	VulnID    string    `json:"vuln_id"`
	Severity  string    `json:"severity"`
	Target    string    `json:"target"`
	Detail    string    `json:"detail"`
	Status    string    `json:"status"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}
