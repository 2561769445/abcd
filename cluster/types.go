package cluster

import "encoding/json"

// 分布式主控-分节点共享协议类型与Redis键名常量

const (
	QueueTasks        = "queue:tasks"   // 公共任务队列(自动分配)
	QueueNodePrefix   = "queue:node:"   // 指定节点队列前缀
	QueueResults      = "queue:results" // 结果上报队列
	QueueResultsRetry = "queue:results:retry"
	HashNodes         = "nodes"          // 节点心跳hash: field=nodeID -> Heartbeat JSON
	ProgressPrefix    = "task:progress:" // 进度hash前缀: key=task:progress:{id}
	CtrlChannelPre    = "ctrl:"          // 控制指令pubsub前缀 ctrl:{nodeID}
	TaskStatePrefix   = "task:state:"    // 任务实时状态 string key
	ExecResultPrefix  = "exec:result:"   // 节点命令执行回执
	FileTmpPrefix     = "nodefile:"      // 文件传输中转(base64)
)

// ScanOptions 任务携带的扫描参数(完整映射structs.GlobalConfig, 与命令行功能对齐)
type ScanOptions struct {
	// 端口扫描
	PortScanType       string `json:"port_scan_type,omitempty"` // tcp/syn
	TCPPortScanThreads int    `json:"tcp_port_scan_threads,omitempty"`
	SYNPortScanThreads int    `json:"syn_scan_threads,omitempty"`
	NoPortString       string `json:"no_port,omitempty"` // 禁扫端口
	MasscanPath        string `json:"masscan_path,omitempty"`
	PortsThreshold     int    `json:"ports_max_count,omitempty"`
	TCPPortScanTimeout int    `json:"port_scan_timeout,omitempty"`
	AdaptiveTCP        bool   `json:"adaptive_tcp,omitempty"`
	// 主机发现
	SkipHostDiscovery bool `json:"skip_host_discovery,omitempty"`
	NoICMPPing        bool `json:"no_icmp_ping,omitempty"`
	TCPPing           bool `json:"tcp_ping,omitempty"`
	// 协议识别
	GetBannerThreads int `json:"nmap_threads,omitempty"`
	GetBannerTimeout int `json:"nmap_timeout,omitempty"`
	// 子域名
	Subdomain                  bool `json:"subdomain,omitempty"`
	NoSubdomainBruteForce      bool `json:"no_subdomain_brute,omitempty"`
	NoSubFinder                bool `json:"no_subfinder,omitempty"`
	SubdomainBruteForceThreads int  `json:"subdomain_brute_threads,omitempty"`
	AllowLocalAreaDomain       bool `json:"local_domain,omitempty"`
	AllowCDNAssets             bool `json:"allow_cdn,omitempty"`
	NoHostBind                 bool `json:"no_host_bind,omitempty"`
	// Web探针
	WebThreads  int  `json:"web_threads,omitempty"`
	WebTimeout  int  `json:"web_timeout,omitempty"`
	NoDirSearch bool `json:"no_dir_search,omitempty"`
	// 代理
	HTTPProxy string `json:"http_proxy,omitempty"`
	// 空间搜索引擎(配合config/api-config.yaml里的key)
	Hunter         bool `json:"hunter,omitempty"`
	Fofa           bool `json:"fofa,omitempty"`
	Quake          bool `json:"quake,omitempty"`
	HunterPageSize int  `json:"hunter_page_size,omitempty"`
	HunterMaxPage  int  `json:"hunter_max_page,omitempty"`
	FofaMaxCount   int  `json:"fofa_max_count,omitempty"`
	QuakeSize      int  `json:"quake_max_count,omitempty"`
	LowPerception  bool `json:"low_perception_mode,omitempty"`
	OnlyIPPort     bool `json:"only_ip_port,omitempty"`
	// 漏洞探测
	NoPoc             bool   `json:"no_poc,omitempty"`
	NoGolangPoc       bool   `json:"no_golang_poc,omitempty"`
	DisableGeneralPoc bool   `json:"disable_general_poc,omitempty"`
	PocNameForSearch  string `json:"poc_name,omitempty"`
	GoPocThreads      int    `json:"golang_poc_threads,omitempty"`
	ExcludeTags       string `json:"exclude_tags,omitempty"`
	Severities        string `json:"severity,omitempty"`
	NoServiceBrute    bool   `json:"no_brute,omitempty"`
	// 反连
	NoInteractsh    bool   `json:"no_interactsh,omitempty"`
	InteractshURL   string `json:"interactsh_server,omitempty"`
	InteractshToken string `json:"interactsh_token,omitempty"`
	// 爆破凭证
	Password     string `json:"username_password,omitempty"` // 'admin : password'
	PasswordFile string `json:"username_password_file,omitempty"`
	// abcd扩展
	Xray      bool `json:"xray,omitempty"`
	Xscan     bool `json:"xscan,omitempty"`
	Oss       bool `json:"oss,omitempty"`
	Findre    bool `json:"findre,omitempty"`
	JSAPIScan bool `json:"js,omitempty"`
}

// Task 主控下发给节点的扫描任务
type Task struct {
	ID           string      `json:"id"`
	Name         string      `json:"name,omitempty"`
	Targets      []string    `json:"targets"`
	Ports        string      `json:"ports,omitempty"`
	Options      ScanOptions `json:"options"`
	AssignedNode string      `json:"assigned_node,omitempty"` // 空=任意节点可领
	CreatedAt    int64       `json:"created_at"`
}

// ResultEnvelope 节点上报的结果信封(ddout.OutputMessage原样内嵌)
type ResultEnvelope struct {
	TaskID string          `json:"task_id"`
	NodeID string          `json:"node_id"`
	Msg    json.RawMessage `json:"msg"`
}

// Heartbeat 节点心跳
type Heartbeat struct {
	NodeID      string  `json:"node_id"`
	Name        string  `json:"name"`
	IP          string  `json:"ip"`
	OS          string  `json:"os"`
	Version     string  `json:"version"`
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float64 `json:"mem_percent"`
	RunningTask string  `json:"running_task,omitempty"` // 当前任务ID, 空闲=空
	Ts          int64   `json:"ts"`
}

// CtrlMessage 主控→节点控制指令
type CtrlMessage struct {
	Action  string `json:"action"`            // stop / shutdown / exec
	TaskID  string `json:"task_id,omitempty"` // stop目标任务
	Cmd     string `json:"cmd,omitempty"`     // exec命令/文件路径
	Session string `json:"session,omitempty"` // 终端会话ID(维持cwd)
	ExecID  string `json:"exec_id,omitempty"` // exec回执ID
	Timeout int    `json:"timeout,omitempty"` // exec超时秒
}
