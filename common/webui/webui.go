package webui

import (
	"crypto/rand"
	"abcd/structs"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// webui.go 内置 Web 管理界面（源自 2026 系列 dddd 二开版本的 webui 能力）。
// 提供任务管理、POC 搜索、报告查看、指纹/工作流配置管理、日志等功能。

var (
	token   string
	tasksMu sync.Mutex
	tasks   []*task
)

type task struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Args      []string  `json:"args"`
	Cmd       string    `json:"cmd"`
	Status    string    `json:"status"` // running / done / stopped / error
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Proc      *exec.Cmd `json:"-"`
	Pid       int       `json:"pid"`
	Output    string    `json:"output"`
	mu        sync.Mutex
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

func authOK(r *http.Request) bool {
	if r.Header.Get("X-Token") == token {
		return true
	}
	c, err := r.Cookie("webui_token")
	return err == nil && c.Value == token
}

func authMW(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			writeJSON(w, map[string]interface{}{"ok": false, "msg": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.Form.Get("token") == token {
		http.SetCookie(w, &http.Cookie{Name: "webui_token", Value: token, Path: "/", MaxAge: 86400})
		writeJSON(w, map[string]interface{}{"ok": true, "token": token})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": false, "msg": "bad token"})
}

func countEmbeddedPocs() int {
	return pocsCount()
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"ok":         true,
		"pocs":       countEmbeddedPocs(),
		"fingers":    len(structs.FingerprintDB),
		"workflows":  len(structs.WorkFlowDB),
		"urls":       len(structs.GlobalURLMap),
		"tasks":      len(tasks),
		"reportDir":  "report",
	})
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"ok": true, "token": token})
}

func handlePocs(w http.ResponseWriter, r *http.Request) {
	search := strings.ToLower(r.URL.Query().Get("search"))
	pocs := listPocs(search)
	writeJSON(w, map[string]interface{}{"ok": true, "total": len(pocs), "pocs": pocs})
}

func handleReports(w http.ResponseWriter, r *http.Request) {
	var files []string
	_ = filepath.Walk("report", func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	sort.Strings(files)
	writeJSON(w, map[string]interface{}{"ok": true, "reports": files})
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Query().Get("file"))
	data, err := os.ReadFile(filepath.Join("report", name))
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "msg": "not found"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func handleLogs(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile("audit.log")
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": true, "logs": ""})
		return
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	writeJSON(w, map[string]interface{}{"ok": true, "logs": strings.Join(lines, "\n")})
}

func handleTasks(w http.ResponseWriter, r *http.Request) {
	tasksMu.Lock()
	out := make([]*task, len(tasks))
	copy(out, tasks)
	tasksMu.Unlock()
	writeJSON(w, map[string]interface{}{"ok": true, "tasks": out})
}

func handleTaskStart(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	target := r.Form.Get("target")
	extra := r.Form.Get("args")
	if target == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "msg": "target required"})
		return
	}
	self, err := os.Executable()
	if err != nil {
		self = "abcd"
	}
	args := []string{"-t", target, "-o", "result.txt"}
	if extra != "" {
		args = append(args, strings.Fields(extra)...)
	}
	t := &task{
		ID:        randomToken(8),
		Target:    target,
		Args:      args,
		Cmd:       self + " " + strings.Join(args, " "),
		Status:    "running",
		StartTime: time.Now(),
	}
	cmd := exec.Command(self, args...)
	t.Proc = cmd
	t.Pid = cmd.Process.Pid
	tasksMu.Lock()
	tasks = append(tasks, t)
	tasksMu.Unlock()
	go func() {
		out, err := cmd.CombinedOutput()
		t.mu.Lock()
		t.Output = string(out)
		t.EndTime = time.Now()
		if err != nil {
			t.Status = "error"
		} else {
			t.Status = "done"
		}
		t.mu.Unlock()
	}()
	writeJSON(w, map[string]interface{}{"ok": true, "task": t})
}

func handleTaskStop(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	tasksMu.Lock()
	var t *task
	for _, x := range tasks {
		if x.ID == id {
			t = x
			break
		}
	}
	tasksMu.Unlock()
	if t == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "msg": "task not found"})
		return
	}
	if t.Proc != nil && t.Proc.Process != nil {
		_ = t.Proc.Process.Kill()
	}
	t.mu.Lock()
	t.Status = "stopped"
	t.mu.Unlock()
	writeJSON(w, map[string]interface{}{"ok": true})
}

func handleGetConfig(w http.ResponseWriter, r *http.Request) {
	which := r.URL.Query().Get("name")
	path := "config/" + which + ".yaml"
	data, err := os.ReadFile(path)
	if err != nil {
		data = []byte("{}")
	}
	writeJSON(w, map[string]interface{}{"ok": true, "name": which, "content": string(data)})
}

func handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	which := r.URL.Query().Get("name")
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
	path := "config/" + which + ".yaml"
	if err := os.MkdirAll("config", 0755); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "msg": err.Error()})
		return
	}
	if err := os.WriteFile(path, body, 0644); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "msg": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true})
}

func handleXray(w http.ResponseWriter, r *http.Request) {
	go func() {
		// 触发外部 xray 扫描（后台执行）
		callXrayExternal()
	}()
	writeJSON(w, map[string]interface{}{"ok": true, "msg": "xray started"})
}

func indexHTML() string {
	return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>abcd WebUI</title>
<style>body{font-family:Menlo,Consolas,monospace;background:#0d1117;color:#c9d1d9;margin:0;padding:20px}
h1{color:#58a6ff}button{background:#238636;color:#fff;border:0;padding:8px 14px;border-radius:6px;cursor:pointer;margin-right:6px}
input,select,textarea{background:#161b22;border:1px solid #30363d;color:#c9d1d9;padding:6px;border-radius:6px;margin:4px}
#bar{background:#161b22;padding:10px;border-radius:8px;margin-bottom:14px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px;margin-bottom:14px}
pre{background:#0d1117;border:1px solid #30363d;padding:10px;overflow:auto;max-height:400px}
.ok{color:#3fb950}.bad{color:#f85149}</style></head><body>
<h1>abcd WebUI</h1>
<div id="bar">token: <input id="token" placeholder="登录 token"><button onclick="login()">登录</button>
<button onclick="stats()">状态</button><button onclick="tasks()">任务</button>
<button onclick="reports()">报告</button><button onclick="pocs()">POC</button>
<button onclick="logs()">日志</button><button onclick="startScan()">扫描目标</button><button onclick="xray()">xray</button></div>
<div id="out" class="card"></div>
<script>
let tk=localStorage.getItem('tk')||'';
async function api(path,opts){opts=opts||{};opts.headers=opts.headers||{};opts.headers['X-Token']=tk;
 const r=await fetch(path,opts);return r.json();}
function login(){tk=document.getElementById('token').value;localStorage.setItem('tk',tk);me();}
async function me(){const j=await api('/api/me');out('<div class="ok">token ok</div>');}
async function stats(){const j=await api('/api/stats');out('<b>POC:</b> '+j.pocs+' <b>指纹:</b> '+j.fingers+' <b>工作流:</b> '+j.workflows+' <b>URL:</b> '+j.urls+'<br><b>任务数:</b> '+j.tasks);}
async function tasks(){const j=await api('/api/tasks');let h='<table border=1 cellpadding=5><tr><th>id</th><th>目标</th><th>状态</th><th>操作</th></tr>';
 (j.tasks||[]).forEach(t=>{h+='<tr><td>'+t.id+'</td><td>'+t.target+'</td><td>'+t.status+'</td><td><button onclick="stop(\''+t.id+'\')">停止</button></td></tr>';});
 h+='</table>';out(h);}
async function stop(id){await api('/api/tasks/stop?id='+id);tasks();}
async function reports(){const j=await api('/api/reports');let h='<b>报告列表</b><ul>';
 (j.reports||[]).forEach(f=>{h+='<li><a href="/api/report?file='+encodeURIComponent(f.split(/[\\\\/]/).pop())+'" target="_blank">'+f+'</a></li>';});
 h+='</ul>';out(h);}
async function pocs(){const q=prompt('POC 关键字:')||'';const j=await api('/api/pocs?search='+encodeURIComponent(q));
 let h='<b>POC ('+j.total+')</b><pre>'+ (j.pocs||[]).join('\\n') +'</pre>';out(h);}
async function logs(){const j=await api('/api/logs');out('<b>audit.log</b><pre>'+escapeHtml(j.logs)+'</pre>');}
async function startScan(){const tgt=prompt('目标:')||'';if(!tgt)return;const extra=prompt('额外参数(如 -p 80,443):')||'';
 await api('/api/tasks/start','POST');tasks();}
async function xray(){await api('/api/xray');out('<span class="ok">xray 已触发</span>');}
function out(h){document.getElementById('out').innerHTML=h;}
function escapeHtml(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script></body></html>`
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML()))
}

// Run 启动 Web UI 服务
func Run(addr string) {
	if addr == "" {
		addr = "127.0.0.1:8082"
	}
	token = randomToken(16)
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/login", handleLogin)
	mux.HandleFunc("/api/me", authMW(handleMe))
	mux.HandleFunc("/api/stats", authMW(handleStats))
	mux.HandleFunc("/api/pocs", authMW(handlePocs))
	mux.HandleFunc("/api/reports", authMW(handleReports))
	mux.HandleFunc("/api/report", authMW(handleReport))
	mux.HandleFunc("/api/logs", authMW(handleLogs))
	mux.HandleFunc("/api/tasks", authMW(handleTasks))
	mux.HandleFunc("/api/tasks/start", authMW(handleTaskStart))
	mux.HandleFunc("/api/tasks/stop", authMW(handleTaskStop))
	mux.HandleFunc("/api/config", authMW(handleGetConfig))
	mux.HandleFunc("/api/config/save", authMW(handleSaveConfig))
	mux.HandleFunc("/api/xray", authMW(handleXray))
	gologger.Info().Msgf("[WebUI] 管理界面已启动: http://%s  (token: %s)", addr, token)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		_ = srv.ListenAndServe()
	}()
}

var _ = fmt.Sprintf
