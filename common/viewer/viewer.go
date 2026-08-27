package viewer

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// viewer.go 轻量报告查看器：扫描完成后可在浏览器中浏览 HTML 漏洞报告与日志。

var (
	authToken   string
	reportDir   = "report"
	logFile     = "audit.log"
	resultFile  = "result.txt"
)

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func tokenHash(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func validToken(r *http.Request) bool {
	c, err := r.Cookie("viewer_token")
	if err != nil {
		return false
	}
	return c.Value == authToken
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !validToken(r) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func page(w http.ResponseWriter, title, body string) {
	fmt.Fprintf(w, "<html><head><meta charset='utf-8'><title>%s</title></head><body style='font-family:monospace;background:#0d1117;color:#c9d1d9;padding:20px'>%s</body></html>", html.EscapeString(title), body)
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		if r.Form.Get("token") == authToken {
			http.SetCookie(w, &http.Cookie{Name: "viewer_token", Value: authToken, Path: "/", MaxAge: 86400})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		page(w, "Login", "<p style='color:red'>Token 错误</p><form method='post'><input name='token' placeholder='token'><button>登录</button></form>")
		return
	}
	page(w, "Login", "<form method='post'><input name='token' placeholder='token'><button>登录</button></form><p>启动时控制台会打印 token</p>")
}

func collectReports() []string {
	var out []string
	_ = filepath.Walk(reportDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".html") || strings.HasSuffix(strings.ToLower(path), ".htm")) {
			out = append(out, path)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	reports := collectReports()
	var sb strings.Builder
	sb.WriteString("<h2>abcd 报告查看器</h2>")
	sb.WriteString("<a href='/dashboard'>数据总览</a> | <a href='/logout'>退出</a><hr>")
	if len(reports) == 0 {
		sb.WriteString("<p>report/ 目录下暂无报告</p>")
	} else {
		sb.WriteString("<ul>")
		for _, f := range reports {
			name := strings.TrimPrefix(f, reportDir+string(os.PathSeparator))
			sb.WriteString(fmt.Sprintf("<li><a href='/report?file=%s'>%s</a></li>", html.EscapeString(name), html.EscapeString(name)))
		}
		sb.WriteString("</ul>")
	}
	page(w, "Reports", sb.String())
}

func handleReport(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("file")
	if strings.Contains(name, "..") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	path := filepath.Join(reportDir, filepath.Base(name))
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func handleDashboard(w http.ResponseWriter, r *http.Request) {
	var sb strings.Builder
	sb.WriteString("<h2>扫描数据总览</h2>")
	sb.WriteString("<a href='/'>返回报告列表</a><hr>")
	// result.txt 统计
	if data, err := os.ReadFile(resultFile); err == nil {
		lines := strings.Split(string(data), "\n")
		counts := map[string]int{}
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l == "" {
				continue
			}
			key := "Other"
			if strings.HasPrefix(l, "[") {
				if i := strings.Index(l, "]"); i > 0 {
					key = l[1:i]
				}
			}
			counts[key]++
		}
		sb.WriteString("<h3>result.txt 统计</h3><table border='1' cellpadding='4'>")
		keys := make([]string, 0, len(counts))
		for k := range counts {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>", html.EscapeString(k), counts[k]))
		}
		sb.WriteString("</table>")
	}
	// audit.log tail
	if data, err := os.ReadFile(logFile); err == nil {
		lines := strings.Split(string(data), "\n")
		tail := lines
		if len(lines) > 50 {
			tail = lines[len(lines)-50:]
		}
		sb.WriteString("<h3>audit.log 最近日志</h3><pre>")
		sb.WriteString(html.EscapeString(strings.Join(tail, "\n")))
		sb.WriteString("</pre>")
	}
	page(w, "Dashboard", sb.String())
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "viewer_token", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Run 启动报告查看器服务
func Run(addr string) {
	if addr == "" {
		addr = "127.0.0.1:8081"
	}
	authToken = randomString(16)
	mux := http.NewServeMux()
	mux.HandleFunc("/", requireAuth(handleIndex))
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/report", requireAuth(handleReport))
	mux.HandleFunc("/dashboard", requireAuth(handleDashboard))
	mux.HandleFunc("/logout", handleLogout)
	gologger.Info().Msgf("[Viewer] 报告查看器已启动: http://%s  (token: %s)", addr, authToken)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		_ = srv.ListenAndServe()
	}()
}
