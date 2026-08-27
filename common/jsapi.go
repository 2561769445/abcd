package common

import (
	"abcd/ddout"
	"abcd/structs"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// jsapi.go JS 接口提取与敏感信息(API/ak/sk/密码/邮箱/URL)扫描。
// 灵感来源于多款 dddd 二开版本的“JS 接口/泄露扫描”能力。

var (
	reScriptSrc  = regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)
	reAPIPath    = regexp.MustCompile(`(?i)["'](/[a-z0-9_\-/]{3,}(?:api|action|servlet|list|get|set|query|login|upload|download|export|import|search|info|data)[a-z0-9_\-/]*)["']`)
	reAKSK       = regexp.MustCompile(`(?i)(access_?key_?id|access_?key_?secret|secret_?access_?key|secret_?key)\s*[=:]\s*["']([A-Za-z0-9+/=_\-]{16,64})["']`)
	rePassword   = regexp.MustCompile(`(?i)["']?(password|passwd|pwd|user_pass|db_pass|redis_pass|mysql_pass)["']?\s*[=:]\s*["']([^"']{4,})["']`)
	reEmail      = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reCredURL    = regexp.MustCompile(`(?i)(https?://[^\s"']+:[^\s"']+@[^\s"']+)`)
	reJDBC       = regexp.MustCompile(`(?i)jdbc:[a-z:]+://[^\s"']+`)
	reInnerIP    = regexp.MustCompile(`(?i)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})`)
	jsSeenMu     sync.Mutex
	jsSeen       = map[string]bool{}
)

func jsHTTPGet(rawURL string, timeout int) string {
	if timeout <= 0 {
		timeout = 10
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	return string(b)
}

func jsResolve(base, ref string) string {
	if strings.HasPrefix(ref, "//") {
		if u, err := url.Parse(base); err == nil {
			return u.Scheme + ":" + ref
		}
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	ru, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return bu.ResolveReference(ru).String()
}

func jsReport(kind, uri, match string) {
	msg := "[" + kind + "] " + uri + " => " + match
	gologger.Silent().Msg("[JS-API] " + msg)
	ddout.FormatOutput(ddout.OutputMessage{
		Type:          "JS-" + kind,
		URI:           uri,
		AdditionalMsg: match,
	})
}

func scanJSContent(rawURL, content string) {
	emit := func(kind, match string) {
		key := kind + "|" + rawURL + "|" + match
		jsSeenMu.Lock()
		if jsSeen[key] {
			jsSeenMu.Unlock()
			return
		}
		jsSeen[key] = true
		jsSeenMu.Unlock()
		jsReport(kind, rawURL, match)
	}
	// 接口路径
	for _, m := range reAPIPath.FindAllStringSubmatch(content, -1) {
		if len(m) > 1 {
			emit("API", m[1])
		}
	}
	// AK/SK
	for _, m := range reAKSK.FindAllStringSubmatch(content, -1) {
		if len(m) > 2 {
			emit("AKSK", m[1]+"="+m[2])
		}
	}
	// 密码
	for _, m := range rePassword.FindAllStringSubmatch(content, -1) {
		if len(m) > 2 {
			emit("Password", m[1]+"="+m[2])
		}
	}
	// 邮箱
	for _, m := range reEmail.FindAllString(content, -1) {
		emit("Email", m)
	}
	// 带凭据 URL
	for _, m := range reCredURL.FindAllString(content, -1) {
		emit("CredURL", m)
	}
	// JDBC
	for _, m := range reJDBC.FindAllString(content, -1) {
		emit("JDBC", m)
	}
	// 内网 IP
	for _, m := range reInnerIP.FindAllString(content, -1) {
		emit("InnerIP", m)
	}
}

// JSAPIScan 扫描单个 URL 及其 JS 资源
func JSAPIScan(rawURL string) {
	body := jsHTTPGet(rawURL, 10)
	if body == "" {
		return
	}
	scanJSContent(rawURL, body)
	if strings.Contains(strings.ToLower(rawURL), ".js") {
		return
	}
	seen := map[string]bool{}
	for _, m := range reScriptSrc.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		js := jsResolve(rawURL, m[1])
		if js == "" || seen[js] {
			continue
		}
		seen[js] = true
		jsBody := jsHTTPGet(js, 10)
		if jsBody != "" {
			scanJSContent(js, jsBody)
		}
	}
}

// JSAPIScanAll 扫描全部存活 URL
func JSAPIScanAll() {
	if !structs.GlobalConfig.JSAPIScan {
		return
	}
	gologger.Info().Msg("[JS-API] JS 接口/敏感信息扫描开始")
	for rootURL := range structs.GlobalURLMap {
		JSAPIScan(rootURL)
	}
	gologger.Info().Msg("[JS-API] JS 接口/敏感信息扫描结束")
}
