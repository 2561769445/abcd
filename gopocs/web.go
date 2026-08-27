package gopocs

import (
	"abcd/structs"
	_ "embed"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"net/http"
	"net/url"
	"strings"
	"time"
)

//go:embed dict/tomcat.txt
var tomcatUserPasswdDict string

//go:embed dict/weblogic.txt
var weblogicUserPasswdDict string

//go:embed dict/jboss.txt
var jbossUserPasswdDict string

//go:embed dict/basic.txt
var basicUserPasswdDict string

// webWeakPasswordFingerprints 命中这些指纹时触发对应中间件弱口令爆破
var tomcatFingerprints = []string{"tomcat"}
var weblogicFingerprints = []string{"weblogic"}
var jbossFingerprints = []string{"jboss", "wildfly"}

// normalizeWebFinger 归一化指纹名用于匹配
func normalizeWebFinger(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// hasWebWeakPasswordFingerprint 判断目标指纹是否命中任意中间件
func hasWebWeakPasswordFingerprint(fingers []string) (tomcat, weblogic, jboss, basic bool) {
	for _, f := range fingers {
		fn := normalizeWebFinger(f)
		for _, k := range tomcatFingerprints {
			if strings.Contains(fn, k) {
				tomcat = true
			}
		}
		for _, k := range weblogicFingerprints {
			if strings.Contains(fn, k) {
				weblogic = true
			}
		}
		for _, k := range jbossFingerprints {
			if strings.Contains(fn, k) {
				jboss = true
			}
		}
		// 通用 Basic Auth 弱口令指纹
		if strings.Contains(fn, "basic") || strings.Contains(fn, "basic-auth") {
			basic = true
		}
	}
	return
}

// WebWeakPasswordScan Web 中间件弱口令爆破入口
func WebWeakPasswordScan(info *structs.HostInfo) {
	if structs.GlobalConfig.NoServiceBruteForce {
		return
	}
	u := info.Url
	if u == "" {
		return
	}
	if !strings.HasPrefix(u, "http") {
		u = "http://" + u
	}
	rootURL := ""
	if parsed, err := url.Parse(u); err == nil {
		rootURL = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	}
	// ????? + ?????????????????????????(? /console)???
	fingerSet := make(map[string]struct{})
	if rootURL != "" {
		for _, f := range structs.GlobalResultMap[rootURL+"/"] {
			fingerSet[f] = struct{}{}
		}
		for _, f := range structs.GlobalResultMap[rootURL] {
			fingerSet[f] = struct{}{}
		}
	}
	for url, fs := range structs.GlobalResultMap {
		if !strings.HasPrefix(url, rootURL) {
			continue
		}
		for _, f := range fs {
			fingerSet[f] = struct{}{}
		}
	}
	fingers := make([]string, 0, len(fingerSet))
	for f := range fingerSet {
		fingers = append(fingers, f)
	}
	tomcat, weblogic, jboss, _ := hasWebWeakPasswordFingerprint(fingers)
	// 中间件弱口令统一基于站点根路径探测，避免路径重复拼接
	rootInfo := *info
	rootInfo.Url = rootURL
	if tomcat {
		bruteTomcat(&rootInfo)
	}
	if weblogic {
		bruteWebLogic(&rootInfo)
	}
	if jboss {
		bruteJBoss(&rootInfo)
	}
}

// newNoKeepAliveTransport 构建代理感知的 HTTP 传输层
func newNoKeepAliveTransport() *http.Transport {
	transport := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     true,
	}
	if structs.GlobalConfig.HTTPProxy != "" {
		if proxyURL, err := url.Parse(structs.GlobalConfig.HTTPProxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}
	return transport
}

// doBasicRequest 发起带 Basic Auth 的请求
func doBasicRequest(rawURL, user, pass string, timeout int) (statusCode int, body string, err error) {
	client := &http.Client{
		Transport: newNoKeepAliveTransport(),
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
		if len(buf) > 512*1024 {
			break
		}
	}
	return resp.StatusCode, string(buf), nil
}

// doFormPost 发起表单 POST 请求
func doFormPost(rawURL string, form url.Values, timeout int) (statusCode int, body string, err error) {
	client := &http.Client{
		Transport: newNoKeepAliveTransport(),
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if rerr != nil {
			break
		}
		if len(buf) > 512*1024 {
			break
		}
	}
	return resp.StatusCode, string(buf), nil
}

// writeWebBruteFinding 输出 Web 弱口令命中结果
func writeWebBruteFinding(target, plugin, user, pass string) {
	msg := fmt.Sprintf("%s [%s] %s : %s", target, plugin, user, pass)
	gologger.Silent().Msg("[GoPoc] " + msg)
	GoPocWriteResult(structs.GoPocsResultType{
		PocName:     plugin + "-WeakPassword",
		Security:    "High",
		Description: plugin + " weak password",
		Target:      target,
		InfoLeft:    user,
		InfoRight:   pass,
	})
}

// bruteTomcat 爆破 Tomcat Manager
func bruteTomcat(info *structs.HostInfo) {
	base := info.Url
	if base == "" {
		return
	}
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	paths := []string{"/manager/html", "/manager/status", "/host-manager/html", "/html"}
	userPassList := sortUserPassword(info, tomcatUserPasswdDict, []string{"tomcat"})
	timeout := 5
	if structs.GlobalConfig.WebTimeout > 0 {
		timeout = structs.GlobalConfig.WebTimeout
	}
	for _, path := range paths {
		target := strings.TrimRight(base, "/") + path
		// 先确认该端点确实需要 Basic 认证(401)，避免把公开页面误报为弱口令
		pre, _, err0 := doBasicRequest(target, "", "", timeout)
		if err0 != nil || pre != 401 {
			continue
		}
		for _, up := range userPassList {
			if up.Password == "" {
				continue
			}
			code, _, err := doBasicRequest(target, up.UserName, up.Password, timeout)
			if err != nil {
				continue
			}
			// 401 表示需要认证但失败；200/302 表示认证通过
			if code != 401 && code != 403 {
				writeWebBruteFinding(target, "Tomcat", up.UserName, up.Password)
				return
			}
		}
	}
}

// bruteWebLogic 爆破 WebLogic Console
func bruteWebLogic(info *structs.HostInfo) {
	base := info.Url
	if base == "" {
		return
	}
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	loginURL := strings.TrimRight(base, "/") + "/console/login/LoginForm.jsp"
	userPassList := sortUserPassword(info, weblogicUserPasswdDict, []string{"weblogic"})
	timeout := 5
	if structs.GlobalConfig.WebTimeout > 0 {
		timeout = structs.GlobalConfig.WebTimeout
	}
	for _, up := range userPassList {
		if up.Password == "" {
			continue
		}
		form := url.Values{}
		form.Set("j_username", up.UserName)
		form.Set("j_password", up.Password)
		form.Set("j_character_encoding", "UTF-8")
		code, body, err := doFormPost(loginURL, form, timeout)
		if err != nil {
			continue
		}
		// 成功登录特征: 302 跳走(Location 不含 LoginForm/error) 或 200 且页面不含登录表单/错误提示
		lowBody := strings.ToLower(body)
		isLoginPage := strings.Contains(lowBody, "loginform") || strings.Contains(lowBody, "j_password")
		hasError := strings.Contains(lowBody, "error") || strings.Contains(lowBody, "failed") ||
			strings.Contains(lowBody, "invalid") || strings.Contains(lowBody, "exception")
		if code == 302 {
			if strings.Contains(lowBody, "loginform") || strings.Contains(lowBody, "login_error") {
				continue
			}
			writeWebBruteFinding(loginURL, "WebLogic", up.UserName, up.Password)
			return
		}
		if code == 200 && !isLoginPage && !hasError {
			writeWebBruteFinding(loginURL, "WebLogic", up.UserName, up.Password)
			return
		}
	}
}

// bruteJBoss 爆破 JBoss/WildFly 控制台
func bruteJBoss(info *structs.HostInfo) {
	base := info.Url
	if base == "" {
		return
	}
	if !strings.HasPrefix(base, "http") {
		base = "http://" + base
	}
	paths := []string{"/jmx-console/", "/web-console/ServerInfo.jsp", "/admin-console/", "/invoker/JMXInvokerServlet"}
	userPassList := sortUserPassword(info, jbossUserPasswdDict, []string{"admin", "jboss"})
	timeout := 5
	if structs.GlobalConfig.WebTimeout > 0 {
		timeout = structs.GlobalConfig.WebTimeout
	}
	for _, path := range paths {
		target := strings.TrimRight(base, "/") + path
		pre, _, err0 := doBasicRequest(target, "", "", timeout)
		if err0 != nil || pre != 401 {
			continue
		}
		for _, up := range userPassList {
			if up.Password == "" {
				continue
			}
			code, _, err := doBasicRequest(target, up.UserName, up.Password, timeout)
			if err != nil {
				continue
			}
			if code != 401 && code != 403 {
				writeWebBruteFinding(target, "JBoss", up.UserName, up.Password)
				return
			}
		}
	}
}

// BasicAuthScan éç¨ Basic Auth å¼±å£ä»¤çç ´å¥å£
// å¯¹å·ä½ URL（å¦ /oauth/token /basic ç­）å 401 ç¡®è®¤åçç ´
func BasicAuthScan(info *structs.HostInfo) {
	if structs.GlobalConfig.NoServiceBruteForce {
		return
	}
	u := info.Url
	if u == "" {
		return
	}
	if !strings.HasPrefix(u, "http") {
		u = "http://" + u
	}
	bruteBasicAuth(info, u)
}

// bruteBasicAuth 通用 Basic Auth 弱口令
func bruteBasicAuth(info *structs.HostInfo, target string) {
	userPassList := sortUserPassword(info, basicUserPasswdDict, []string{"admin"})
	timeout := 5
	if structs.GlobalConfig.WebTimeout > 0 {
		timeout = structs.GlobalConfig.WebTimeout
	}
	// 确认端点要求 Basic 认证
	pre, _, err0 := doBasicRequest(target, "", "", timeout)
	if err0 != nil || pre != 401 {
		return
	}
	for _, up := range userPassList {
		if up.Password == "" {
			continue
		}
		code, _, err := doBasicRequest(target, up.UserName, up.Password, timeout)
		if err != nil {
			continue
		}
		if code != 401 && code != 403 {
			writeWebBruteFinding(target, "BasicAuth", up.UserName, up.Password)
			return
		}
	}
}
