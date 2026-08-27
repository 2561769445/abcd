package http

import (
	_ "embed"
	"abcd/ddout"
	"abcd/structs"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v3"
)

//go:embed findre.yaml
var embedFindreData string

type findreRule struct {
	Name   string `yaml:"name"`
	Regex  string `yaml:"f_regex"`
	compiled *regexp.Regexp
}

var (
	findreRules   []findreRule
	findreOnce    sync.Once
	findreResults []string
	findreLock    sync.Mutex
	findreSeen    map[string]bool
	findreCount   map[string]int
)

// loadFindreRules 加载内嵌 + 外部 config/findre.yaml 规则
func loadFindreRules() {
	findreOnce.Do(func() {
		loadFindreFrom([]byte(embedFindreData))
		if b, err := readExternalFile("config/findre.yaml"); err == nil {
			loadFindreFrom(b)
		}
	})
}

func loadFindreFrom(data []byte) {
	var doc struct {
		Rules []struct {
			Name  string `yaml:"name"`
			Regex string `yaml:"f_regex"`
		} `yaml:"rules"`
	}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return
	}
	for _, r := range doc.Rules {
		if r.Regex == "" {
			continue
		}
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			gologger.Warning().Msgf("[Findre] 规则 %s 编译失败: %v", r.Name, err)
			continue
		}
		// 去重
		dup := false
		for _, e := range findreRules {
			if e.Name == r.Name && e.Regex == r.Regex {
				dup = true
				break
			}
		}
		if !dup {
			findreRules = append(findreRules, findreRule{Name: r.Name, Regex: r.Regex, compiled: re})
		}
	}
}

func readExternalFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// scanFindreOnBody 对文本内容执行 findre 规则扫描
func scanFindreOnBody(source, content string) {
	loadFindreRules()
	findreLock.Lock()
	if findreSeen == nil {
		findreSeen = map[string]bool{}
		findreCount = map[string]int{}
	}
	findreLock.Unlock()
	for _, r := range findreRules {
		m := r.compiled.FindString(content)
		if m == "" {
			continue
		}
		findreLock.Lock()
		key := source + "|" + r.Name + "|" + m
		if !findreSeen[key] {
			findreSeen[key] = true
			// 同一规则在同一源上限 20 条，避免刷屏
			if findreCount[source+"|"+r.Name] < 20 {
				findreResults = append(findreResults, source+" ["+r.Name+"] "+m)
			}
			findreCount[source+"|"+r.Name]++
		}
		findreLock.Unlock()
	}
}

// fetchBody 抓取 URL 内容（限制大小）
func fetchBody(rawURL string, timeout int) string {
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
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	return string(buf)
}

// extractJSURLs 从 HTML 中提取 JS 资源链接
func extractJSURLs(rawURL, body string) []string {
	var urls []string
	re := regexp.MustCompile(`(?is)<script[^>]+src=["']([^"']+)["']`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		u := resolveRelativeURL(rawURL, m[1])
		if u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}

func resolveRelativeURL(base, ref string) string {
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

// FindreScan 对单个 URL 执行 findre 复核（body + 页面 JS）
func FindreScan(rawURL string) {
	body := fetchBody(rawURL, 10)
	if body == "" {
		return
	}
	scanFindreOnBody(rawURL, body)
	if strings.Contains(strings.ToLower(rawURL), ".js") {
		return
	}
	for _, js := range extractJSURLs(rawURL, body) {
		jsBody := fetchBody(js, 10)
		if jsBody != "" {
			scanFindreOnBody(js, jsBody)
		}
	}
}

// FindreScanAll 扫描全部存活 URL（配合 Web 指纹结果）
func FindreScanAll() {
	if !structs.GlobalConfig.Findre {
		return
	}
	loadFindreRules()
	gologger.Info().Msgf("[Findre] 规则加载完成，共 %d 条，开始复核", len(findreRules))
	for rootURL := range structs.GlobalURLMap {
		FindreScan(rootURL)
	}
	FlushFindreResults()
}

// FlushFindreResults 输出 findre 命中结果
func FlushFindreResults() {
	findreLock.Lock()
	defer findreLock.Unlock()
	for _, r := range findreResults {
		ddout.FormatOutput(ddout.OutputMessage{
			Type:          "Findre",
			URI:           r,
			AdditionalMsg: "findre",
		})
		gologger.Silent().Msg("[Findre] " + r)
	}
	findreResults = nil
}
