package ossbucket

import (
	"abcd/ddout"
	"abcd/structs"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// ossbucket.go 云存储桶(Bucket)未授权检测。
// 根据域名特征识别阿里云/腾讯云/华为云/AWS/七牛/京东/青云/又拍/金山/电信天翼云等 OSS 桶，
// 并尝试列举对象，确认是否存在未授权访问。

type providerPattern struct {
	provider string
	pattern  string
}

var providerPatterns = []providerPattern{
	{"Aliyun-OSS", `[a-z0-9][a-z0-9.-]*\.oss-[a-z0-9-]+\.aliyuncs\.com`},
	{"Aliyun-OSS", `[a-z0-9][a-z0-9.-]*\.aliyuncs\.com`},
	{"AWS-S3", `[a-z0-9][a-z0-9.-]*\.s3[.-][a-z0-9-]*\.amazonaws\.com(\.cn)?`},
	{"AWS-S3", `[a-z0-9][a-z0-9.-]*\.s3\.amazonaws\.com`},
	{"Tencent-COS", `[a-z0-9][a-z0-9.-]*\.cos\.[a-z0-9-]+\.myqcloud\.com`},
	{"Tencent-COS", `[a-z0-9][a-z0-9.-]*\.cos\.ap-[a-z0-9-]+\.myqcloud\.com`},
	{"Huawei-OBS", `[a-z0-9][a-z0-9.-]*\.obs\.[a-z0-9-]+\.myhuaweicloud\.com`},
	{"Qiniu", `[a-z0-9][a-z0-9.-]*\.(qiniucs\.com|qiniudn\.com|clouddn\.com|qbox\.me)`},
	{"JDCloud", `[a-z0-9][a-z0-9.-]*\.s3\.[a-z0-9-]+\.jdcloud-oss\.com`},
	{"JDCloud", `[a-z0-9][a-z0-9.-]*\.s3\.[a-z0-9-]+\.jdcloud\.com`},
	{"QingCloud", `[a-z0-9][a-z0-9.-]*\.qingstor\.com`},
	{"Upyun", `[a-z0-9][a-z0-9.-]*\.(b0|b1|b2)\.upaiyun\.com`},
	{"Upyun", `[a-z0-9][a-z0-9.-]*\.aicdn\.com`},
	{"Kingsoft-KS3", `[a-z0-9][a-z0-9.-]*\.ks3-cn-[a-z0-9-]+\.ksyuncs\.com`},
	{"Kingsoft-KS3", `[a-z0-9][a-z0-9.-]*\.ks3-cn-[a-z0-9-]+\.ksyun\.com`},
	{"CTYun", `[a-z0-9][a-z0-9.-]*\.(o\.ctyun\.cn|obs\.ctyun\.cn)`},
}

var compiledPatterns []*regexp.Regexp

func init() {
	for _, p := range providerPatterns {
		compiledPatterns = append(compiledPatterns, regexp.MustCompile(`(?i)^`+p.pattern+`$`))
	}
}

func detectProvider(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	for i, p := range providerPatterns {
		if compiledPatterns[i].MatchString(host) {
			return p.provider
		}
	}
	return ""
}

func httpDo(rawURL string, timeout int) (int, string) {
	if timeout <= 0 {
		timeout = 10
	}
	client := &http.Client{Timeout: time.Duration(timeout) * time.Second}
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	return resp.StatusCode, string(body)
}

// isListResponse 判断是否为 XML 桶列举响应（ListBucketResult / ListAllMyBucketsResult）
func isListResponse(body string) bool {
	l := strings.ToLower(body)
	return strings.Contains(l, "<listbucketresult") ||
		strings.Contains(l, "<listallmybucketsresult") ||
		(strings.Contains(l, "<key>") && strings.Contains(l, "<name>"))
}

func reportFinding(bucketURL, provider, msg string) {
	full := fmt.Sprintf("[%s] %s %s", provider, bucketURL, msg)
	gologger.Silent().Msg("[OSSBucket] " + full)
	ddout.FormatOutput(ddout.OutputMessage{
		Type:          "OSSBucket",
		URI:           bucketURL,
		AdditionalMsg: provider + " " + msg,
	})
}

// DetectBucket 检测单个 URL 是否为可列举的云桶
func DetectBucket(rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return
	}
	provider := detectProvider(u.Host)
	if provider == "" {
		return
	}
	// 直接尝试列举
	code, body := httpDo(u.Scheme+"://"+u.Host+"/", 10)
	if code == 200 && isListResponse(body) {
		reportFinding(u.Scheme+"://"+u.Host+"/", provider, "bucket 列表可访问 (未授权列举)")
		return
	}
	// 带路径前缀尝试（部分桶需要指定路径）
	code, body = httpDo(u.Scheme+"://"+u.Host+"/?list-type=2", 10)
	if code == 200 && isListResponse(body) {
		reportFinding(u.Scheme+"://"+u.Host+"/?list-type=2", provider, "bucket 列表可访问 (list-type=2)")
	}
}

// DetectBuckets 对全部存活 URL / 域名执行云桶检测
func DetectBuckets() {
	if !structs.GlobalConfig.OssBucket {
		return
	}
	gologger.Info().Msg("[OSSBucket] 云存储桶未授权检测开始")
	seen := map[string]bool{}
	for rootURL := range structs.GlobalURLMap {
		u, err := url.Parse(rootURL)
		if err != nil {
			continue
		}
		if !seen[u.Host] {
			seen[u.Host] = true
			DetectBucket(rootURL)
		}
	}
	gologger.Info().Msg("[OSSBucket] 云存储桶未授权检测结束")
}
