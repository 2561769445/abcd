package uncover

import (
	"abcd/ddout"
	"abcd/structs"
	"abcd/utils"
	"abcd/utils/cdn"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/subfinder/v2/pkg/passive"
	"gopkg.in/yaml.v3"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var IsVIP bool

type QuakeServiceInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Time      time.Time `json:"time"`
		Transport string    `json:"transport"`
		Service   struct {
			HTTP struct {
				HTMLHash string `json:"html_hash"`
				Favicon  struct {
					Hash     string `json:"hash"`
					Location string `json:"location"`
					Data     string `json:"data"`
				} `json:"favicon"`
				Robots          string   `json:"robots"`
				SitemapHash     string   `json:"sitemap_hash"`
				Server          string   `json:"server"`
				Body            string   `json:"body"`
				XPoweredBy      string   `json:"x_powered_by"`
				MetaKeywords    string   `json:"meta_keywords"`
				RobotsHash      string   `json:"robots_hash"`
				Sitemap         string   `json:"sitemap"`
				Path            string   `json:"path"`
				Title           string   `json:"title"`
				Host            string   `json:"host"`
				SecurityText    string   `json:"security_text"`
				StatusCode      int      `json:"status_code"`
				ResponseHeaders string   `json:"response_headers"`
				URL             []string `json:"http_load_url"`
			} `json:"http"`
			Version  string `json:"version"`
			Name     string `json:"name"`
			Product  string `json:"product"`
			Banner   string `json:"banner"`
			Response string `json:"response"`
		} `json:"service"`
		Images     []interface{} `json:"images"`
		OsName     string        `json:"os_name"`
		Components []interface{} `json:"components"`
		Location   struct {
			DistrictCn  string    `json:"district_cn"`
			ProvinceCn  string    `json:"province_cn"`
			Gps         []float64 `json:"gps"`
			ProvinceEn  string    `json:"province_en"`
			CityEn      string    `json:"city_en"`
			CountryCode string    `json:"country_code"`
			CountryEn   string    `json:"country_en"`
			Radius      float64   `json:"radius"`
			DistrictEn  string    `json:"district_en"`
			Isp         string    `json:"isp"`
			StreetEn    string    `json:"street_en"`
			Owner       string    `json:"owner"`
			CityCn      string    `json:"city_cn"`
			CountryCn   string    `json:"country_cn"`
			StreetCn    string    `json:"street_cn"`
		} `json:"location"`
		Asn       int    `json:"asn"`
		Hostname  string `json:"hostname"`
		Org       string `json:"org"`
		OsVersion string `json:"os_version"`
		IsIpv6    bool   `json:"is_ipv6"`
		IP        string `json:"ip"`
		Port      int    `json:"port"`
	} `json:"data"`
	Meta struct {
		Total        int    `json:"total"`
		PaginationID string `json:"pagination_id"`
	} `json:"meta"`
}

func getQuakeKeys() []string {
	var apiKeys []string
	f, err := os.Open(structs.GlobalConfig.APIConfigFilePath)
	if err != nil {
		gologger.Error().Msgf("打开API Key配置文件 %v 失败", structs.GlobalConfig.APIConfigFilePath)
		return []string{}
	}
	defer f.Close()

	sourceApiKeysMap := map[string][]string{}
	err = yaml.NewDecoder(f).Decode(sourceApiKeysMap)
	for _, source := range passive.AllSources {
		sourceName := strings.ToLower(source.Name())
		if sourceName == "quake" {
			apiKeys = sourceApiKeysMap[sourceName]
			break
		}
	}
	if len(apiKeys) == 0 {
		gologger.Error().Msg("未获取到Quake API Key(主控Web系统设置页可配), 跳过Quake测绘")
		return []string{}
	}

	return apiKeys
}

// 从Fofa中搜索目标
func SearchQuakeCore(keyword string, pageSize int) []string {
	return searchQuakeCore(keyword, pageSize, 0)
}

var quakeRetry sync.Map

func searchQuakeCore(keyword string, pageSize int, retried int) []string {
	// size下限防御(0/负数会导致空查询), 上限500与免费/VIP额度对齐
	if pageSize < 1 {
		pageSize = 1
	}
	if pageSize > 500 {
		pageSize = 500
	}
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	url := "https://quake.360.net/api/v3/search/quake_service"
	keys := getQuakeKeys()
	if len(keys) == 0 {
		gologger.Error().Msg("未配置Quake Key(主控Web系统设置页可配), 跳过Quake测绘")
		return nil
	}
	randKey := keys[rand.Intn(len(keys))]

	data := make(map[string]interface{})
	data["query"] = keyword
	data["start"] = "0"
	data["size"] = strconv.Itoa(pageSize)
	if !IsVIP {
		data["include"] = []string{"ip", "port"}
	}
	jsonData, _ := json.Marshal(data)

	req, err := retryablehttp.NewRequest(http.MethodPost, url, jsonData)
	if err != nil {
		gologger.Error().Msgf("Quake API请求构建失败: %v", err)
		return nil
	}
	req.Header.Set("X-QuakeToken", randKey)
	req.Header.Set("Content-Type", "application/json")

	// 确保不会超速
	time.Sleep(time.Second * 2)
	var results []string

	resp, errDo := client.Do(req)
	if errDo != nil {
		gologger.Error().Msgf("[Quake] [%s] 资产查询失败！请检查网络状态。Error:%s", keyword, errDo.Error())
		return results
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		gologger.Error().Msgf("[Quake] API-KEY错误(401), 请在主控Web设置页检查Quake Key, 跳过Quake测绘。keyword: %s", keyword)
		return results
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[Quake] 获取Quake 响应Body失败: %v", err.Error())
		return results
	}

	var serviceInfo QuakeServiceInfo
	// Quake限流(q3005 "调用API过于频繁", code为字符串会导致下方Unmarshal失败):
	// 反序列化前预检, 节流退避重试(多节点共用同一把Key高发), 最多重试2次
	bodyStr := string(respBody)
	if retried < 2 && (strings.Contains(bodyStr, "q3005") || strings.Contains(bodyStr, "过于频繁")) {
		if _, running := quakeRetry.LoadOrStore(keyword, true); !running {
			wait := time.Duration(retried+1) * 8 * time.Second
			gologger.Info().Msgf("[Quake] 触发限流, %v后重试(%d/2): %s", wait, retried+1, keyword)
			time.Sleep(wait)
			r := searchQuakeCore(keyword, pageSize, retried+1)
			quakeRetry.Delete(keyword)
			return r
		}
		quakeRetry.Delete(keyword)
	}
	err = json.Unmarshal(respBody, &serviceInfo)
	if err != nil {
		gologger.Error().Msg("[Quake] 响应解析失败，疑似Token失效。Quake接口具体返回信息如下：")
		fmt.Println(string(respBody))
		return results
	}

	// 做一个域名缓存，避免重复dns请求
	domainCDNMap := make(map[string]bool)
	var domainList []string

	for _, d := range serviceInfo.Data {
		domainList = append(domainList, d.Service.HTTP.Host)
	}

	domainList = utils.RemoveDuplicateElement(domainList)
	if len(domainList) != 0 {
		gologger.Info().Msgf("正在查询 [%v] 个域名是否为CDN资产", len(domainList))
	}
	cdnDomains, normalDomains, _ := cdn.CheckCDNs(domainList, structs.GlobalConfig.SubdomainBruteForceThreads)
	for _, d := range cdnDomains {
		_, ok := domainCDNMap[d]
		if !ok {
			domainCDNMap[d] = true
		}
	}
	for _, d := range normalDomains {
		_, ok := domainCDNMap[d]
		if !ok {
			domainCDNMap[d] = false
		}
	}

	for _, d := range serviceInfo.Data {
		if d.Service.HTTP.URL == nil {
			t := fmt.Sprintf("%s:%d", d.IP, d.Port)
			if utils.GetItemInArray(results, t) == -1 {
				ddout.FormatOutput(ddout.OutputMessage{
					Type:          "Quake",
					IP:            d.IP,
					IPs:           nil,
					Port:          strconv.Itoa(d.Port),
					Protocol:      "",
					Web:           ddout.WebInfo{},
					Finger:        nil,
					Domain:        "",
					GoPoc:         ddout.GoPocsResultType{},
					URI:           "",
					City:          "",
					Show:          t,
					AdditionalMsg: "",
				})
				// gologger.Silent().Msgf("[Quake] %s", t)
				results = append(results, t)
			}
		} else {
			isCDN := false
			t, ok := domainCDNMap[d.Service.HTTP.Host]
			if ok {
				isCDN = t
			}
			if !isCDN {
				AddIPDomainMap(d.IP, d.Service.HTTP.Host)
			}

			if structs.GlobalConfig.OnlyIPPort && !isCDN {
				u := fmt.Sprintf("%v://%v:%v", strings.ReplaceAll(d.Service.Name, "http/ssl", "https"), d.IP, d.Port)
				if utils.GetItemInArray(results, u) == -1 {
					results = append(results, u)
					// gologger.Silent().Msgf("[Quake] %s", u)
					ddout.FormatOutput(ddout.OutputMessage{
						Type:          "Quake",
						IP:            d.IP,
						IPs:           nil,
						Port:          strconv.Itoa(d.Port),
						Protocol:      d.Service.Name,
						Web:           ddout.WebInfo{},
						Finger:        nil,
						Domain:        "",
						GoPoc:         ddout.GoPocsResultType{},
						URI:           "",
						City:          "",
						Show:          u,
						AdditionalMsg: "",
					})
				}
			} else {
				for _, u := range d.Service.HTTP.URL {
					if utils.GetItemInArray(results, u) == -1 {
						if !isCDN || structs.GlobalConfig.AllowCDNAssets {
							// gologger.Silent().Msgf("[Quake] %s", u)
							ddout.FormatOutput(ddout.OutputMessage{
								Type:          "Quake",
								IP:            d.IP,
								IPs:           nil,
								Port:          strconv.Itoa(d.Port),
								Protocol:      d.Service.Name,
								Web:           ddout.WebInfo{},
								Finger:        nil,
								Domain:        "",
								GoPoc:         ddout.GoPocsResultType{},
								URI:           u,
								City:          "",
								Show:          u,
								AdditionalMsg: "",
							})
							results = append(results, u)
						}
					}
				}
			}
		}

	}
	return results
}

func IsQuakeVIP() bool {
	keys := getQuakeKeys()
	if len(keys) == 0 {
		gologger.Error().Msg("未配置Quake Key(主控Web系统设置页可配), 跳过Quake测绘")
		return false
	}
	randKey := keys[rand.Intn(len(keys))]
	opts := retryablehttp.DefaultOptionsSpraying
	client := retryablehttp.NewClient(opts)

	url := "https://quake.360.net/api/v3/user/info"

	req, err := retryablehttp.NewRequest(http.MethodGet, url, "")
	if err != nil {
		gologger.Error().Msgf("Quake API请求构建失败: %v", err)
		return false
	}
	req.Header.Set("X-QuakeToken", randKey)
	req.Header.Set("Content-Type", "application/json")
	resp, errDo := client.Do(req)
	if errDo != nil {
		gologger.Error().Msgf("[Quake] 用户信息查询失败！请检查网络状态。Error:%s", errDo.Error())
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		gologger.Error().Msgf("[Quake] API-KEY错误(401), 请在主控Web设置页检查Quake Key。")
		return false
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		gologger.Error().Msgf("[Quake] 获取用户信息Body失败: %v", err.Error())
		return false
	}

	if strings.Contains(string(respBody), "终身会员") {
		return true
	}
	if strings.Contains(string(respBody), "高级会员") {
		return true
	}

	return false
}

// SmartQuakeQuery 把裸目标(域名/IP/CIDR/URL/IP:Port)自动包装成Quake检索语法, 已是语法或关键词的透传。
// 背景: Quake对裸字符串按全文模糊检索(与Fofa/Hunter自动识别域名不同),
// 裸传 v2share.org 会被分词全文匹配, 拉回大量无关资产; 必须显式 domain:"xxx" / ip:"x.x.x.x"
func SmartQuakeQuery(keyword string) string {
	k := strings.TrimSpace(keyword)
	if k == "" {
		return k
	}
	// 已是测绘语法(key:"value" / key="value")原样透传
	if strings.Contains(k, `:"`) || strings.Contains(k, `="`) {
		return k
	}
	// URL → 取Host再判断
	if utils.IsURL(k) {
		if u, err := url.Parse(k); err == nil && u.Hostname() != "" {
			k = u.Hostname()
		}
	}
	switch {
	case utils.IsIPv4(k), utils.IsCIDR(k):
		return fmt.Sprintf("ip:%q", k)
	case utils.IsIPRange(k):
		// IP段对齐到CIDR边界(/24 /16 /8)则转换, 否则警告透传
		parts := strings.SplitN(k, "-", 2)
		s, e := net.ParseIP(strings.TrimSpace(parts[0])), net.ParseIP(strings.TrimSpace(parts[1]))
		for _, bits := range []int{24, 16, 8} {
			mask := net.CIDRMask(bits, 32)
			network := s.Mask(mask)
			if s.Equal(network) && e.Equal(lastIPOf(network, mask)) {
				return fmt.Sprintf("ip:%q", network.String()+"/"+strconv.Itoa(bits))
			}
		}
		gologger.Warning().Msgf("[Quake] IP段 %s 未对齐CIDR边界, 原样透传(结果可能不精确), 建议改用CIDR写法", k)
		return keyword
	case utils.IsIPPort(k), utils.IsDomainPort(k):
		if host, _, err := net.SplitHostPort(k); err == nil && host != "" {
			k = host
		}
		if utils.IsIPv4(k) {
			return fmt.Sprintf("ip:%q", k)
		}
		return fmt.Sprintf("domain:%q", k)
	case utils.IsDomain(k):
		return fmt.Sprintf("domain:%q", k)
	}
	// 其余(自定义关键词等)原样透传, 保持旧行为
	return keyword
}

// lastIPOf 计算网段的最后一个IP
func lastIPOf(network net.IP, mask net.IPMask) net.IP {
	last := make(net.IP, len(network))
	for i := range network {
		last[i] = network[i] | ^mask[i]
	}
	return last
}

func QuakeSearch(keywords []string) []string {
	IsVIP = false
	gologger.Info().Msg("正在查询Quake账户权限。")
	IsVIP = IsQuakeVIP()
	if IsVIP {
		gologger.Info().Msgf("VIP")
	} else {
		gologger.Info().Msgf("非VIP")
	}
	gologger.Info().Msgf("准备从 Quake 获取数据")
	var results []string
	for _, keyword := range keywords {
		result := SearchQuakeCore(SmartQuakeQuery(keyword),
			structs.GlobalConfig.QuakeSize)
		results = append(results, result...)
	}
	return utils.RemoveDuplicateElement(results)
}
