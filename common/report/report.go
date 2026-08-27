package report

import (
	"abcd/ddout"
	"abcd/structs"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"os"
	"strconv"
	"strings"
	"time"
)

// ---------------- 缓冲与统计 ----------------
var reportStarted = false
var nucleiEvents []output.ResultEvent
var gopocEvents []structs.GoPocsResultType

func getSeverity(s severity.Severity) string {
	switch s {
	case severity.Info:
		return "Info"
	case severity.Low:
		return "Low"
	case severity.Medium:
		return "Medium"
	case severity.High:
		return "High"
	case severity.Critical:
		return "Critical"
	}
	return "Unknown"
}

// ---------------- 统计计算 ----------------
func countAliveHosts() int {
	seen := make(map[string]struct{})
	for ip := range structs.GlobalIPPortMap {
		if ip != "" {
			host := strings.Split(ip, ":")[0]
			seen[host] = struct{}{}
		}
	}
	for rootURL := range structs.GlobalURLMap {
		if strings.Contains(rootURL, "://") {
			parts := strings.SplitN(rootURL, "://", 2)
			if len(parts) == 2 {
				host := strings.Split(parts[1], ":")[0]
				seen[host] = struct{}{}
			}
		}
	}
	return len(seen)
}

func countFingers() int {
	n := 0
	for _, fs := range structs.GlobalResultMap {
		n += len(fs)
	}
	return n
}

func countPorts() int {
	seen := make(map[string]struct{})
	for hostPort := range structs.GlobalIPPortMap {
		seen[hostPort] = struct{}{}
	}
	for rootURL, entity := range structs.GlobalURLMap {
		if entity.Port > 0 {
			host := rootURL
			if strings.Contains(rootURL, "://") {
				host = strings.SplitN(rootURL, "://", 2)[1]
				host = strings.Split(host, ":")[0]
			}
			seen[host+":"+strconv.Itoa(entity.Port)] = struct{}{}
		}
	}
	return len(seen)
}

// GetReportResultCount 返回收集到的漏洞/凭据结果总数
func GetReportResultCount() int {
	return len(nucleiEvents) + len(gopocEvents)
}

// ---------------- 报告生命周期 ----------------

// GenerateHTMLReportHeader 初始化报告缓冲
func GenerateHTMLReportHeader() {
	if structs.GlobalConfig.ReportName == "" {
		structs.GlobalConfig.ReportName = strconv.Itoa(int(time.Now().Unix())) + ".html"
	}
	if reportStarted {
		return
	}
	reportStarted = true
	nucleiEvents = nil
	gopocEvents = nil
}

// GenerateHTMLReportFooter 统一渲染完整 HTML 报告（扫描收尾调用）
func GenerateHTMLReportFooter() {
	if !reportStarted {
		return
	}
	reportStarted = false

	alive := countAliveHosts()
	ports := countPorts()
	fingers := countFingers()
	creds := len(gopocEvents)
	vulns := len(nucleiEvents)

	// 头部
	head := strings.Replace(defaultHeader(), "{{TIME}}", time.Now().Format("2006-01-02 15:04:05"), 1)
	head = strings.Replace(head, "{{ALIVE}}", strconv.Itoa(alive), 1)
	head = strings.Replace(head, "{{PORTS}}", strconv.Itoa(ports), 1)
	head = strings.Replace(head, "{{FINGERS}}", strconv.Itoa(fingers), 1)
	head = strings.Replace(head, "{{CREDS}}", strconv.Itoa(creds), 1)
	head = strings.Replace(head, "{{VULNS}}", strconv.Itoa(vulns), 1)

	// 漏洞分组
	var vulnBody strings.Builder
	for i, ev := range nucleiEvents {
		vulnBody.WriteString(nucleiVulnRow(i+1, ev, getSeverity(ev.Info.SeverityHolder.Severity)))
	}
	var vulnSection string
	if len(nucleiEvents) > 0 {
		vulnSection = fmt.Sprintf(`<h2 onclick="toggleSection(this)"><span class="arrow">%s</span>漏洞<span class="count">%d</span></h2>
<div class="collapsible">
<table>
<thead><tr><th style="width:22%%">模板</th><th style="width:12%%">等级</th><th style="width:46%%">目标</th><th>名称</th></tr></thead>
<tbody>%s</tbody>
</table>
</div>`, "\u25b8", len(nucleiEvents), vulnBody.String())
	}

	// 有效凭据分组
	var credBody strings.Builder
	for i, ev := range gopocEvents {
		credBody.WriteString(gopocRow(i+1, ev))
	}
	var credSection string
	if len(gopocEvents) > 0 {
		credSection = fmt.Sprintf(`<h2 onclick="toggleSection(this)"><span class="arrow">%s</span>有效凭据<span class="count">%d</span></h2>
<div class="collapsible">
<table>
<thead><tr><th style="width:22%%">插件</th><th style="width:12%%">等级</th><th style="width:46%%">目标</th><th>凭据</th></tr></thead>
<tbody>%s</tbody>
</table>
</div>`, "\u25b8", len(gopocEvents), credBody.String())
	}

	footer := `<div class="footer"><b>ABCD Scanner v1.3.0</b> — 月落攻防实验室</div>
</body></html>
`

	full := head + vulnSection + credSection + footer
	fl, err := os.OpenFile(structs.GlobalConfig.ReportName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("Open %s error, %v\n", structs.GlobalConfig.ReportName, err)
		return
	}
	_, _ = fl.Write([]byte(full))
	fl.Close()
}

// ---------------- 渲染辅助 ----------------

func severityBadge(sev string) string {
	low := strings.ToLower(sev)
	return `<span class="badge ` + low + `">` + strings.ToUpper(sev) + `</span>`
}

// nucleiVulnRow 渲染一个可展开的漏洞行（含详情 + 请求/响应报文）
func nucleiVulnRow(idx int, result output.ResultEvent, sev string) string {
	// 主行
	row := fmt.Sprintf(`<tr class="vuln-row" onclick="toggleVuln(%d)">
	<td><span id="va%d" class="arrow" style="display:inline-block;width:14px">%s</span> %s</td>
	<td>%s</td>
	<td><span class="mono">%s</span></td>
	<td>%s</td>
</tr>`,
		idx, idx, "\u25b8", xssfilter(result.TemplateID),
		severityBadge(sev),
		xssfilter(result.Matched),
		xssfilter(result.Info.Name))

	// 详情
	info := ""
	if result.Info.Name != "" {
		info += "<b>名称:</b> " + xssfilter(result.Info.Name) + "<br/>"
	}
	if len(result.Info.Description) > 0 {
		info += "<b>描述:</b> " + xssfilter(result.Info.Description) + "<br/>"
	}
	if result.Info.Authors.String() != "" {
		info += "<b>作者:</b> " + xssfilter(result.Info.Authors.String()) + "<br/>"
	}
	if result.Info.Reference != nil && len(result.Info.Reference.ToSlice()) > 0 {
		info += "<b>参考:</b><br/>"
		for _, rv := range result.Info.Reference.ToSlice() {
			info += "&nbsp;&nbsp;- <a href='" + xssfilter(rv) + "' target='_blank'>" + xssfilter(rv) + "</a><br/>"
		}
	}
	if len(result.ExtractedResults) > 0 {
		info += "<b>提取结果:</b><br/>"
		for _, ev := range result.ExtractedResults {
			info += "&nbsp;&nbsp;- " + xssfilter(ev) + "<br/>"
		}
	}

	httpBox := ""
	req, resp := result.Request, result.Response
	if len(result.Packet) > 0 {
		for _, v := range result.Packet {
			req, resp = v.Request, v.Response
		}
	}
	if req != "" || resp != "" {
		httpBox = fmt.Sprintf(`<div class="clr">
	<div class="request w50"><div class="toggleR" onclick="toggleReq('R',this)">%s</div>
<xmp>%s</xmp></div>
	<div class="response w50"><div class="toggleL" onclick="toggleReq('L',this)">%s</div>
<xmp>%s</xmp></div>
</div>`, "\u2192", xssfilter(req), "\u2190", xssfilter(resp))
	}

	detail := fmt.Sprintf(`<tr class="vuln-detail" id="vd%d"><td colspan="4">
%s
<div class="http-box">%s</div>
</td></tr>`, idx, info, httpBox)

	return row + detail
}

// gopocRow 渲染一条 GoPoc 弱口令/漏洞行
func gopocRow(idx int, result structs.GoPocsResultType) string {
	severityString := result.Security
	if severityString == "" {
		severityString = "High"
	}
	credShow := ""
	if result.InfoLeft != "" {
		credShow = fmt.Sprintf("<b>账号:</b> <span class=\"mono\">%s</span>&nbsp;&nbsp;<b>密码:</b> <span class=\"mono\">%s</span>",
			xssfilter(result.InfoLeft), xssfilter(result.InfoRight))
	}
	desc := ""
	if result.Description != "" {
		desc = "<b>描述:</b> " + xssfilter(result.Description)
	}
	return fmt.Sprintf(`<tr class="vuln-row" onclick="toggleVuln(%d)">
	<td><span id="va%d" class="arrow" style="display:inline-block;width:14px">%s</span> %s</td>
	<td>%s</td>
	<td><span class="mono">%s</span></td>
	<td>%s</td>
</tr>
<tr class="vuln-detail" id="vd%d"><td colspan="4">
%s
</td></tr>`,
		idx, idx, "\u25b8", xssfilter(result.PocName),
		severityBadge(severityString),
		xssfilter(result.Target), credShow,
		idx, desc)
}

// ---------------- 结果收集 ----------------

// AddResultByResultEvent 收集一条 nuclei 漏洞结果
func AddResultByResultEvent(result output.ResultEvent) {
	if !reportStarted {
		return
	}
	b, e := json.Marshal(result)
	if e == nil {
		show := fmt.Sprintf("[%s] [%s] %v", result.TemplateID,
			result.Info.SeverityHolder.Severity.String(),
			result.Matched)
		ddout.FormatOutput(ddout.OutputMessage{
			Type:   "Nuclei",
			Nuclei: string(b),
			Show:   show,
		})
	}
	nucleiEvents = append(nucleiEvents, result)
}

// AddResultByGoPocResult 收集一条 GoPoc 弱口令/漏洞结果
func AddResultByGoPocResult(result structs.GoPocsResultType) {
	if !reportStarted {
		return
	}
	gopocEvents = append(gopocEvents, result)
}
