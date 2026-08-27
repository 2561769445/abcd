package master

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/xuri/excelize/v2"
)

// ---------- 工具函数 ----------

func itoa(n int) string        { return strconv.Itoa(n) }
func randSuffix() string {
	r := rand.Intn(100000)
	return strconv.Itoa(r)
}
func fmtSprintf(f string, a ...interface{}) string { return fmt.Sprintf(f, a...) }
func jsonMarshal(v interface{}) ([]byte, error)     { return json.Marshal(v) }

// maskDSN 隐藏DSN中的密码
func maskDSN(dsn string) string {
	i := strings.Index(dsn, "://")
	if i < 0 {
		return dsn
	}
	rest := dsn[i+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return dsn
	}
	cred := rest[:at]
	if c := strings.Index(cred, ":"); c >= 0 {
		return dsn[:i+3] + cred[:c] + ":***@" + rest[at+1:]
	}
	return dsn
}

// ---------- 导出 ----------

var exportDir = "exports"

func handleCreateExport(c *gin.Context) {
	var req htmlExportReq // type: assets/vulns/tasks/task | format: csv/xlsx/html
	if err := c.BindJSON(&req); err != nil || req.Type == "" {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	if req.Format == "" {
		req.Format = "xlsx"
	}
	_ = os.MkdirAll(exportDir, 0755)

	// HTML报告走独立渲染(漏洞带数据包/任务汇总多section)
	if req.Format == "html" {
		handleHTMLExport(c, req)
		return
	}

	var headers []string
	var records [][]string
	switch req.Type {
	case "assets":
		headers = []string{"ID", "任务", "节点", "类型", "IP", "端口", "协议", "URI", "域名", "标题", "状态码", "指纹", "标记", "备注", "首次发现", "最近发现"}
		q := `SELECT id,task_id,node_id,asset_type,ip,port,protocol,uri,domain,title,status_code,finger,tag,remark,first_seen,last_seen FROM assets` + exportCond(req) + ` ORDER BY last_seen DESC LIMIT 100000`
		rows, err := db.Query(q)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()
		records = scanRows(rows, 16)
	case "vulns":
		headers = []string{"ID", "任务", "节点", "来源", "漏洞编号", "等级", "目标", "详情", "状态", "首次发现", "最近发现"}
		q := `SELECT id,task_id,node_id,source,vuln_id,severity,target,detail,status,first_seen,last_seen FROM vulns` + exportCond(req) + ` ORDER BY first_seen DESC LIMIT 100000`
		rows, err := db.Query(q)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()
		records = scanRows(rows, 11)
	case "tasks":
		headers = []string{"ID", "名称", "目标数", "端口", "状态", "资产数", "漏洞数", "创建时间", "开始", "结束"}
		rows, err := db.Query(`SELECT id,name,target_count,ports,status,found_assets,found_vulns,created_at,started_at,finished_at FROM tasks ORDER BY created_at DESC LIMIT 10000`)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		defer rows.Close()
		records = scanRows(rows, 10)
	default:
		c.JSON(400, gin.H{"error": "类型必须是 assets/vulns/tasks"})
		return
	}

	// 字段过滤
	if len(req.Fields) > 0 {
		var keep []int
		for _, f := range req.Fields {
			for i, h := range headers {
				if h == f {
					keep = append(keep, i)
					break
				}
			}
		}
		if len(keep) > 0 {
			var nh []string
			for _, i := range keep {
				nh = append(nh, headers[i])
			}
			var nr [][]string
			for _, r := range records {
				var row []string
				for _, i := range keep {
					row = append(row, r[i])
				}
				nr = append(nr, row)
			}
			headers, records = nh, nr
		}
	}

	ext := "." + req.Format
	fname := req.Type + "-" + time.Now().Format("20060102150405") + ext
	fpath := filepath.Join(exportDir, fname)

	switch req.Format {
	case "csv":
		f, err := os.Create(fpath)
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		w := csv.NewWriter(f)
		_ = w.Write(headers)
		_ = w.WriteAll(records)
		w.Flush()
		f.Close()
	case "xlsx":
		// 流式写入: 10万+行全内存会超时/OOM
		f := excelize.NewFile()
		sw, err := f.NewStreamWriter("Sheet1")
		if err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		hdr := make([]interface{}, len(headers))
		for i, h := range headers {
			hdr[i] = h
		}
		_ = sw.SetRow("A1", hdr)
		for i, r := range records {
			row := make([]interface{}, len(r))
			for j, v := range r {
				row[j] = v
			}
			cell, _ := excelize.CoordinatesToCellName(1, i+2)
			_ = sw.SetRow(cell, row)
		}
		if err := f.SaveAs(fpath); err != nil {
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
	default:
		c.JSON(400, gin.H{"error": "格式必须是 csv/xlsx"})
		return
	}

	var id int
	err := db.QueryRow(`INSERT INTO export_records (export_type,file_path,fields,row_count,created_by)
		VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		req.Type, fpath, stringsJoin(req.Fields, ","), len(records), "admin").Scan(&id)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"id": id, "rows": len(records), "file": fname})
}

func stringsJoin(ss []string, sep string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

func scanRows(rows interface{ Next() bool; Scan(...interface{}) error; Close() error }, n int) [][]string {
	defer rows.Close()
	var out [][]string
	for rows.Next() {
		vals := make([]interface{}, n)
		ptrs := make([]interface{}, n)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		var row []string
		for _, v := range vals {
			if v == nil {
				row = append(row, "")
			} else if b, ok := v.([]byte); ok {
				row = append(row, string(b))
			} else if t, ok := v.(time.Time); ok {
				row = append(row, t.Format("2006-01-02 15:04:05"))
			} else {
				row = append(row, fmtSprintf("%v", v))
			}
		}
		out = append(out, row)
	}
	return out
}

func handleListExports(c *gin.Context) {
	rows, err := db.Query(`SELECT id,export_type,file_path,fields,row_count,created_by,created_at FROM export_records ORDER BY created_at DESC LIMIT 100`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	type exportRow struct {
		ID         int       `json:"id"`
		Type       string    `json:"export_type"`
		FilePath   string    `json:"file_path"`
		Fields     string    `json:"fields"`
		RowCount   int       `json:"row_count"`
		CreatedBy  string    `json:"created_by"`
		CreatedAt  time.Time `json:"created_at"`
	}
	var out []exportRow
	for rows.Next() {
		var e exportRow
		if err := rows.Scan(&e.ID, &e.Type, &e.FilePath, &e.Fields, &e.RowCount, &e.CreatedBy, &e.CreatedAt); err == nil {
			out = append(out, e)
		}
	}
	c.JSON(200, out)
}

func handleDownloadExport(c *gin.Context) {
	var fpath string
	err := db.QueryRow(`SELECT file_path FROM export_records WHERE id=$1`, c.Param("id")).Scan(&fpath)
	if err != nil {
		c.JSON(404, gin.H{"error": "导出记录不存在"})
		return
	}
	if _, err := os.Stat(fpath); err != nil {
		c.JSON(404, gin.H{"error": "文件已不存在"})
		return
	}
	c.Header("Content-Disposition", "attachment; filename="+filepath.Base(fpath))
	c.File(fpath)
}

// registerFrontend 托管Vue构建产物(embed dist, 构建时注入)
func registerFrontend(r *gin.Engine) {
	if !frontendReady() {
		r.NoRoute(func(c *gin.Context) {
			c.String(http.StatusOK, "abcd master API. 前端未构建, 请访问 /api/*")
		})
		return
	}
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		if p == "/" || p == "" {
			p = "/index.html"
		}
		b, err := frontendReadFile("dist" + p)
		if err != nil {
			// SPA回退
			b, err = frontendReadFile("dist/index.html")
			if err != nil {
				c.String(404, "not found")
				return
			}
		}
		mime := "text/html"
		switch {
		case stringsHasSuffix(p, ".js"):
			mime = "application/javascript"
		case stringsHasSuffix(p, ".css"):
			mime = "text/css"
		case stringsHasSuffix(p, ".svg"):
			mime = "image/svg+xml"
		case stringsHasSuffix(p, ".png"):
			mime = "image/png"
		}
		c.Data(http.StatusOK, mime, b)
	})
}

func stringsHasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

// ---------- HTML报告导出 ----------

// extractVulnPkt 从漏洞extra原始JSON提取数据包(请求/响应/curl/描述/参考)
func extractVulnPkt(extra string) (req, resp, curl, desc string, refs []string) {
	if extra == "" {
		return
	}
	var m struct {
		Type   string            `json:"type"`
		Nuclei string            `json:"nuclei"`
		GoPoc  map[string]string `json:"go_poc"`
	}
	if json.Unmarshal([]byte(extra), &m) != nil {
		return
	}
	if m.Type == "Nuclei" && m.Nuclei != "" {
		var re struct {
			Request   json.RawMessage `json:"request"`
			Response  json.RawMessage `json:"response"`
			Curl      json.RawMessage `json:"curl-command"`
			MatchedAt string          `json:"matched-at"`
			Info      struct {
				Description string   `json:"description"`
				Reference   []string `json:"reference"`
			} `json:"info"`
		}
		if json.Unmarshal([]byte(m.Nuclei), &re) == nil {
			req = rawToStr(re.Request)
			resp = rawToStr(re.Response)
			curl = rawToStr(re.Curl)
			desc = re.Info.Description
			refs = re.Info.Reference
		}
	}
	if m.Type == "GoPoc" && len(m.GoPoc) > 0 {
		desc = m.GoPoc["description"]
		req = m.GoPoc["info_left"]
	}
	return
}

const htmlReportCSS = `<style>
:root{--bg:#0a0e17;--card:#161d2b;--border:#1e2d45;--accent:#00d4aa;--text:#e2e8f0;--muted:#94a3b8;--danger:#ef4444;--warning:#f59e0b;--info:#3b82f6;--success:#10b981}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:"Microsoft YaHei",sans-serif;background:var(--bg);color:var(--text);padding:20px;min-width:900px}
h1{font-size:22px;margin-bottom:4px;color:var(--accent)}
h1 small{font-size:12px;color:var(--muted);font-weight:400}
.meta{color:var(--muted);font-size:11px;margin-bottom:24px}
h2{font-size:16px;margin:24px 0 12px;padding-bottom:8px;border-bottom:2px solid var(--accent);cursor:pointer;user-select:none}
h2:hover{color:var(--accent)}
h2 .count{font-size:12px;color:var(--muted);font-weight:400;margin-left:8px}
h2 .arrow{display:inline-block;width:16px;transition:transform .2s}
h2.open .arrow{transform:rotate(90deg)}
table{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px}
thead th{padding:10px 12px;background:#111827;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:1px solid var(--border);text-align:left}
tbody td{padding:10px 12px;border-bottom:1px solid rgba(30,45,69,.5);color:var(--text)}
tbody tr:hover{background:rgba(0,212,170,.03)}
.badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.critical{background:rgba(239,68,68,.2);color:var(--danger);border:1px solid rgba(239,68,68,.4)}
.high{background:rgba(239,68,68,.15);color:#f87171}
.medium{background:rgba(245,158,11,.15);color:var(--warning)}
.low{background:rgba(59,130,246,.15);color:var(--info)}
.mono{font-family:"Cascadia Code","Consolas",monospace;font-size:11px;background:rgba(255,255,255,.04);padding:2px 6px;border-radius:3px}
.collapsible{display:none}
.vuln-row{cursor:pointer;user-select:none}
.vuln-row:hover{background:rgba(0,212,170,.06)!important}
.vuln-detail{display:none}
.vuln-detail.show{display:table-row}
.vuln-detail td{padding:16px 20px!important;background:rgba(0,0,0,.2)}
.clr{clear:both}
.request{float:left;overflow-x:auto;overflow-y:auto;position:relative;max-height:600px}
.request .toggleR{z-index:99;position:absolute;padding:0 10px;background:var(--card);color:var(--muted);top:-5px;left:50%;cursor:pointer;border:1px solid var(--border);border-radius:4px;font-size:11px}
.w50{width:50%}.w100{width:100%}
.response{float:left;overflow-x:auto;overflow-y:auto;max-height:600px;position:relative}
.response .toggleL{z-index:99;position:absolute;padding:0 10px;background:var(--card);color:var(--muted);top:-5px;left:50%;cursor:pointer;border:1px solid var(--border);border-radius:4px;font-size:11px}
.http-box{background:#060b14;border:1px solid var(--border);border-radius:6px;margin:0}
xmp{white-space:pre-wrap;word-wrap:break-word;font-family:"Cascadia Code","Consolas",monospace;font-size:11px;line-height:1.6;color:#a0b4cc;padding:12px 14px;margin:0}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.footer{text-align:center;padding:20px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);margin-top:20px}
@media(max-width:768px){body{padding:10px}table{font-size:12px}.w50{width:100%!important;float:none}}
</style>`

func htmlesc(s string) string { return html.EscapeString(s) }

// rawToStr jsonb字段兼容转换: 数组→换行拼接, 字符串→原样
func rawToStr(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var ss []string
	if json.Unmarshal(raw, &ss) == nil {
		return strings.Join(ss, "\n\n")
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// vulnPktHTML 漏洞详情行(vuln-detail): 左右分栏HTTP数据包, dddd报告风格
func vulnPktHTML(idx int, extra string) string {
	req, resp, curl, desc, refs := extractVulnPkt(extra)
	if req == "" && resp == "" && curl == "" && desc == "" && len(refs) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<tr class="vuln-detail" id="vd` + itoa(idx) + `"><td colspan="6" style="background:rgba(0,0,0,.25)">`)
	if desc != "" {
		sb.WriteString(`<div style="font-size:12px;color:var(--muted);margin-bottom:10px;padding:8px 12px;background:var(--card);border-left:3px solid var(--accent);border-radius:4px">` + htmlesc(desc) + `</div>`)
	}
	if len(refs) > 0 {
		sb.WriteString(`<div style="font-size:11px;color:var(--muted);margin-bottom:10px">参考: `)
		for i, r := range refs {
			if i > 0 {
				sb.WriteString(" · ")
			}
			sb.WriteString(`<a href="` + htmlesc(r) + `" target="_blank">` + htmlesc(r) + `</a>`)
		}
		sb.WriteString(`</div>`)
	}
	if req != "" || resp != "" {
		sb.WriteString(`<div class="clr"></div>`)
		if req != "" {
			sb.WriteString(`<div class="request w50"><div class="toggleR" onclick="toggleW(this)">请求</div><div class="http-box"><xmp>` + htmlesc(req) + `</xmp></div></div>`)
		}
		if resp != "" {
			sb.WriteString(`<div class="response w50"><div class="toggleL" onclick="toggleW(this)">响应</div><div class="http-box"><xmp>` + htmlesc(resp) + `</xmp></div></div>`)
		}
		sb.WriteString(`<div class="clr"></div>`)
	}
	if curl != "" {
		sb.WriteString(`<div style="margin-top:10px"><span style="color:var(--muted);font-size:11px">curl 复现:</span><div class="http-box"><xmp>` + htmlesc(curl) + `</xmp></div></div>`)
	}
	sb.WriteString(`</td></tr>`)
	return sb.String()
}

func htmlTable(headers []string, records [][]string) string {
	var sb strings.Builder
	sb.WriteString(`<table><tr>`)
	for _, h := range headers {
		sb.WriteString(`<th>` + htmlesc(h) + `</th>`)
	}
	sb.WriteString(`</tr>`)
	for _, r := range records {
		sb.WriteString(`<tr>`)
		for _, v := range r {
			sb.WriteString(`<td>` + htmlesc(v) + `</td>`)
		}
		sb.WriteString(`</tr>`)
	}
	sb.WriteString(`</table>`)
	return sb.String()
}

// vulnStatCards 从漏洞记录累计统计卡(漏洞数/各等级)
func vulnStatCards(recs [][]string, cards map[string]int) map[string]int {
	cards["漏洞"] = len(recs)
	return cards
}

func sevTag(s string) string {
	return `<span class="badge ` + htmlesc(strings.ToLower(s)) + `">` + htmlesc(s) + `</span>`
}

// htmlExportReq HTML导出请求
type htmlExportReq struct {
	Type    string   `json:"type"`
	Format  string   `json:"format"`
	Fields  []string `json:"fields"`
	TaskID  string   `json:"task_id"`
	TaskIDs string   `json:"task_ids"` // 聚合任务: 逗号分隔子任务ID, 一键导出整个"象山"
	IDs     []int64  `json:"ids"`      // 勾选导出: 只导这些行(漏洞/资产行ID), 空=按task_id/全量
}

// joinInts ids拼SQL IN子句: 1,2,3
func joinInts(ids []int64) string {
	parts := make([]string, len(ids))
	for i, v := range ids {
		parts[i] = itoa(int(v))
	}
	return strings.Join(parts, ",")
}

// exportCond task_id/task_ids + 勾选ids 组合过滤条件
func exportCond(req htmlExportReq) string {
	cond := ""
	if req.TaskID != "" {
		cond = ` WHERE task_id='` + strings.ReplaceAll(req.TaskID, "'", "") + `'`
	}
	if in := safeIDIn(req.TaskIDs); in != "" {
		c := ` task_id IN (` + in + `)`
		if cond == "" {
			cond = ` WHERE` + c
		} else {
			cond += ` AND` + c
		}
	}
	if len(req.IDs) > 0 {
		in := ` id IN (` + joinInts(req.IDs) + `)`
		if cond == "" {
			cond = ` WHERE` + in
		} else {
			cond += ` AND` + in
		}
	}
	return cond
}

// handleHTMLExport 自包含HTML报告: assets/vulns(带数据包)/tasks/ task=任务汇总(资产+漏洞)
func handleHTMLExport(c *gin.Context, req htmlExportReq) {
	t0 := time.Now()
	type section struct{ title, body string; count int; note string }
	var secs []section
	statCards := map[string]int{}
	title := "ABCD 扫描报告"
	taskFilter := strings.ReplaceAll(req.TaskID, "'", "")

	addAssets := func(where string) {
		q := `SELECT id,task_id,node_id,asset_type,ip,port,protocol,uri,domain,title,status_code,finger,tag,remark,first_seen,last_seen FROM assets` + exportCond(req) + ` ORDER BY last_seen DESC LIMIT 100000`
		rows, err := db.Query(q)
		if err != nil {
			return
		}
		hs := []string{"ID", "类型", "IP", "端口", "URI", "标题", "状态码", "指纹", "域名", "最近发现"}
		keep := []int{0, 3, 4, 5, 7, 9, 10, 11, 8, 15}
		rows2 := scanRows(rows, 16)
		var recs [][]string
		for _, r := range rows2 {
			// 统计卡片: 按资产类型累计
			switch r[3] {
			case "IPAlive":
				statCards["存活主机"]++
			case "PortScan":
				statCards["开放端口"]++
			case "Web":
				statCards["Web服务"]++
			case "Finger":
				statCards["Web指纹"]++
			}
			var nr []string
			for _, i := range keep {
				nr = append(nr, r[i])
			}
			recs = append(recs, nr)
		}
		secs = append(secs, section{"资产清单", htmlTable(hs, recs), len(recs), ""})
	}
	addVulns := func(where string) {
		q := `SELECT id,task_id,node_id,source,vuln_id,severity,target,detail,status,first_seen,last_seen,extra FROM vulns` + exportCond(req) + ` ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END, first_seen DESC LIMIT 100000`
		rows, err := db.Query(q)
		if err != nil {
			return
		}
		hs := []string{"ID", "任务", "节点", "来源", "漏洞编号", "等级", "目标", "详情", "状态", "首次发现", "最近发现", "extra"}
		recs := scanRows(rows, len(hs))
		var sb strings.Builder
		sb.WriteString(`<table><thead><tr><th>等级</th><th>漏洞</th><th>目标</th><th>详情</th><th>来源</th><th>发现时间</th></tr></thead><tbody>`)
		for i, r := range recs {
			extra := r[len(r)-1]
			sb.WriteString(`<tr class="vuln-row" onclick="toggleVuln(` + itoa(i) + `)"><td><span id="va` + itoa(i) + `" style="color:var(--muted)">▸</span> ` + sevTag(r[5]) + `</td><td>` + htmlesc(r[4]) + `</td><td class="mono">` + htmlesc(r[6]) + `</td><td>` + htmlesc(r[7]) + `</td><td>` + htmlesc(r[3]) + `</td><td>` + htmlesc(r[9]) + `</td></tr>`)
			sb.WriteString(vulnPktHTML(i, extra))
		}
		sb.WriteString(`</tbody></table>`)
		secs = append(secs, section{"漏洞清单", sb.String(), len(recs), "点击漏洞行展开数据包"})
		statCards = vulnStatCards(recs, statCards)
	}

	switch req.Type {
	case "assets":
		title = "资产导出报告"
		addAssets(taskFilter)
	case "vulns":
		title = "漏洞导出报告"
		addVulns(taskFilter)
	case "tasks":
		title = "任务清单报告"
		rows, err := db.Query(`SELECT id,name,target_count,ports,status,found_assets,found_vulns,created_at,started_at,finished_at FROM tasks ORDER BY created_at DESC LIMIT 10000`)
		if err == nil {
			hs := []string{"ID", "名称", "目标数", "端口", "状态", "资产数", "漏洞数", "创建时间", "开始", "结束"}
			rs := scanRows(rows, len(hs))
			secs = append(secs, section{"任务", htmlTable(hs, rs), len(rs), ""})
		}
	case "task":
		// 单task_id 或 task_ids聚合(多节点子任务合并一份报告)
		refID := taskFilter
		if refID == "" {
			for _, id := range strings.Split(req.TaskIDs, ",") {
				if id != "" {
					refID = strings.TrimSpace(id)
					break
				}
			}
		}
		if refID == "" {
			c.JSON(400, gin.H{"error": "task汇总导出需要task_id或task_ids"})
			return
		}
		var name string
		var tcount int
		if db.QueryRow(`SELECT name,target_count FROM tasks WHERE id=$1`, refID).Scan(&name, &tcount) != nil {
			c.JSON(404, gin.H{"error": "任务不存在"})
			return
		}
		// 去子任务后缀聚合名: "象山全端口 [vps96]" → "象山全端口"
		if i := strings.Index(name, " ["); i > 0 {
			name = name[:i]
		}
		title = "任务汇总报告 - " + name
		addVulns(taskFilter)
		addAssets(taskFilter)
	default:
		c.JSON(400, gin.H{"error": "html类型必须是 assets/vulns/tasks/task"})
		return
	}

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>` + htmlesc(title) + `</title>` + htmlReportCSS + `</head><body>`)
	sb.WriteString(`<h1>ABCD Scanner <small>分布式扫描平台</small></h1><div class="meta">` + htmlesc(title) + ` · 生成时间: ` + time.Now().Format("2006-01-02 15:04:05") + `</div>`)
	// 统计卡片
	sb.WriteString(`<div style="display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap">`)
	cards := []struct{ name, color string }{{"存活主机", "var(--accent)"}, {"开放端口", "#06b6d4"}, {"Web指纹", "#8b5cf6"}, {"Web服务", "#0ea5e9"}, {"漏洞", "var(--danger)"}}
	for _, cd := range cards {
		sb.WriteString(`<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 20px"><span style="color:var(--muted);font-size:11px">` + cd.name + `</span><br><b style="font-size:20px;color:` + cd.color + `">` + itoa(statCards[cd.name]) + `</b></div>`)
	}
	sb.WriteString(`</div>`)
	// 可折叠section
	for i, sec := range secs {
		cnt := ""
		if sec.count > 0 {
			cnt = `<span class="count">` + itoa(sec.count) + `</span>`
		}
		note := ""
		if sec.note != "" {
			note = `<span class="count">` + htmlesc(sec.note) + `</span>`
		}
		sb.WriteString(`<h2 onclick="toggleSection(this)"><span class="arrow">▾</span>` + htmlesc(sec.title) + cnt + note + `</h2><div class="collapsible" style="display:block">` + sec.body + `</div>`)
		_ = i
	}
	sb.WriteString(`<div class="footer"><b>ABCD Scanner</b> — ABCD分布式扫描平台</div>
<script>
function toggleSection(el){var d=el.nextElementSibling;var a=el.querySelector(".arrow");if(d.style.display=="none"){d.style.display="block";a.textContent="▾"}else{d.style.display="none";a.textContent="▸"}}
function toggleVuln(idx){var d=document.getElementById("vd"+idx);var a=document.getElementById("va"+idx);if(d){if(d.classList.contains("show")){d.classList.remove("show");a.textContent="▸"}else{d.classList.add("show");a.textContent="▾"}}}
function toggleW(el){var p=el.parentElement;if(p.classList.contains("w50")){p.classList.remove("w50");p.classList.add("w100");p.style.width="100%"}else{p.classList.remove("w100");p.classList.add("w50");p.style.width="50%"}}
</script></body></html>`)

	fname := req.Type + "-report-" + time.Now().Format("20060102150405") + ".html"
	fpath := filepath.Join(exportDir, fname)
	if err := os.WriteFile(fpath, []byte(sb.String()), 0644); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	var id int
	if err := db.QueryRow(`INSERT INTO export_records (export_type,file_path,fields,row_count,created_by)
		VALUES ($1,$2,$3,$4,$5) RETURNING id`,
		req.Type, fpath, "", 0, "admin").Scan(&id); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"id": id, "rows": 0, "file": fname, "gen_ms": time.Since(t0).Milliseconds()})
}
