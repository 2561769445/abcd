package report

import (
	"strings"
)

// xssfilter 转义 HTML 特殊字符，防止内容破坏页面结构
func xssfilter(s string) string {
	s = strings.ReplaceAll(s, "<", "%3C")
	s = strings.ReplaceAll(s, ">", "%3E")
	return s
}

// defaultHeader 生成设计稿风格的报告头部模板
// 统计数字通过 %s 占位，收尾时由 GenerateHTMLReportFooter 填充
func defaultHeader() string {
	return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>ABCD Scanner — 扫描报告</title>
<style>
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
.info{background:rgba(16,185,129,.15);color:var(--success)}
.mono{font-family:"Cascadia Code","Consolas",monospace;font-size:11px;background:rgba(255,255,255,.04);padding:2px 6px;border-radius:3px}
.collapsible{display:none}
.vuln-row{cursor:pointer;user-select:none}
.vuln-row:hover{background:rgba(0,212,170,.06)!important}
.vuln-detail{display:none}
.vuln-detail.show{display:table-row}
.vuln-detail td{padding:16px 20px!important;background:rgba(0,0,0,.2)}
/* dddd-style HTTP packets */
.clr{clear:both}
.request{float:left;overflow-x:auto;overflow-y:auto;position:relative}
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
</style>
</head>
<body>
<h1>ABCD Scanner <small>月落攻防实验室</small></h1>
<div class="meta">生成时间: {{TIME}}</div>
<div style="display:flex;gap:16px;margin-bottom:24px;flex-wrap:wrap">
<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 20px"><span style="color:var(--muted);font-size:11px">存活主机</span><br><b style="font-size:20px;color:var(--accent)">{{ALIVE}}</b></div>
<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 20px"><span style="color:var(--muted);font-size:11px">开放端口</span><br><b style="font-size:20px;color:#06b6d4">{{PORTS}}</b></div>
<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 20px"><span style="color:var(--muted);font-size:11px">Web指纹</span><br><b style="font-size:20px;color:#8b5cf6">{{FINGERS}}</b></div>
<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 20px"><span style="color:var(--muted);font-size:11px">有效凭据</span><br><b style="font-size:20px;color:var(--success)">{{CREDS}}</b></div>
<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 20px"><span style="color:var(--muted);font-size:11px">漏洞</span><br><b style="font-size:20px;color:var(--danger)">{{VULNS}}</b></div>
</div>
<script>
function toggleSection(el){var d=el.nextElementSibling;var a=el.querySelector(".arrow");if(d.style.display=="block"){d.style.display="none";a.textContent="\u25b8";el.classList.remove("open")}else{d.style.display="block";a.textContent="\u25be";el.classList.add("open")}}
function toggleVuln(idx){var d=document.getElementById("vd"+idx);var a=document.getElementById("va"+idx);if(d.classList.contains("show")){d.classList.remove("show");a.textContent="\u25b8"}else{d.classList.add("show");a.textContent="\u25be"}}
function toggleReq(dir,obj){var box=obj.parentElement;var other=dir=="R"?box.nextElementSibling:box.previousElementSibling;if(box.classList.contains("w50")){box.classList.remove("w50");box.classList.add("w100");other.style.display="none";obj.textContent="\u2190"}else{box.classList.add("w50");box.classList.remove("w100");other.style.display="";obj.textContent=dir=="R"?"\u2192":"\u2190"}}
</script>
`
}
