package ddout

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// output_extra.go 在基础 text/json 之外补充 csv / xlsx 输出能力（纯标准库实现）。

var (
	xlsxRows   []OutputMessage
	xlsxLock   sync.Mutex
	xlsxTicker *time.Ticker
	xlsxDone   chan struct{}
)

func outputColumns() []string {
	return []string{"Type", "IP", "Port", "Protocol", "URI", "Status", "Title",
		"Finger", "Domain", "GoPoc", "Nuclei", "AdditionalMsg"}
}

func outputRow(o *OutputMessage) []string {
	return []string{
		o.Type,
		o.IP,
		o.Port,
		o.Protocol,
		o.URI,
		o.Web.Status,
		o.Web.Title,
		strings.Join(o.Finger, ","),
		o.Domain,
		o.GoPoc.PocName,
		o.Nuclei,
		o.AdditionalMsg,
	}
}

// startPeriodicXLSXSave 定期把累积行写入 xlsx（仅当输出格式为 xlsx 时启用）
func startPeriodicXLSXSave(filename string) {
	xlsxLock.Lock()
	defer xlsxLock.Unlock()
	if xlsxTicker != nil {
		return
	}
	xlsxDone = make(chan struct{})
	xlsxTicker = time.NewTicker(5 * time.Second)
	go func() {
		for {
			select {
			case <-xlsxTicker.C:
				flushXLSX(filename)
			case <-xlsxDone:
				return
			}
		}
	}()
}

func stopPeriodicXLSXSave(filename string) {
	xlsxLock.Lock()
	if xlsxTicker != nil {
		xlsxTicker.Stop()
		xlsxTicker = nil
		close(xlsxDone)
	}
	xlsxLock.Unlock()
	flushXLSX(filename)
}

func flushXLSX(filename string) {
	xlsxLock.Lock()
	rows := make([]OutputMessage, len(xlsxRows))
	copy(rows, xlsxRows)
	xlsxLock.Unlock()
	if len(rows) == 0 {
		return
	}
	if err := writeXLSX(filename, rows); err != nil {
		// 写入失败（例如文件被占用）时静默重试下一轮
		return
	}
}

// writeXLSX 使用标准库生成最小可用的 xlsx（inline string）
func writeXLSX(filename string, rows []OutputMessage) error {
	_ = os.MkdirAll(filepath.Dir(filename), 0755)
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	contentTypes := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
</Types>`
	_ = writeZipEntry(zw, "[Content_Types].xml", contentTypes)

	rels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`
	_ = writeZipEntry(zw, "_rels/.rels", rels)

	workbook := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="result" sheetId="1" r:id="rId1"/></sheets>
</workbook>`
	_ = writeZipEntry(zw, "xl/workbook.xml", workbook)

	wbRels := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>`
	_ = writeZipEntry(zw, "xl/_rels/workbook.xml.rels", wbRels)

	styles := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<fonts count="1"><font><sz val="11"/><name val="Calibri"/></font></fonts>
<fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills>
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/></cellXfs>
</styleSheet>`
	_ = writeZipEntry(zw, "xl/styles.xml", styles)

	// 构造 sheet XML
	cols := outputColumns()
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>` + "\n")
	sb.WriteString(`<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` + "\n")
	// header row
	sb.WriteString("<row r=\"1\">")
	for ci, c := range cols {
		sb.WriteString(fmt.Sprintf(`<c r="%s%d" t="inlineStr"><is><t>%s</t></is></c>`, colLetter(ci), 1, xmlEscape(c)))
	}
	sb.WriteString("</row>\n")
	for ri, o := range rows {
		sb.WriteString(fmt.Sprintf("<row r=\"%d\">", ri+2))
		for ci, v := range outputRow(&o) {
			sb.WriteString(fmt.Sprintf(`<c r="%s%d" t="inlineStr"><is><t>%s</t></is></c>`, colLetter(ci), ri+2, xmlEscape(v)))
		}
		sb.WriteString("</row>\n")
	}
	sb.WriteString("</sheetData></worksheet>")
	_ = writeZipEntry(zw, "xl/worksheets/sheet1.xml", sb.String())

	if err := zw.Close(); err != nil {
		return err
	}
	return os.WriteFile(filename, buf.Bytes(), 0644)
}

func colLetter(i int) string {
	// A..Z, AA..ZZ
	s := ""
	for {
		s = string(rune('A'+i%26)) + s
		i = i/26 - 1
		if i < 0 {
			break
		}
	}
	return s
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

func writeZipEntry(zw *zip.Writer, name, content string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(content))
	return err
}

// appendXLSXRow 累积 xlsx 行（去重）
func appendXLSXRow(o OutputMessage) {
	xlsxLock.Lock()
	defer xlsxLock.Unlock()
	key := o.Type + "|" + o.URI + "|" + o.IP + ":" + o.Port + "|" + strings.Join(o.Finger, ",") + "|" + o.GoPoc.PocName + "|" + o.Nuclei
	for _, e := range xlsxRows {
		k := e.Type + "|" + e.URI + "|" + e.IP + ":" + e.Port + "|" + strings.Join(e.Finger, ",") + "|" + e.GoPoc.PocName + "|" + e.Nuclei
		if k == key {
			return
		}
	}
	xlsxRows = append(xlsxRows, o)
}

// writeCSVRow 增量写 CSV
func writeCSVRow(filename string, o OutputMessage) {
	if filename == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(filename), 0755)
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write(outputRow(&o))
	w.Flush()
}

// FlushOutput 扫描结束时落盘 xlsx / 写出统计信息
func FlushOutput() {
	if OutputType == "xlsx" {
		stopPeriodicXLSXSave(OutputFileName)
	}
}

// sortedRows 供统计/报告使用
func sortedRows() []OutputMessage {
	xlsxLock.Lock()
	defer xlsxLock.Unlock()
	out := make([]OutputMessage, len(xlsxRows))
	copy(out, xlsxRows)
	sort.SliceStable(out, func(i, j int) bool { return out[i].URI < out[j].URI })
	return out
}
