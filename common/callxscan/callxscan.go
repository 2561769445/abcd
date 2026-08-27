package callxscan

import (
	"abcd/ddout"
	"abcd/structs"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// callxscan.go 调用外部 xscan 二进制对存活 URL 进行扫描，并合并结果到 dddd 输出。
// 用法: abcd -xscan -xscan-path ./xscan

type xscanResult struct {
	URL     string `json:"url"`
	Type    string `json:"type"`
	Payload string `json:"payload"`
	Detail  string `json:"detail"`
	Title   string `json:"title"`
	Status  int    `json:"status"`
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// CallXscan 对全部存活 URL 执行 xscan
func CallXscan() {
	if !structs.GlobalConfig.Xscan {
		return
	}
	binary := structs.GlobalConfig.XscanPath
	if binary == "" {
		binary = "xscan"
	}
	if _, err := exec.LookPath(binary); err != nil && !fileExists(binary) {
		gologger.Error().Msgf("[Xscan] 未找到 xscan 可执行文件: %s", binary)
		return
	}

	var urls []string
	for rootURL := range structs.GlobalURLMap {
		urls = append(urls, rootURL)
	}
	if len(urls) == 0 {
		return
	}

	tmpDir, err := os.MkdirTemp("", "xscan_")
	if err != nil {
		return
	}
	defer os.RemoveAll(tmpDir)

	outFile := filepath.Join(tmpDir, "xscan.json")
	gologger.Info().Msgf("[Xscan] 调用 xscan 扫描 %d 个 URL", len(urls))
	for _, u := range urls {
		args := []string{"web", "--url", u, "--json", outFile}
		cmd := exec.Command(binary, args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		_ = cmd.Run()
		if data, err := os.ReadFile(outFile); err == nil {
			parseXscanJSON(data)
			_ = os.Remove(outFile)
		}
	}
	gologger.Info().Msg("[Xscan] xscan 扫描完成")
}

func parseXscanJSON(data []byte) {
	// xscan 输出可能是单对象或对象数组，或 JSONL
	var results []xscanResult
	if err := json.Unmarshal(data, &results); err != nil {
		// 尝试单对象
		var one xscanResult
		if err2 := json.Unmarshal(data, &one); err2 != nil {
			// 尝试 JSONL
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var r xscanResult
				if json.Unmarshal([]byte(line), &r) == nil {
					results = append(results, r)
				}
			}
		} else {
			results = append(results, one)
		}
	}
	for _, r := range results {
		msg := fmt.Sprintf("%s [%s] %s", r.URL, r.Type, r.Detail)
		gologger.Silent().Msg("[Xscan] " + msg)
		ddout.FormatOutput(ddout.OutputMessage{
			Type:          "Xscan",
			URI:           r.URL,
			GoPoc:         ddout.GoPocsResultType{PocName: r.Type, Security: "High", Target: r.URL, Description: r.Detail},
			AdditionalMsg: r.Type,
		})
	}
}
