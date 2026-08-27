package callxray

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

// callxray.go 调用外部 xray 二进制对存活 URL 进行漏洞验证，并合并结果到 dddd 输出。
// 用法: abcd -xray -xray-path ./xray

type xrayVuln struct {
	Detail struct {
		Addr   string   `json:"addr"`
		Payload string   `json:"payload"`
		Snapshot []string `json:"snapshot"`
	} `json:"detail"`
	Plugin    string `json:"plugin"`
	VulnClass string `json:"vuln_class"`
	CreateTime string `json:"create_time"`
}

// CallXray 对全部存活 URL 执行 xray webscan
func CallXray() {
	if !structs.GlobalConfig.Xray {
		return
	}
	binary := structs.GlobalConfig.XrayPath
	if binary == "" {
		binary = "xray"
	}
	if _, err := exec.LookPath(binary); err != nil && !fileExists(binary) {
		gologger.Error().Msgf("[Xray] 未找到 xray 可执行文件: %s", binary)
		return
	}

	var urls []string
	for rootURL := range structs.GlobalURLMap {
		urls = append(urls, rootURL)
	}
	if len(urls) == 0 {
		return
	}

	tmpDir, err := os.MkdirTemp("", "xray_")
	if err != nil {
		return
	}
	defer os.RemoveAll(tmpDir)

	urlFile := filepath.Join(tmpDir, "urls.txt")
	_ = os.WriteFile(urlFile, []byte(strings.Join(urls, "\n")), 0644)
	outFile := filepath.Join(tmpDir, "xray.json")

	gologger.Info().Msgf("[Xray] 调用 xray 扫描 %d 个 URL", len(urls))
	args := []string{"webscan", "--url-file", urlFile, "--json-output", outFile}
	cmd := exec.Command(binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		gologger.Error().Msgf("[Xray] 执行失败: %v", err)
	}

	if data, err := os.ReadFile(outFile); err == nil {
		parseXrayJSON(data)
	}
	gologger.Info().Msg("[Xray] xray 扫描完成")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func parseXrayJSON(data []byte) {
	var vulns []xrayVuln
	if err := json.Unmarshal(data, &vulns); err != nil {
		return
	}
	for _, v := range vulns {
		msg := fmt.Sprintf("%s [%s] %s", v.Detail.Addr, v.VulnClass, v.Plugin)
		gologger.Silent().Msg("[Xray] " + msg)
		ddout.FormatOutput(ddout.OutputMessage{
			Type:          "Xray",
			URI:           v.Detail.Addr,
			GoPoc:         ddout.GoPocsResultType{PocName: v.Plugin, Security: "High", Description: v.VulnClass, Target: v.Detail.Addr},
			AdditionalMsg: v.VulnClass,
		})
	}
}
