package webui

import (
	"abcd/structs"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// pocs.go WebUI 的 POC 统计/搜索与 xray 触发辅助

func pocsCount() int {
	n := 0
	_ = fs.WalkDir(structs.GlobalEmbedPocs, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
			n++
		}
		return nil
	})
	// 磁盘补充
	_ = filepath.Walk("config/pocs", func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) {
			n++
		}
		return nil
	})
	return n
}

func listPocs(search string) []string {
	set := map[string]bool{}
	_ = fs.WalkDir(structs.GlobalEmbedPocs, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml") {
				name := strings.TrimPrefix(path, "config/pocs/")
				if search == "" || strings.Contains(strings.ToLower(name), search) {
					set[name] = true
				}
			}
		}
		return nil
	})
	_ = filepath.Walk("config/pocs", func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
				rel, _ := filepath.Rel("config/pocs", p)
				if search == "" || strings.Contains(strings.ToLower(rel), search) {
					set[rel] = true
				}
			}
		}
		return nil
	})
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// callXrayExternal 后台触发外部 xray 扫描
func callXrayExternal() {
	binary := structs.GlobalConfig.XrayPath
	if binary == "" {
		binary = "xray"
	}
	cmd := newXrayCmd(binary)
	_ = cmd.Run()
}

func newXrayCmd(binary string) *exec.Cmd {
	var urls []string
	for rootURL := range structs.GlobalURLMap {
		urls = append(urls, rootURL)
	}
	if len(urls) == 0 {
		return exec.Command(binary, "version")
	}
	// 简单起见：逐个 URL 扫描
	return exec.Command(binary, "webscan", "--url", urls[0])
}
