package master

import (
	"embed"
)

//go:embed all:dist
var embeddedDist embed.FS

// frontendReady 前端产物是否已构建(非占位文件)
func frontendReady() bool {
	b, err := embeddedDist.ReadFile("dist/index.html")
	if err != nil || len(b) < 200 {
		return false
	}
	return true
}

func frontendReadFile(p string) ([]byte, error) {
	return embeddedDist.ReadFile(p)
}
