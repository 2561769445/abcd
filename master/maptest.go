package master

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// handleMapKeyTest 验证测绘key可用性: 发最小查询, 返回有效性+剩余配额
func handleMapKeyTest(c *gin.Context) {
	var req struct {
		Engine string `json:"engine"` // hunter/fofa/quake
	}
	if err := c.BindJSON(&req); err != nil || req.Engine == "" {
		c.JSON(400, gin.H{"error": "参数错误"})
		return
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	switch req.Engine {
	case "hunter":
		key := getSetting("hunter_key")
		if key == "" {
			c.JSON(400, gin.H{"error": "请先保存Hunter Key"})
			return
		}
		search := base64.URLEncoding.EncodeToString([]byte(`ip="127.0.0.1"`))
		url := "https://hunter.qianxin.com/openApi/search?api-key=" + key + "&search=" + search + "&page=1&page_size=10&is_web=3"
		body := httpGetBody(ctx, url)
		var r struct {
			Code int    `json:"code"`
			Msg  string `json:"message"`
			Data struct {
				RestQuota string `json:"rest_quota"`
				Total     int    `json:"total"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			c.JSON(500, gin.H{"error": "响应解析失败: " + string(body[:min(len(body), 120)])})
			return
		}
		if r.Code == 200 {
			c.JSON(200, gin.H{"ok": true, "msg": "Key有效 · 剩余配额 " + r.Data.RestQuota})
		} else {
			c.JSON(200, gin.H{"ok": false, "msg": "code=" + itoa(r.Code) + " " + r.Msg})
		}
	case "fofa":
		key := getSetting("fofa_key")
		if key == "" {
			c.JSON(400, gin.H{"error": "请先保存FOFA Key"})
			return
		}
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			c.JSON(200, gin.H{"ok": false, "msg": "格式错误, 应为 邮箱:key"})
			return
		}
		qb := base64.StdEncoding.EncodeToString([]byte(`ip="1.1.1.1"`))
		url := "https://fofa.info/api/v1/search/all?email=" + parts[0] + "&key=" + parts[1] + "&qbase64=" + qb + "&size=1"
		body := httpGetBody(ctx, url)
		var r struct {
			Error   bool   `json:"error"`
			Errmsg  string `json:"errmsg"`
			Size    int    `json:"size"`
			Mode    string `json:"mode"`
			IsVIP   bool   `json:"isvip"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			c.JSON(500, gin.H{"error": "响应解析失败: " + string(body[:min(len(body), 120)])})
			return
		}
		if !r.Error {
			vip := "普通会员"
			if r.IsVIP {
				vip = "VIP"
			}
			c.JSON(200, gin.H{"ok": true, "msg": "Key有效 · " + vip + " · 模式 " + r.Mode})
		} else {
			c.JSON(200, gin.H{"ok": false, "msg": r.Errmsg})
		}
	case "quake":
		key := getSetting("quake_key")
		if key == "" {
			c.JSON(400, gin.H{"error": "请先保存Quake Key"})
			return
		}
		reqQ, _ := http.NewRequestWithContext(ctx, "GET", "https://quake.360.net/api/v3/user/info", nil)
		reqQ.Header.Set("X-QuakeToken", key)
		resp, err := http.DefaultClient.Do(reqQ)
		if err != nil {
			c.JSON(500, gin.H{"error": "请求失败: " + err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var r struct {
			Code int    `json:"code"`
			Msg  string `json:"message"`
			Data struct {
				User struct {
					FreeCount int `json:"free_count"`
					Vip       struct {
						EndTime string `json:"end_time"`
					} `json:"vip"`
				} `json:"user"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			c.JSON(500, gin.H{"error": "响应解析失败"})
			return
		}
		if r.Code == 0 {
			vip := r.Data.User.Vip.EndTime
			msg := "Key有效 · 免费配额剩余 " + itoa(r.Data.User.FreeCount)
			if vip != "" {
				msg += " · VIP至 " + vip[:min(len(vip), 10)]
			}
			c.JSON(200, gin.H{"ok": true, "msg": msg})
		} else {
			c.JSON(200, gin.H{"ok": false, "msg": "code=" + itoa(r.Code) + " " + r.Msg})
		}
	default:
		c.JSON(400, gin.H{"error": "engine必须是hunter/fofa/quake"})
	}
}

func httpGetBody(ctx context.Context, url string) []byte {
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return []byte(`{"error":true,"errmsg":"` + err.Error() + `"}`)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
