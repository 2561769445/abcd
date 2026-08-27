package master

import (
	"os"
)

// Config 主控配置(环境变量优先, 有默认值)
type Config struct {
	ListenAddr string // Web监听
	PgDSN      string // postgres DSN
	RedisAddr  string
	RedisPass  string
	JWTSecret  string
	AdminUser  string
	AdminPass  string
}

func LoadConfig() *Config {
	c := &Config{
		ListenAddr: getenv("ABCD_LISTEN", ":8080"),
		PgDSN:      getenv("ABCD_PG_DSN", "postgres://abcd:abcd123@127.0.0.1:5432/abcd?sslmode=disable"),
		RedisAddr:  getenv("ABCD_REDIS", "127.0.0.1:6379"),
		RedisPass:  os.Getenv("ABCD_REDIS_PASS"),
		JWTSecret:  getenv("ABCD_JWT_SECRET", "abcd-default-jwt-secret-change-me"),
		AdminUser:  getenv("ABCD_ADMIN_USER", "admin"),
		AdminPass:  getenv("ABCD_ADMIN_PASS", "abcd@2026"),
	}
	return c
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
