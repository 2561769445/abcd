// portmux: 单端口协议分流器
// 监听对外端口, 嗅探首包: HTTP方法(GET/POST/...) → HTTP后端; 其余(Redis RESP/inline) → Redis后端
package main

import (
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var (
	listenAddr = getenv("MUX_LISTEN", ":6379")
	httpAddr   = getenv("MUX_HTTP", "127.0.0.1:8080")
	redisAddr  = getenv("MUX_REDIS", "127.0.0.1:6390")
)

var httpMethods = map[string]bool{
	"GET": true, "POST": true, "PUT": true, "DELETE": true, "HEAD": true,
	"OPTIONS": true, "PATCH": true, "CONNECT": true, "TRACE": true,
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func main() {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("portmux %s -> HTTP:%s Redis:%s", listenAddr, httpAddr, redisAddr)
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c)
	}
}

func handle(c net.Conn) {
	defer c.Close()
	// 嗅探首包前缀(阻塞读, 客户端会立即发请求)
	buf := make([]byte, 16)
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	n, err := c.Read(buf)
	if err != nil || n == 0 {
		return
	}
	c.SetReadDeadline(time.Time{})

	target := redisAddr
	head := buf[:n]
	if idx := strings.IndexByte(string(head), ' '); idx > 0 {
		if httpMethods[string(head[:idx])] {
			target = httpAddr
		}
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		return
	}
	defer up.Close()
	// 首包转发 + 双向透传
	if _, err := up.Write(head); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go pipe(up, c, done)
	go pipe(c, up, done)
	<-done
}

func pipe(a, b net.Conn, done chan struct{}) {
	io.Copy(a, b)
	done <- struct{}{}
}
