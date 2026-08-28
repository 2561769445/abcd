package uncover

import (
	"fmt"
	"testing"
)

func TestSmartQuakeQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		// 域名 → domain语法
		{"v2share.org", `domain:"v2share.org"`},
		{"www.target.com", `domain:"www.target.com"`},
		// IP/CIDR → ip语法
		{"192.0.2.10", `ip:"192.0.2.10"`},
		{"192.168.1.0/24", `ip:"192.168.1.0/24"`},
		// IP段对齐 → CIDR
		{"1.2.3.0-1.2.3.255", `ip:"1.2.3.0/24"`},
		{"10.0.0.0-10.255.255.255", `ip:"10.0.0.0/8"`},
		// URL → 拆host
		{"http://192.0.2.10:6379/", `ip:"192.0.2.10"`},
		{"https://v2share.org/login", `domain:"v2share.org"`},
		// IP:Port / 域名:Port → 拆host
		{"192.0.2.10:6379", `ip:"192.0.2.10"`},
		{"www.xx.com:8080", `domain:"www.xx.com"`},
		// 已是语法 → 透传
		{`domain:"a.com"`, `domain:"a.com"`},
		{`ip:"1.1.1.1" AND port:"80"`, `ip:"1.1.1.1" AND port:"80"`},
		{`app:"通用"`, `app:"通用"`},
		// 纯关键词 → 透传全文检索
		{"某公司官网", "某公司官网"},
		// 空白
		{"", ""},
	}
	for _, c := range cases {
		got := SmartQuakeQuery(c.in)
		status := "PASS"
		if got != c.want {
			status = "FAIL"
			t.Errorf("SmartQuakeQuery(%q) = %q, want %q", c.in, got, c.want)
		}
		fmt.Printf("  [%s] %-28s => %s\n", status, c.in, got)
	}
	// IP段不对齐 → 警告透传(不崩溃, 返回原文)
	got := SmartQuakeQuery("1.2.3.5-1.2.3.99")
	if got != "1.2.3.5-1.2.3.99" {
		t.Errorf("IP段不对齐应透传原文, got %q", got)
	}
	fmt.Printf("  [PASS] %-28s => %s (不对齐透传)\n", "1.2.3.5-1.2.3.99", got)
}
