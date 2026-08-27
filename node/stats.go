package node

import (
	"runtime"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// loadStats 采集本机CPU/内存负载
func loadStats() (cpuP float64, memP float64) {
	defer func() {
		if cpuP < 0 {
			cpuP = 0
		}
		if memP < 0 {
			memP = 0
		}
	}()
	if pct, err := cpu.Percent(0, false); err == nil && len(pct) > 0 {
		cpuP = pct[0]
	}
	if vm, err := mem.VirtualMemory(); err == nil {
		memP = vm.UsedPercent
	} else {
		// 兜底: Go运行时估算
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		if ms.Sys > 0 {
			// 仅近似, 无总内存信息时返回0
			memP = 0
		}
	}
	return
}
