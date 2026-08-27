package main

import (
	"context"
	"abcd/common"
	"abcd/common/viewer"
	"abcd/common/webui"
	"abcd/engine"
	"abcd/master"
	"abcd/node"
	"abcd/structs"
	"os"
)

func main() {
	// 分布式模式早期分流: -node / -master 在常规flag解析前拦截
	for _, arg := range os.Args[1:] {
		if arg == "-node" || arg == "--node" {
			nodeMain()
			return
		}
		if arg == "-node-exec" {
			// 节点并发子进程: -node-exec <task.json>, 跑完单任务退出(全局状态进程隔离)
			node.ExecRun(os.Args[2:])
			return
		}
		if arg == "-master" || arg == "--master" {
			masterMain()
			return
		}
	}

	common.Flag()

	// abcd: 按需启动 Web 管理界面 / 报告查看器
	if structs.GlobalConfig.WebUI {
		webui.Run(structs.GlobalConfig.WebUIAddr)
	}
	if structs.GlobalConfig.Viewer {
		viewer.Run(structs.GlobalConfig.ViewerAddr)
	}

	_ = engine.RunScan(context.Background())
}

// nodeMain -node 模式
func nodeMain() {
	node.Run()
}

// masterMain -master 模式
func masterMain() {
	master.Run()
}
