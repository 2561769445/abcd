//go:build linux || darwin

package node

import (
	"os/exec"
	"syscall"
)

// setPgid 独立进程组: kill时连masscan等孙进程一起收掉, 防孤儿残留
func setPgid(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killGroup 杀整个进程组(子进程+masscan孙进程)
func killGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
