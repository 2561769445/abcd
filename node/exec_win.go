//go:build windows

package node

import (
	"os/exec"
)

// setPgid windows无进程组, 空实现(CommandContext默认kill)
func setPgid(cmd *exec.Cmd) {}

// killGroup windows空实现
func killGroup(cmd *exec.Cmd) {}
