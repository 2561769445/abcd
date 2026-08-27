package common

import (
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/gologger"
)

// adaptive_tcp.go
// 自适应 TCP 扫描调度器：当出现文件描述符耗尽 / 资源不可用等错误时自动降速，
// 待稳定后逐步恢复并发，避免整机资源被打满导致扫描失败。

func isTCPResourceExhaustedError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	patterns := []string{
		"too many open files", "cannot assign requested address",
		"address already in use", "no buffer space available",
		"connection reset by peer", "resource temporarily unavailable",
		"emfile", "enfile", "eaddrnotavail", "eaddrinuse", "enobufs",
	}
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if errors.Is(ne.Err, os.ErrDeadlineExceeded) {
			return false
		}
	}
	return false
}

func isTCPTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		return errors.Is(ne.Err, os.ErrDeadlineExceeded)
	}
	return strings.Contains(strings.ToLower(err.Error()), "timeout")
}

type adaptiveTCPScanScheduler struct {
	mu            sync.Mutex
	cond          *sync.Cond
	current       int64
	maxConcurrent int64
	minConcurrent int64

	lastAdjust time.Time
	lastLog    time.Time
	recentErr  int64
	success    int64
	fail       int64
	origMaxValue int64
}

func newAdaptiveTCPScanScheduler(max int) *adaptiveTCPScanScheduler {
	if max <= 0 {
		max = 1000
	}
	min := max / 20
	if min < 10 {
		min = 10
	}
	s := &adaptiveTCPScanScheduler{
		maxConcurrent: int64(max),
		minConcurrent: int64(min),
		lastAdjust:    time.Now(),
		lastLog:       time.Now(),
		origMaxValue:  int64(max),
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *adaptiveTCPScanScheduler) acquire() {
	s.mu.Lock()
	for s.current >= s.maxConcurrent {
		s.cond.Wait()
	}
	s.current++
	s.mu.Unlock()
}

func (s *adaptiveTCPScanScheduler) release() {
	s.mu.Lock()
	s.current--
	if s.current < 0 {
		s.current = 0
	}
	s.cond.Signal()
	s.mu.Unlock()
}

func (s *adaptiveTCPScanScheduler) record(err error) {
	if err == nil {
		atomic.AddInt64(&s.success, 1)
		s.recover()
		return
	}
	atomic.AddInt64(&s.fail, 1)
	if isTCPResourceExhaustedError(err) {
		atomic.AddInt64(&s.recentErr, 1)
		s.throttle()
	}
}

// throttle 遇到资源耗尽错误时降速
func (s *adaptiveTCPScanScheduler) throttle() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.lastAdjust) < 2*time.Second {
		return
	}
	newMax := s.maxConcurrent / 2
	if newMax < s.minConcurrent {
		newMax = s.minConcurrent
	}
	if newMax < s.maxConcurrent {
		s.lastAdjust = time.Now()
		gologger.Warning().Msgf("[AdaptiveTCP] 检测到资源耗尽，并发从 %d 降为 %d", s.maxConcurrent, newMax)
		s.maxConcurrent = newMax
		atomic.StoreInt64(&s.recentErr, 0)
	}
	s.maybeLog()
}

// recover 稳定一段时间后缓慢恢复并发
func (s *adaptiveTCPScanScheduler) recover() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Since(s.lastAdjust) < 10*time.Second {
		return
	}
	if atomic.LoadInt64(&s.recentErr) > 0 {
		return
	}
	// 每 30 秒尝试恢复 10%
	if time.Since(s.lastAdjust) > 30*time.Second && s.maxConcurrent < s.origMax() {
		newMax := s.maxConcurrent + s.maxConcurrent/10
		if newMax > s.origMax() {
			newMax = s.origMax()
		}
		s.lastAdjust = time.Now()
		gologger.Info().Msgf("[AdaptiveTCP] 状态稳定，并发恢复为 %d", newMax)
		s.maxConcurrent = newMax
	}
	s.maybeLog()
}

func (s *adaptiveTCPScanScheduler) origMax() int64 {
	return s.origMaxValue
}

func (s *adaptiveTCPScanScheduler) maybeLog() {
	if time.Since(s.lastLog) < 30*time.Second {
		return
	}
	s.lastLog = time.Now()
	gologger.Info().Msgf("[AdaptiveTCP] 当前并发上限 %d，成功 %d，失败 %d", s.maxConcurrent,
		atomic.LoadInt64(&s.success), atomic.LoadInt64(&s.fail))
}
