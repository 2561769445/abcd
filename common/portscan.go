package common

import (
	"context"
	"net"
	"bytes"
	"abcd/ddout"
	"abcd/lib/masscan"
	"abcd/structs"
	"abcd/utils"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ParsePort(ports string) (scanPorts []int) {
	if ports == "" {
		return
	}
	slices := strings.Split(ports, ",")
	for _, port := range slices {
		port = strings.TrimSpace(port)
		if port == "" {
			continue
		}
		upper := port
		if strings.Contains(port, "-") {
			ranges := strings.Split(port, "-")
			if len(ranges) < 2 {
				continue
			}

			startPort, _ := strconv.Atoi(ranges[0])
			endPort, _ := strconv.Atoi(ranges[1])
			if startPort < endPort {
				port = ranges[0]
				upper = ranges[1]
			} else {
				port = ranges[1]
				upper = ranges[0]
			}
		}
		start, _ := strconv.Atoi(port)
		end, _ := strconv.Atoi(upper)
		for i := start; i <= end; i++ {
			scanPorts = append(scanPorts, i)
		}
	}
	scanPorts = utils.RemoveDuplicateElementInt(scanPorts)
	return scanPorts
}

var BackList map[string]struct{}
var BackListLock sync.Mutex

func PortScanTCP(IPs []string, Ports string, NoPorts string, timeout int) []string {
	var AliveAddress []string
	gologger.AuditTimeLogger("开始TCP端口扫描，端口设置: %s\nTCP端口扫描目标:%s", Ports, strings.Join(IPs, ","))
	ports := ParsePort(Ports)
	noPorts := ParsePort(NoPorts)

	var probePorts []int
	for _, port := range ports {
		ok := false
		for _, nport := range noPorts {
			if nport == port {
				ok = true
				break
			}
		}
		if !ok {
			probePorts = append(probePorts, port)
		}
	}

	IPPortCount := make(map[string]int)
	BackList = make(map[string]struct{})

	workers := structs.GlobalConfig.TCPPortScanThreads
	if workers > len(IPs)*len(probePorts) {
		workers = len(IPs) * len(probePorts)
	}
	Addrs := make(chan Addr, structs.GlobalConfig.TCPPortScanThreads)
	results := make(chan string, structs.GlobalConfig.TCPPortScanThreads)
	var wg sync.WaitGroup

	var sched *adaptiveTCPScanScheduler
	if structs.GlobalConfig.AdaptiveTCPScan {
		sched = newAdaptiveTCPScanScheduler(workers)
		gologger.Info().Msgf("[AdaptiveTCP] ?????? TCP ????????? %d", workers)
	}

	//接收结果
	go func() {
		for found := range results {
			AliveAddress = append(AliveAddress, found)

			t := strings.Split(found, ":")
			ip := t[0]

			count, ok := IPPortCount[ip]
			if ok {
				if count > structs.GlobalConfig.PortsThreshold {
					inblack := false
					BackListLock.Lock()
					_, inblack = BackList[ip]
					BackListLock.Unlock()
					if !inblack {
						BackListLock.Lock()
						BackList[ip] = struct{}{}
						BackListLock.Unlock()
						gologger.Error().Msgf("%s 端口数量超出阈值,放弃扫描", ip)
					}
				}
				IPPortCount[ip] = count + 1
			} else {
				IPPortCount[ip] = 1
			}

			wg.Done()
		}
	}()

	//多线程扫描
	for i := 0; i < workers; i++ {
		go func() {
			for addr := range Addrs {
				if sched != nil {
					sched.acquire()
				}
				err := PortConnect(addr, results, timeout, &wg)
				if sched != nil {
					sched.record(err)
					sched.release()
				}
				wg.Done()
			}
		}()
	}

	//添加扫描目标
	for _, port := range probePorts {
		for _, host := range IPs {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}
	wg.Wait()
	close(Addrs)
	close(results)
	gologger.AuditTimeLogger("TCP端口扫描结束")

	return AliveAddress
}

type Addr struct {
	ip   string
	port int
}

var PortScan bool

func PortConnect(addr Addr, respondingHosts chan<- string, adjustedTimeout int, wg *sync.WaitGroup) error {
	inblack := false
	BackListLock.Lock()
	_, inblack = BackList[addr.ip]
	BackListLock.Unlock()
	if inblack {
		return nil
	}

	host, port := addr.ip, addr.port
	conn, err := WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	if err == nil {
		address := host + ":" + strconv.Itoa(port)
		if PortScan {
			// gologger.Silent().Msgf("[PortScan] %v", address)
			ddout.FormatOutput(ddout.OutputMessage{
				Type: "PortScan",
				IP:   host,
				Port: strconv.Itoa(port),
			})

		} else {
			// gologger.Silent().Msgf("[TCP-Alive] %v", address)
			ddout.FormatOutput(ddout.OutputMessage{
				Type:          "IPAlive",
				IP:            host,
				AdditionalMsg: "TCP:" + strconv.Itoa(port),
			})
		}
		wg.Add(1)
		respondingHosts <- address
	}
	return err
}


// defaultRouteInterface 取第一个非loopback的Up状态网卡作为masscan出包口
func defaultRouteInterface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				return i.Name
			}
		}
	}
	return ""
}


// masscanNetInfo 解析masscan所需的网卡名与网关MAC
func masscanNetInfo() (iface, gwMAC string) {
	iface = defaultRouteInterface()
	if iface == "" {
		return "", ""
	}
	// 默认网关
	gw := ""
	out, err := exec.Command("/bin/bash", "-c", "ip route show default 2>/dev/null | awk '{print $3; exit}'").Output()
	if err == nil {
		gw = strings.TrimSpace(string(out))
	}
	if gw == "" {
		return iface, ""
	}
	// ping一次让网关进ARP表
	_ = exec.Command("/bin/bash", "-c", "ping -c1 -W1 "+gw+" >/dev/null 2>&1").Run()
	// 从ip neigh提取lladdr
	out, err = exec.Command("/bin/bash", "-c", "ip neigh show "+gw+" 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i==\"lladdr\") print $(i+1)}' | head -1").Output()
	if err == nil {
		m := strings.TrimSpace(string(out))
		if strings.Contains(m, ":") {
			return iface, m
		}
	}
	return iface, ""
}

func PortScanSYN(ctx context.Context, IPs []string) []string {
	ips := strings.Join(utils.RemoveDuplicateElement(IPs), "\n")
	err := os.WriteFile("masscan_tmp.txt", []byte(ips), 0666)
	if err != nil {
		return []string{}
	}
	defer os.Remove("masscan_tmp.txt")

	ms := masscan.New(structs.GlobalConfig.MasscanPath)
	ms.SetFileName("masscan_tmp.txt")
	// 尊重任务自定义端口, 未指定则全端口
	synPorts := structs.GlobalConfig.Ports
	if synPorts == "" {
		synPorts = "1-65535"
	}
	ms.SetPorts(synPorts)
	ms.SetRate(strconv.Itoa(structs.GlobalConfig.SYNPortScanThreads))
	// 显式指定出包网卡: 部分系统(如Ubuntu 24.04)masscan无法自检默认网卡
	// 且netlink取网关MAC失败(ARP timed-out), 需显式给--router-mac
	iface, gwMAC := masscanNetInfo()
	// --wait: 发包结束后最多等30秒收尾。云主机virtio虚拟网卡上masscan收包线程
	// 可能收不到包导致无限等待挂起(华为云/百度云实测), 必须硬限制收尾时间
	args := []string{"--retries", "2", "--wait", "30"}
	if iface != "" {
		args = append(args, "--interface", iface)
	}
	if gwMAC != "" {
		args = append(args, "--router-mac", gwMAC)
	}
	if len(args) > 0 {
		ms.SetArgs(args...)
	}
	gologger.Info().Msgf("调用masscan进行SYN端口扫描")
	err = ms.Run(ctx) // 任务取消时联动kill masscan, 不再等满35min
	gologger.AuditTimeLogger("masscan扫描结束")
	if err != nil {
		// 超时被kill/异常退出不直接放弃: 尝试解析已产出的部分结果
		gologger.Error().Msgf("masscan异常退出: %v, 尝试解析已产出结果", err)
	}
	hosts, errParse := ms.Parse()
	if errParse != nil {
		if err != nil {
			return []string{} // 原本就失败且无结果可解析
		}
		gologger.Error().Msgf("masscan结果解析失败")
		return []string{}
	}

	var results []string
	for _, each := range hosts {
		for _, port := range each.Ports {
			results = append(results, each.Address.Addr+":"+port.Portid)
		}
	}
	results = utils.RemoveDuplicateElement(results)
	for _, each := range results {
		// gologger.Silent().Msg("[PortScan] " + each)
		t := strings.Split(each, ":")
		ddout.FormatOutput(ddout.OutputMessage{
			Type: "PortScan",
			IP:   t[0],
			Port: t[1],
		})
	}
	return results
}

// CheckMasScan 校验MasScan是否正确安装
func CheckMasScan() bool {
	var bsenv = ""
	if OS != "windows" {
		bsenv = "/bin/bash"
	}

	var command *exec.Cmd
	if OS == "windows" {
		command = exec.Command("cmd", "/c", structs.GlobalConfig.MasscanPath)
	} else if OS == "linux" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	} else if OS == "darwin" {
		command = exec.Command(bsenv, "-c", structs.GlobalConfig.MasscanPath)
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}
	_ = command.Wait()

	// 未检测到masscan的默认banner
	if !strings.Contains(outinfo.String(), "masscan -p80,8000-8100 10.0.0.0/8 --rate=10000") {
		gologger.Error().Msgf("未检测到路径 %v 存在masscan", structs.GlobalConfig.MasscanPath)
		return false
	}

	return true
}

func RemoveFirewall(ipPorts []string) []string {
	var results []string

	gologger.AuditTimeLogger("移除开放端口过多的目标")

	m := make(map[string][]string)
	for _, ipPort := range ipPorts {
		t := strings.Split(ipPort, ":")
		ip := t[0]
		port := t[1]

		_, ok := m[ip]
		if !ok {
			m[ip] = []string{port}
		} else {
			m[ip] = append(m[ip], port)
		}
	}

	for ip, ports := range m {
		ps := utils.RemoveDuplicateElement(ports)
		if len(ps) >= structs.GlobalConfig.PortsThreshold {
			gologger.Error().Msgf("%s 端口数量超出阈值,已丢弃", ip)
			continue
		}
		for _, p := range ports {
			results = append(results, ip+":"+p)
		}
	}
	return utils.RemoveDuplicateElement(results)
}
