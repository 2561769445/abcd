package masscan

import (
	"bytes"
	"context"
	"encoding/xml"
	"github.com/pkg/errors"
	"io"
	"os/exec"
	"time"
)

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL string `xml:"reason_ttl,attr"`
}
type Host struct {
	XMLName xml.Name `xml:"host"`
	Endtime string   `xml:"endtime,attr"`
	Address Address  `xml:"address"`
	Ports   Ports    `xml:"ports>port"`
}
type Ports []struct {
	Protocol string  `xml:"protocol,attr"`
	Portid   string  `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
}
type Service struct {
	Name   string `xml:"name,attr"`
	Banner string `xml:"banner,attr"`
}

type Masscan struct {
	SystemPath string
	Args       []string
	Ports      string
	FileName   string
	Rate       string
	Exclude    string
	Result     []byte
}

func (m *Masscan) SetSystemPath(systemPath string) {
	if systemPath != "" {
		m.SystemPath = systemPath
	}
}
func (m *Masscan) SetArgs(arg ...string) {
	m.Args = arg
}
func (m *Masscan) SetPorts(ports string) {
	m.Ports = ports
}
func (m *Masscan) SetFileName(name string) {
	m.FileName = name
}

func (m *Masscan) SetRate(rate string) {
	m.Rate = rate
}
func (m *Masscan) SetExclude(exclude string) {
	m.Exclude = exclude
}

// Start scanning: ctx取消(任务停止)或35min超时会kill masscan并保留已产出结果
func (m *Masscan) Run(ctx context.Context) error {
	var (
		cmd        *exec.Cmd
		outb, errs bytes.Buffer
	)
	if m.Rate != "" {
		m.Args = append(m.Args, "--rate")
		m.Args = append(m.Args, m.Rate)
	}
	if m.FileName != "" {
		m.Args = append(m.Args, "-iL")
		m.Args = append(m.Args, m.FileName)
	}
	if m.Ports != "" {
		m.Args = append(m.Args, "-p")
		m.Args = append(m.Args, m.Ports)
	}
	if m.Exclude != "" {
		m.Args = append(m.Args, "--exclude")
		m.Args = append(m.Args, m.Exclude)
	}
	m.Args = append(m.Args, "-oX")
	m.Args = append(m.Args, "-")
	// 35min硬超时兜底: masscan在云虚拟网卡上可能无限挂起; 挂到任务ctx下, 停止任务立即kill
	cctx, cancel := context.WithTimeout(ctx, 35*time.Minute)
	defer cancel()
	cmd = exec.CommandContext(cctx, m.SystemPath, m.Args...)
	cmd.Stdout = &outb
	cmd.Stderr = &errs
	err := cmd.Run()
	m.Result = outb.Bytes() // 无论成败保留已有输出, 供上层解析已发现端口
	if err != nil {
		if errs.Len() > 0 {
			return errors.New(errs.String())
		}
		return err
	}
	return nil
}

// Parse scans result.
func (m *Masscan) Parse() ([]Host, error) {
	var hosts []Host
	decoder := xml.NewDecoder(bytes.NewReader(m.Result))
	for {
		t, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			// XML截断(超时被kill): 返回已完整解析的host而非全部丢弃
			if len(hosts) > 0 {
				return hosts, nil
			}
			return nil, err
		}
		if t == nil {
			break
		}
		switch se := t.(type) {
		case xml.StartElement:
			if se.Name.Local == "host" {
				var host Host
				err := decoder.DecodeElement(&host, &se)
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, err
				}
				hosts = append(hosts, host)
			}
		default:
		}
	}
	return hosts, nil
}
func New(SystemPath string) *Masscan {
	return &Masscan{
		SystemPath: SystemPath,
	}
}
