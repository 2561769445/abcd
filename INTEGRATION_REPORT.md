# abcd 集成报告

版权：月落安全研究实验室

本报告说明 abcd 的构建过程：如何对收集到的多份 dddd 二进制进行"反编译"分析，
并抽取/集成其中的 POC、指纹与功能。

## 一、输入资产清单

| 目录 | 二进制 | Go 版本 | 定位 |
|------|--------|---------|------|
| dddd-1.8.3 | dddd (linux amd64) | go1.21.5 | 官方 1.8.3 发布版(带 viewer/katana JS 扫描/POC 索引) |
| dddd-linux-amd64 (2) | dddd | go1.21.5 | 精简版(无 viewer/JS 扫描) |
| dddd-windows其他二开版 | dddd-windows-amd64.exe | go1.25.1 | 二开版(JS/API/泄露扫描最强，ddout 带 CSV) |
| dddd2-V1 | dddd2 及全平台发布 | go1.22.5 | 二开版(ADB 扫描、ddout) |
| dddd202607 | dddd_linux + dddd_windows.exe | go1.24.3 | 2026-07 二开版(webui/callxray/callxscan/ossbucket/自适应TCP) |
| ddddpro改版 | dddd_linux_amd64 / dddd_windows_amd64.exe | go1.23.0 | UPX 压缩二开版(XLSX 输出、多源指纹合并、license 授权系统) |
| dddd_202606 | dddd_linux / dddd.exe / dddd_macos | go1.24.3 | 2026-06 二开版(webui/callxray/callxscan/ossbucket/findre) |
| dddd二开版 | dddd-linux / dddd-mac / dddd.exe | go1.24.0 | 二开版(ADB/ddout) |
| dddd扫描器2026.4更新 | dddd_linux / dddd.exe / dddd_macos | go1.24.0 | 2026.4 二开版(带 config/pocs + xray/xscan 插件) |
| 源码 | dddd-main (GitHub) | go1.21 | 官方 v2.0.2 源码(本工程基础) |

## 二、反编译方法

Go 二进制没有传统意义的"源码反编译"，本次采用以下方法最大化提取信息：

1. **符号表提取(pclntab)**：自研 Go 工具 `gosymdump` 利用 `debug/elf` + `debug/gosym` + `debug/macho` + `debug/pe`
   解析二进制的 pclntab，在 strip(-s -w) 的二进制上仍可还原全部 4万~8万个函数符号，
   据此逐版本对比出**独有功能**。
2. **UPX 脱壳**：ddddpro改版 为 UPX 压缩，先用 `upx -d` 还原后再提取符号。
3. **字符串提取**：提取可打印字符串，还原 POC 名称、接口路径、字典引用、API 域名等逻辑细节。
4. **嵌入资产提取(embedx)**：自研 `embedx.py` 解析 Go `//go:embed` 的 []file 数据结构(支持 ELF/PE/Mach-O)，
   从全部二进制中提取内嵌 POC/指纹/字典，共发现 **9,520 个外部配置没有的独有 POC**。
5. **源码对照**：以官方 v2.0.2 源码为基线，与各二进制的符号表 diff，精确得出新增功能。

## 三、集成后的资产

- POC 模板：**15,731 个有效模板**(13,120 个唯一漏洞 id，全部通过 nuclei 解析器校验)
- 指纹 finger.yaml：**8,053 产品 / 8,670 规则**
- workflow 映射：**1,134 条 / 3,204 个引用全部可解析**(文件名引用 + 目录展开)
- findre 规则：40 条；字典：15 套
- JSON 指纹库：goby / wappalyzer / localFinger / fingerprinthub_web / eHoleFinger / fingers_http

## 四、新增功能(均为 Go 源码实现)

| 模块 | 文件 | 来源还原自 |
|------|------|-----------|
| Web 弱口令爆破 | gopocs/web.go | base183(含 401 预检降误报) |
| XLSX/CSV 输出 | ddout/output_extra.go | ddddpro改版/win_other |
| 自适应 TCP 调度 | common/adaptive_tcp.go | dddd202607 |
| findre 指纹复核 | common/http/findre.go | dddd202606/202607 |
| 云存储桶检测 | common/ossbucket/ossbucket.go | dddd202606/202607 |
| xray 联动 | common/callxray/callxray.go | dddd202606/202607 |
| xscan 联动 | common/callxscan/callxscan.go | dddd202606/202607 |
| 报告查看器 | common/viewer/viewer.go | base183 |
| WebUI 管理界面 | common/webui/*.go | dddd202606/202607 |
| JS 接口/泄露扫描 | common/jsapi.go | dddd-windows其他二开版 |

## 五、质量修复

1. **模板按 id 去重 + 映射文件名保护**：删除 9,635 个重复变体；被 workflow 引用的 2,798 个文件名绝不删除/改名。
2. **目录引用展开**：9 个目录引用展开为 44 个具体模板名。
3. **映射表闭合**：1,134 条映射 / 3,204 个引用全部可解析。
4. **模板有效性校验**：全部通过 nuclei 解析器(0 错误 0 panic)。
5. **Web 弱口令降误报**：401 预检 + WebLogic 登录成功特征判断。
6. **findre/JS 去重限流**：同规则同源去重、单规则限 20 条。
7. **自包含优化**：禁用官方 nuclei-templates 自动下载，屏蔽指向该目录的噪音引用。

## 六、验证

- `go vet ./...` 全通过；三平台(Windows/Linux/macOS)离线编译通过。
- 指纹 8,670 条、workflow 1,134 条、findre 37~40 条规则加载正常。
- `-poc` 文件名引用(如 ac-weak-login)、nuclei 全量加载、findre/JS/OSS/自适应TCP/WebUI 均实测正常。

## 七、未集成说明

1. **ddddpro改版 license 授权系统**：商业付费功能，未集成。
2. **katana 驱动 JS 深度爬取**：依赖缺失库，以自研正则 JS 提取替代。
3. **HTML 报告深层集成**：findre/ossbucket/js 发现通过 ddout 输出，未写入 HTML 报告主体。

---
版权：月落安全研究实验室 | 基于 GPL 协议开源项目 dddd 二次开发，保留上游 LICENSE。
