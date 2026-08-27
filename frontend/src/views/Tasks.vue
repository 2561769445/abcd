<template>
  <div class="page">
    <h2 class="page-title">任务管理</h2>
    <div class="toolbar">
      <el-button type="primary" @click="dlg = true"><el-icon><Plus /></el-icon>&nbsp;新建任务</el-button>
      <el-button @click="load" :icon="'Refresh'">刷新</el-button>
      <span style="color:var(--muted);font-size:12px">每5秒自动刷新</span>
    </div>
    <div class="card">
      <el-table :data="grows" row-key="id" size="default">
        <el-table-column type="expand" width="28">
          <template #default="{row}">
            <div v-if="row._subs" style="padding:4px 8px">
              <div v-for="s in row._subs" :key="s.id" class="subtask-row">
                <span class="mono" style="min-width:230px;display:inline-block">{{ s.name }}</span>
                <el-tag :type="stType(s.status)" size="small">{{ stText(s.status) }}</el-tag>
                <span style="margin-left:10px;font-size:12px;color:var(--muted)">{{ s.progress || 0 }}% {{ s.stage || '' }}</span>
                <span class="mono" style="margin-left:auto;font-size:11px;color:var(--muted)">{{ s.assigned_node || '自动' }} · {{ s.target_count }}目标 · 资产{{ s.found_assets }}/漏洞{{ s.found_vulns }}</span>
                <span style="white-space:nowrap;margin-left:8px">
                  <el-button size="small" type="danger" text @click="stop(s)" v-if="['pending','queued','scanning'].includes(s.status)">停</el-button>
                  <el-button size="small" type="primary" text @click="retry(s)" v-else>重跑</el-button>
                  <el-button size="small" type="info" text @click="detail(s)">详情</el-button>
                  <el-button size="small" type="success" text @click="exportTask(s)">导出</el-button>
                  <el-button size="small" type="danger" text @click="del(s)">删</el-button>
                </span>
              </div>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="任务" min-width="150">
          <template #default="{row}">
            <div style="font-weight:600">
              {{ row.name || '未命名' }}
              <el-tag v-if="row._subs" size="small" type="success" effect="plain" style="margin-left:6px">{{ row._subs.length }}节点并行</el-tag>
            </div>
            <div class="mono" style="color:var(--muted);font-size:11px">{{ row.id }}</div>
          </template>
        </el-table-column>
        <el-table-column label="目标/端口" width="110">
          <template #default="{row}">
            <div>{{ row.target_count }} 个</div>
            <div class="mono" style="color:var(--muted);font-size:11px">{{ row.ports || 'Top1000' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="状态/进度" width="200">
          <template #default="{row}">
            <el-tag :type="stType(row.status)" size="small">{{ stText(row.status) }}</el-tag>
            <el-progress v-if="['queued','scanning','stopping'].includes(row.status)" :percentage="row.progress || 0"
              :stroke-width="8" :color="pgColor(row.progress)"
              :format="() => (row.stage || '调度中') + ' ' + (row.progress || 0) + '%'" style="width:170px;margin-top:4px" />
            <div v-else-if="row.status==='done'" style="color:#10b981;font-size:12px;margin-top:2px">✅ 完成 100%</div>
          </template>
        </el-table-column>
        <el-table-column label="发现" width="100">
          <template #default="{row}"><span style="color:#34d399">{{ row.found_assets }}</span> / <span style="color:#fbbf24">{{ row.found_vulns }}</span></template>
        </el-table-column>
        <el-table-column label="节点" width="110" show-overflow-tooltip>
          <template #default="{row}">{{ row.assigned_node || '自动' }}</template>
        </el-table-column>
        <el-table-column label="创建时间" width="140"><template #default="{row}">{{ fmtTime(row.created_at).slice(5) }}</template></el-table-column>
        <el-table-column label="操作" width="170">
          <template #default="{row}">
            <template v-if="row._subs">
              <el-button size="small" type="danger" plain @click="stopAll(row)" v-if="row._subs.some(s=>['pending','queued','scanning'].includes(s.status))">全停</el-button>
              <el-button size="small" type="primary" plain @click="retryAll(row)" v-else>全重跑</el-button>
              <el-button size="small" type="success" plain @click="exportAll(row)">导出全部</el-button>
              <el-button size="small" type="danger" text @click="delAll(row)">全删</el-button>
            </template>
            <template v-else>
              <el-button size="small" type="danger" plain @click="stop(row)" v-if="['pending','queued','scanning'].includes(row.status)">停止</el-button>
              <el-button size="small" type="primary" plain @click="retry(row)" v-else>重跑</el-button>
              <el-button size="small" type="info" plain @click="detail(row)">详情</el-button>
              <el-button size="small" type="success" plain @click="exportTask(row)">导出</el-button>
              <el-button size="small" type="danger" text @click="del(row)">删</el-button>
            </template>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="dlg" title="新建扫描任务" width="620px" destroy-on-close>
      <el-form label-width="90px">
        <el-form-item label="任务名称"><el-input v-model="form.name" placeholder="如: 某单位外网测绘" /></el-form-item>
        <el-form-item label="扫描目标">
          <el-input v-model="form.targets" type="textarea" :rows="5"
            placeholder="每行一个: 192.168.1.0/24 / 10.0.0.1 / baidu.com / http://x.com:8080" />
        </el-form-item>
        <el-form-item label="端口">
          <el-input v-model="form.ports" placeholder="留空=Top1000, 示例: 80,443,8080 或 1-65535" />
        </el-form-item>
        <el-form-item label="执行节点">
          <el-select v-model="form.node_ids" multiple collapse-tags collapse-tags-tooltip clearable placeholder="不选=所有在线节点均分并行扫; 勾选=指定节点" style="width:100%">
            <el-option v-for="n in nodes" :key="n.id" :value="n.id" :label="`${n.name} (${n.online?'在线':'离线'})`" />
          </el-select>
        </el-form-item>
        <el-form-item label="常用开关">
          <el-checkbox v-model="form.options.subdomain">子域名枚举</el-checkbox>
          <el-checkbox v-model="form.options.tcp_ping">TCP存活探测</el-checkbox>
          <el-checkbox v-model="form.options.skip_host_discovery">跳过存活探测(禁ping,全部当存活)</el-checkbox>
          <el-checkbox v-model="form.options.no_poc">只收集不测漏</el-checkbox>
          <el-checkbox v-model="form.options.no_dir_search">跳过目录探测</el-checkbox>
          <el-checkbox v-model="form.options.no_golang_poc">跳过GoPoc</el-checkbox>
          <el-checkbox v-model="form.options.no_brute">禁服务爆破</el-checkbox>
        </el-form-item>
        <el-form-item label="存活探测说明">
          <span style="color:var(--muted);font-size:12px">
            三种模式: 默认ICMP探测 / 勾"TCP存活探测"+高级里"禁ICMP"=纯TCP探测(防火墙禁ping场景) / 勾"跳过存活探测"=不探测直接全量扫端口(最慢但最全)
          </span>
        </el-form-item>
        <el-form-item label="预设模式">
          <el-radio-group v-model="preset" @change="applyPreset">
            <el-radio-button value="fast">⚡ 快速测绘</el-radio-button>
            <el-radio-button value="std">⚖️ 标准扫描</el-radio-button>
            <el-radio-button value="deep">🎯 深度拿壳</el-radio-button>
            <el-radio-button value="corp">🏢 单位收集</el-radio-button>
          </el-radio-group>
          <div style="width:100%;color:var(--muted);font-size:12px;margin-top:4px">
            {{ presetTip }}
          </div>
        </el-form-item>
        <el-form-item label="扫描方式">
          <el-radio-group v-model="form.options.port_scan_type">
            <el-radio value="tcp">TCP扫描</el-radio><el-radio value="syn">SYN(需masscan)</el-radio>
          </el-radio-group>
        </el-form-item>

        <el-collapse style="margin-bottom:6px">
          <el-collapse-item title="▶ 高级选项(线程/引擎/子域/漏洞/反连/代理/测绘)" name="adv">
            <el-row :gutter="10">
              <el-col :span="8"><el-form-item label="禁扫端口" label-width="82px"><el-input v-model="form.options.no_port" placeholder="如 25,110" size="small" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="TCP线程" label-width="82px"><el-input-number v-model="form.options.tcp_scan_threads" size="small" style="width:100%" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="SYN速率" label-width="82px"><el-input-number v-model="form.options.syn_scan_threads" :min="1000" :step="10000" size="small" style="width:100%" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="端口超时" label-width="82px"><el-input-number v-model="form.options.port_scan_timeout" size="small" style="width:100%" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="Web线程" label-width="82px"><el-input-number v-model="form.options.web_threads" size="small" style="width:100%" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="Web超时" label-width="82px"><el-input-number v-model="form.options.web_timeout" size="small" style="width:100%" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="Nmap线程" label-width="82px"><el-input-number v-model="form.options.nmap_threads" size="small" style="width:100%" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="GoPoc线程" label-width="82px"><el-input-number v-model="form.options.golang_poc_threads" size="small" style="width:100%" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="子域线程" label-width="82px"><el-input-number v-model="form.options.subdomain_brute_threads" size="small" style="width:100%" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="HTTP代理" label-width="82px"><el-input v-model="form.options.http_proxy" placeholder="http://127.0.0.1:8080" size="small" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="漏洞等级" label-width="82px">
                <el-select v-model="form.options.severity" size="small" clearable placeholder="全部" style="width:100%">
                  <el-option value="critical" /><el-option value="high" /><el-option value="medium" /><el-option value="low" /><el-option value="info" />
                </el-select>
              </el-form-item></el-col>
              <el-col :span="8"><el-form-item label="排除tags" label-width="82px"><el-input v-model="form.options.exclude_tags" placeholder="逗号分隔" size="small" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="Poc匹配" label-width="82px"><el-input v-model="form.options.poc_name" placeholder="如 thinkphp" size="small" /></el-form-item></el-col>
              <el-col :span="8"><el-form-item label="爆破凭证" label-width="82px"><el-input v-model="form.options.username_password" placeholder="admin : password" size="small" /></el-form-item></el-col>
              <el-col :span="24">
                <el-form-item label="功能开关" label-width="82px">
                  <el-checkbox v-model="form.options.no_icmp_ping" size="small">禁ICMP</el-checkbox>
                  <el-checkbox v-model="form.options.no_subdomain_brute" size="small">禁子域爆破</el-checkbox>
                  <el-checkbox v-model="form.options.no_subfinder" size="small">禁SubFinder</el-checkbox>
                  <el-checkbox v-model="form.options.allow_cdn" size="small">扫CDN资产</el-checkbox>
                  <el-checkbox v-model="form.options.local_domain" size="small">允许内网解析</el-checkbox>
                  <el-checkbox v-model="form.options.no_host_bind" size="small">禁Host绑定探测</el-checkbox>
                  <el-checkbox v-model="form.options.disable_general_poc" size="small">禁通用Poc</el-checkbox>
                  <el-checkbox v-model="form.options.no_interactsh" size="small">禁反连</el-checkbox>
                  <el-checkbox v-model="form.options.adaptive_tcp" size="small">自适应TCP</el-checkbox>
                  <el-checkbox v-model="form.options.findre" size="small">findre复核</el-checkbox>
                  <el-checkbox v-model="form.options.js" size="small">JS敏感信息</el-checkbox>
                  <el-checkbox v-model="form.options.oss" size="small">OSS桶检测</el-checkbox>
                </el-form-item>
              </el-col>
              <el-col :span="24">
                <el-form-item label="测绘引擎" label-width="82px">
                  <el-checkbox v-model="form.options.hunter" size="small">Hunter</el-checkbox>
                  <el-checkbox v-model="form.options.fofa" size="small">Fofa</el-checkbox>
                  <el-checkbox v-model="form.options.quake" size="small">Quake</el-checkbox>
                  <el-checkbox v-model="form.options.low_perception_mode" size="small">低感知模式</el-checkbox>
                  <el-checkbox v-model="form.options.only_ip_port" size="small">只取IP:Port</el-checkbox>
                  <span style="color:var(--muted);font-size:12px;margin-left:8px">(API Key读节点config/api-config.yaml)</span>
                </el-form-item>
              </el-col>
            </el-row>
          </el-collapse-item>
        </el-collapse>
      </el-form>
      <template #footer>
        <el-button @click="dlg=false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">创建任务</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="dtask" :title="dtask?.id || ''" size="600px">
      <el-descriptions :column="1" border>
        <el-descriptions-item label="目标">{{ dtask?.targets }}</el-descriptions-item>
        <el-descriptions-item label="状态">{{ dtask?.status }}</el-descriptions-item>
        <el-descriptions-item label="资产 / 漏洞">{{ dtask?.found_assets }} / {{ dtask?.found_vulns }}</el-descriptions-item>
        <el-descriptions-item label="实时状态">{{ JSON.stringify(dlive) }}</el-descriptions-item>
      </el-descriptions>
    </el-drawer>
  </div>
</template>
<script setup>
import { ref, reactive, computed, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, fmtTime } from '../api'
const rows = ref([]), nodes = ref([]), dlg = ref(false), saving = ref(false), dtask = ref(false), dlive = ref({})
// 多节点子任务聚合: 按去掉" [节点名]"后缀的任务名分组, 单行展示聚合状态, 展开看子任务
const grows = computed(() => {
  const map = new Map()
  for (const r of rows.value) {
    const base = (r.name || '未命名').replace(/\s*\[[^\]]+\]\s*$/, '')
    if (!map.has(base)) map.set(base, [])
    map.get(base).push(r)
  }
  const out = []
  for (const [base, subs] of map) {
    if (subs.length === 1) { out.push({ ...subs[0], _subs: null }); continue }
    const n = subs.length
    const done = subs.filter(s => s.status === 'done').length
    const running = subs.some(s => ['scanning', 'stopping'].includes(s.status))
    const queued = subs.some(s => ['queued', 'pending'].includes(s.status))
    const failed = subs.some(s => s.status === 'failed')
    const status = done === n ? 'done' : running ? 'scanning' : queued ? 'queued' : failed ? 'failed' : subs[0].status
    out.push({
      id: 'g:' + subs[0].id,
      name: base,
      target_count: subs.reduce((a, s) => a + (s.target_count || 0), 0),
      ports: subs[0].ports,
      status,
      progress: Math.round(subs.reduce((a, s) => a + (s.progress || 0), 0) / n),
      stage: `${done}/${n} 子任务完成`,
      found_assets: subs.reduce((a, s) => a + (s.found_assets || 0), 0),
      found_vulns: subs.reduce((a, s) => a + (s.found_vulns || 0), 0),
      assigned_node: `${n} 节点`,
      created_at: subs[0].created_at,
      _subs: subs
    })
  }
  return out
})
const stopAll = async r => { for (const s of r._subs) await api.post(`/tasks/${s.id}/stop`); ElMessage.success('已对全部子任务下发停止指令'); load() }
const retryAll = async r => { for (const s of r._subs) await api.post(`/tasks/${s.id}/retry`); ElMessage.success('已全部重新入队'); load() }
const delAll = async r => {
  await ElMessageBox.confirm(`确认删除「${r.name}」的全部 ${r._subs.length} 个子任务?`, '提示', { type: 'warning' })
  for (const s of r._subs) await api.delete(`/tasks/${s.id}`)
  load()
}
const exportAll = async r => {
  // 聚合一份: 全部子任务的漏洞(带数据包)+资产合并单个报告
  try {
    const ids = r._subs.map(s => s.id).join(',')
    const e = await api.post('/exports', { type: 'task', format: 'html', task_id: '', task_ids: ids }, { timeout: 300000 })
    window.open('/api/exports/' + e.id + '/download?token=' + localStorage.getItem('token'), '_blank')
    ElMessage.success(`已生成聚合报告(${r._subs.length}个子任务合并一份)`)
  } catch (err) { ElMessage.error('导出失败: ' + (err?.response?.data?.error || '超时')) }
}
const emptyOptions = () => ({ subdomain: false, tcp_ping: false, skip_host_discovery: false, no_icmp_ping: false, no_poc: false, no_dir_search: false, no_golang_poc: false, no_brute: false, port_scan_type: 'syn', no_port: '', tcp_scan_threads: 0, syn_scan_threads: 0, port_scan_timeout: 0, web_threads: 0, web_timeout: 0, nmap_threads: 0, golang_poc_threads: 0, subdomain_brute_threads: 0, http_proxy: '', severity: '', exclude_tags: '', poc_name: '', username_password: '', no_subdomain_brute: false, no_subfinder: false, allow_cdn: false, local_domain: false, no_host_bind: false, disable_general_poc: false, no_interactsh: false, adaptive_tcp: false, findre: false, js: false, oss: false, xray: false, xscan: false, hunter: false, fofa: false, quake: false, low_perception_mode: false, only_ip_port: false })
const form = reactive({ name: '', targets: '', ports: '', node_ids: [], options: emptyOptions() })
const preset = ref('std')
const PORT_FAST = '21,22,23,80,81,443,445,1433,1521,3306,3389,5432,6379,7001,7002,8000,8080,8081,8088,8090,8443,8888,9000,9090,9200,11211,27017'
const presetTip = ref('端口Top1000+目录爆破+全量PoC, 慢但全')
const applyPreset = v => {
  const o = form.options
  if (v === 'fast') {
    form.ports = PORT_FAST
    o.tcp_ping = true; o.no_icmp_ping = true
    o.port_scan_timeout = 3; o.tcp_scan_threads = 3000; o.syn_scan_threads = 30000
    o.no_dir_search = true; o.no_poc = true; o.web_threads = 400; o.web_timeout = 5
    presetTip.value = 'TOP28高频端口+纯TCP探活+3s超时+3000线程+跳目录跳PoC — 300个IP约10~20分钟出资产测绘'
  } else if (v === 'std') {
    form.ports = ''
    o.port_scan_type = 'syn'; o.tcp_ping = true; o.no_icmp_ping = false
    o.port_scan_timeout = 4; o.tcp_scan_threads = 2000
    o.no_dir_search = false; o.no_poc = false; o.no_golang_poc = false
    o.web_threads = 300; o.web_timeout = 8
    presetTip.value = 'Top1000端口+目录爆破+指纹驱动PoC(workflow映射表) — 均衡, 300个IP约1~3小时'
  } else if (v === 'deep') {
    form.ports = '1-65535'
    o.skip_host_discovery = true
    o.port_scan_timeout = 3; o.tcp_scan_threads = 5000; o.syn_scan_threads = 20000
    o.no_dir_search = false; o.no_poc = false
    o.web_threads = 300; o.web_timeout = 10
    // 已精简: 子域爆破(11.4万字典最慢)/JS敏感信息/findre/OSS 不再默认开, 需要时在开关里手动勾
    o.subdomain = false; o.js = false; o.findre = false; o.oss = false
    presetTip.value = '全端口65535+目录爆破+指纹驱动PoC(workflow映射表精准匹配) — 已精简提速: 去掉子域爆破/JS/findre/OSS(要就在上面开关手动勾); SYN 20k为实测最优'
  } else if (v === 'corp') {
    form.ports = ''
    o.port_scan_type = 'syn'; o.tcp_ping = true
    o.no_dir_search = false; o.no_poc = false
    o.web_threads = 300; o.web_timeout = 8
    o.subdomain = false
    form.options.hunter = true
    presetTip.value = '目标框每行填一个【公司全名】 — 自动转鹰图语法 icp.name="公司" 并限定近一年数据, 拉取备案资产后按标准扫描跑; 需在系统设置配Hunter Key'
  }
}
let timer
async function load() {
  try { rows.value = (await api.get('/tasks')) || [] } catch {}
}
async function loadNodes() { try { nodes.value = (await api.get('/nodes')) || [] } catch {} }
async function save() {
  let targets = form.targets.split('\n').map(s => s.trim()).filter(Boolean)
  if (!targets.length) return ElMessage.warning('请输入目标')
  // 单位收集模式: 公司名 -> 鹰图icp语法直查(引擎原样传Hunter API), 自动限定近一年数据
  if (preset.value === 'corp') {
    const before = new Date().toISOString().slice(0, 10)
    const after = new Date(Date.now() - 365 * 86400000).toISOString().slice(0, 10)
    targets = targets.map(t => t.includes('=') ? t : 'icp.name="' + t + '"&&after="' + after + '"&&before="' + before + '"')
    form.options.hunter = true
  }
  // 不选执行节点 = 所有在线节点均分并行扫
  const nids = (form.node_ids && form.node_ids.length)
    ? form.node_ids
    : nodes.value.filter(n => n.online).map(n => n.id)
  if (!nids.length) return ElMessage.warning('没有在线节点, 无法创建任务')
  saving.value = true
  try {
    if (nids.length <= 1) {
      await api.post('/tasks', { name: form.name || '未命名任务', targets, ports: form.ports, node_id: nids[0] || '', options: form.options })
      ElMessage.success('任务已创建, 等待调度派发')
    } else {
      // 勾选多节点: 目标轮询均分, 每节点一个子任务并行扫
      const nameMap = {}; nodes.value.forEach(n => nameMap[n.id] = n.name)
      const buckets = {}; nids.forEach(id => buckets[id] = [])
      targets.forEach((t, i) => buckets[nids[i % nids.length]].push(t))
      let k = 0
      for (const id of nids) {
        if (!buckets[id].length) continue
        k++
        await api.post('/tasks', { name: (form.name || '未命名任务') + ' [' + (nameMap[id] || id) + ']', targets: buckets[id], ports: form.ports, node_id: id, options: form.options })
      }
      ElMessage.success(`已拆成 ${k} 个子任务并行分发到 ${k} 个节点`)
    }
    dlg.value = false
    form.name = ''; form.targets = ''; form.ports = ''; form.node_ids = []; form.options = emptyOptions()
  } catch (e) { ElMessage.error(e.response?.data?.error || '创建失败') }
  finally { saving.value = false }
}
const stop = async r => { await api.post(`/tasks/${r.id}/stop`); ElMessage.success('已下发停止指令'); load() }
const retry = async r => { await api.post(`/tasks/${r.id}/retry`); ElMessage.success('已重新入队'); load() }
const del = async r => { await ElMessageBox.confirm('确认删除该任务?', '提示', { type: 'warning' }); await api.delete(`/tasks/${r.id}`); load() }
const detail = async r => { const d = await api.get(`/tasks/${r.id}`); dtask.value = d.task; dlive.value = d.live; dtask.value = true }
const exportTask = async r => {
  try {
    // HTML任务汇总: 漏洞(含数据包)+资产清单 一个文件
    const e = await api.post('/exports', { type: 'task', format: 'html', task_id: r.id }, { timeout: 300000 })
    ElMessage.success('已生成任务汇总HTML报告(含漏洞数据包)')
    window.open('/api/exports/' + e.id + '/download?token=' + localStorage.getItem('token'), '_blank')
  } catch (err) { ElMessage.error('导出失败') }
}
const pgColor = p => p >= 90 ? '#10b981' : p >= 45 ? '#00d4aa' : '#f59e0b'
const stType = st => ({done:'success', scanning:'primary', queued:'warning', pending:'info', failed:'danger', stopped:'info', stopping:'warning'}[st] || 'info')
const stText = st => ({done:'已完成', scanning:'扫描中', queued:'已派发', pending:'待执行', failed:'失败', stopped:'已终止', stopping:'停止中', scheduled:'定时'}[st] || st)
onMounted(() => { load(); loadNodes(); timer = setInterval(load, 5000) })
onUnmounted(() => clearInterval(timer))
</script>
<style scoped>
.subtask-row { display: flex; align-items: center; gap: 6px; padding: 5px 4px; border-bottom: 1px dashed var(--border, #eee); font-size: 12px; }
.subtask-row:last-child { border-bottom: none; }
</style>
