<template>
  <div class="page">
    <h2 class="page-title">漏洞管理</h2>
    <div class="toolbar">
      <el-select v-model="q.task_ids" placeholder="按任务筛选" clearable filterable style="width:260px" @change="load">
        <el-option v-for="t in taskOptions" :key="t.value" :value="t.value" :label="t.label" />
      </el-select>
      <el-select v-model="q.severity" placeholder="风险等级" clearable style="width:120px" @change="load">
        <el-option value="critical" label="严重" /><el-option value="high" label="高危" />
        <el-option value="medium" label="中危" /><el-option value="low" label="低危" /><el-option value="info" label="提示" />
      </el-select>
      <el-select v-model="q.status" placeholder="修复状态" clearable style="width:130px" @change="load">
        <el-option value="open" label="未修复" /><el-option value="fixed" label="已修复" /><el-option value="ignored" label="已忽略" />
      </el-select>
      <el-input v-model="q.search" placeholder="搜索目标/漏洞名" clearable style="width:200px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
      <el-button type="success" plain :loading="exporting" @click="doExport">📥 导出Excel</el-button>
      <el-button plain :loading="exporting" @click="doExport('csv')">📥 导出CSV</el-button>
      <el-button type="warning" plain :loading="exporting" @click="doExport('html')">📄 导出HTML(含数据包)</el-button>
      <span v-if="selected.length" style="color:#00d4aa;font-size:12px">已勾选 {{ selected.length }} 条 — 导出只含勾选项</span>
    </div>
    <div class="card">
      <el-table :data="rows" size="small" :height="tableH" :fit="true" style="width:100%" @selection-change="s => selected = s">
        <el-table-column type="selection" width="40" reserve-selection />
        <el-table-column label="等级" width="85">
          <template #default="{row}">
            <el-tag size="small" class="sev-tag" :style="sevStyle(row.severity)">{{ sevText(row.severity) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="vuln_id" label="漏洞名称" min-width="200" show-overflow-tooltip />
        <el-table-column label="影响目标" min-width="180" show-overflow-tooltip>
          <template #default="{row}">
            <a v-if="row.target && row.target.startsWith('http')" :href="row.target" target="_blank" rel="noopener" class="uri-link mono">{{ row.target }}</a>
            <span v-else class="mono">{{ row.target }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="source" label="引擎" width="80" />
        <el-table-column prop="detail" label="详情" min-width="180" show-overflow-tooltip />
        <el-table-column label="状态" width="90">
          <template #default="{row}">
            <el-tag size="small" :type="stType(row.status)">{{ stText(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="所属任务" width="170" show-overflow-tooltip>
          <template #default="{row}">{{ taskName(row.task_id) }}</template>
        </el-table-column>
        <el-table-column label="发现时间" width="145"><template #default="{row}">{{ fmtTime(row.first_seen) }}</template></el-table-column>
        <el-table-column label="操作" width="210">
          <template #default="{row}">
            <el-button size="small" text type="primary" @click="showPkt(row)">数据包</el-button>
            <el-button size="small" text type="success" @click="setStatus(row, 'fixed')">标记修复</el-button>
            <el-button size="small" text type="info" @click="setStatus(row, 'ignored')">忽略</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-drawer v-model="pktDlg" :title="pktVuln?.vuln_id || '漏洞详情'" size="680px">
      <div v-if="pktVuln">
        <el-descriptions :column="1" border size="small">
          <el-descriptions-item label="等级"><el-tag size="small" :style="sevStyle(pktVuln.severity)">{{ sevText(pktVuln.severity) }}</el-tag></el-descriptions-item>
          <el-descriptions-item label="目标"><span class="mono">{{ pktVuln.target }}</span></el-descriptions-item>
          <el-descriptions-item label="详情">{{ pktVuln.detail }}</el-descriptions-item>
          <el-descriptions-item label="引擎">{{ pktVuln.source }} · {{ pktVuln.task_id }}</el-descriptions-item>
          <el-descriptions-item label="发现时间">{{ fmtTime(pktVuln.first_seen) }}</el-descriptions-item>
        </el-descriptions>
        <div v-if="pkt.description" style="margin-top:14px;padding:10px 12px;background:var(--bg2,#161b22);border-left:3px solid #00d4aa66;font-size:12px;color:var(--muted)">{{ pkt.description }}</div>
        <div v-if="pkt.reference && pkt.reference.length" style="margin-top:8px;font-size:12px;color:var(--muted)">
          参考: <a v-for="r in pkt.reference" :key="r" :href="r" target="_blank" rel="noopener" style="color:#67e8f9;margin-right:10px">{{ r }}</a>
        </div>
        <template v-if="pkt.request || pkt.response || pkt.curl">
          <div v-if="pkt.request" style="margin-top:14px">
            <div style="color:#8b949e;font-size:11px;margin-bottom:4px">请求 Request</div>
            <pre class="pkt-pre">{{ pkt.request }}</pre>
          </div>
          <div v-if="pkt.response" style="margin-top:12px">
            <div style="color:#8b949e;font-size:11px;margin-bottom:4px">响应 Response</div>
            <pre class="pkt-pre">{{ pkt.response }}</pre>
          </div>
          <div v-if="pkt.curl" style="margin-top:12px">
            <div style="color:#8b949e;font-size:11px;margin-bottom:4px">curl 复现命令</div>
            <pre class="pkt-pre">{{ pkt.curl }}</pre>
          </div>
        </template>
        <el-empty v-else description="该漏洞无数据包(部分引擎只回显文本结果)" :image-size="60" style="margin-top:20px" />
      </div>
    </el-drawer>
  </div>
</template>
<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api, fmtTime } from '../api'
const rows = ref([])
const tasks = ref([])
const tableH = window.innerHeight - 220
const q = reactive({ severity: '', status: '', search: '', task_ids: '' })
// 多节点子任务聚合: 选"象山"=同时筛4个子任务的漏洞
const taskOptions = computed(() => {
  const map = new Map()
  for (const t of tasks.value) {
    const base = (t.name || '未命名').replace(/\s*\[[^\]]+\]\s*$/, '')
    if (!map.has(base)) map.set(base, [])
    map.get(base).push(t)
  }
  return [...map.entries()].map(([base, subs]) => ({
    label: subs.length > 1 ? `${base} (${subs.length}节点并行聚合)` : `${base} (${subs[0].id})`,
    value: subs.map(s => s.id).join(',')
  }))
})
async function load() {
  try { rows.value = (await api.get('/vulns', { params: q })) || [] } catch (e) { rows.value = [] }
}
async function setStatus(row, status) {
  await api.patch('/vulns/' + row.id, { status })
  ElMessage.success('已更新'); load()
}
const pktDlg = ref(false), pktVuln = ref(null), pkt = ref({})
async function showPkt(row) {
  pktVuln.value = row; pkt.value = {}; pktDlg.value = true
  try {
    const d = await api.get('/vulns/' + row.id)
    pktVuln.value = d.vuln || row
    pkt.value = d.pkt || {}
  } catch (e) { ElMessage.error('详情获取失败') }
}
const sevText = s => ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' }[s] || s || '未知')
const sevStyle = s => {
  const m = { critical: '#7f1d1d,#fca5a5', high: '#7c2d12,#fdba74', medium: '#78350f,#fde047', low: '#1e3a5f,#7dd3fc', info: '#374151,#9ca3af' }
  const pair = (m[s] || m.info).split(',')
  return 'background:' + pair[0] + ';border-color:' + pair[1] + ';color:' + pair[1]
}
const stType = s => ({ open: 'danger', fixed: 'success', ignored: 'info' }[s] || 'info')
const stText = s => ({ open: '未修复', fixed: '已修复', ignored: '已忽略' }[s] || s)
const exporting = ref(false)
const selected = ref([])
async function doExport(format = 'xlsx') {
  exporting.value = true
  try {
    const body = { type: 'vulns', format, task_id: '', task_ids: q.task_ids || '' }
    const cfg = { timeout: 300000 }
    if (selected.value.length) body.ids = selected.value.map(x => x.id)
    const r = await api.post('/exports', body, cfg)
    ElMessage.success(selected.value.length ? `已导出勾选的 ${selected.value.length} 条` : '已生成 ' + r.rows + ' 行, 开始下载')
    window.open('/api/exports/' + r.id + '/download?token=' + localStorage.getItem('token'), '_blank')
  } catch (e) { ElMessage.error('导出失败') } finally { exporting.value = false }
}
const taskName = id => { const t = tasks.value.find(x => x.id === id); return t ? (t.name || t.id) : (id || '-') }
onMounted(() => { load(); api.get('/tasks').then(r => tasks.value = r || []).catch(() => {}) })
</script>
<style scoped>
a.uri-link { color: #67e8f9; text-decoration: none; }
a.uri-link:hover { text-decoration: underline; }
.pkt-pre { background:#010409; border:1px solid #21262d; border-radius:4px; padding:10px; overflow-x:auto; font:12px/1.5 Consolas,monospace; color:#a5d6ff; white-space:pre-wrap; word-break:break-all; max-height:340px; overflow-y:auto; }
</style>
