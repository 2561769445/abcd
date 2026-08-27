<template>
  <div class="page">
    <h2 class="page-title">资产台账</h2>
    <div class="toolbar">
      <el-select v-model="q.task_ids" placeholder="按任务筛选" clearable filterable style="width:260px" @change="load">
        <el-option v-for="t in taskOptions" :key="t.value" :value="t.value" :label="t.label" />
      </el-select>
      <el-input v-model="q.search" placeholder="搜索 IP / URI / 标题" clearable style="width:200px" prefix-icon="Search" @keyup.enter="load" />
      <el-select v-model="q.type" placeholder="资产类型" clearable style="width:140px" @change="load">
        <el-option v-for="t in types" :key="t" :value="t" :label="typeText(t)" />
      </el-select>
      <el-input v-model="q.finger" placeholder="指纹包含" clearable style="width:150px" @keyup.enter="load" />
      <el-button type="primary" @click="goLoad">查询</el-button>
      <el-button type="success" plain :loading="exporting" @click="doExport">📥 导出Excel</el-button>
      <el-button plain :loading="exporting" @click="doExport('csv')">📥 导出CSV</el-button>
      <span class="count-tip">共 {{ total }} 条{{ q.task_ids ? '(已按任务过滤,导出同任务)' : '' }}</span>
    </div>
    <div class="card">
      <el-table :data="rows" size="small" :height="tableH" :fit="true" style="width:100%">
        <el-table-column prop="id" label="#" width="70" />
        <el-table-column label="类型" width="110">
          <template #default="{row}"><el-tag size="small" effect="plain">{{ typeText(row.asset_type) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="ip" label="IP" width="130" class-name="mono" />
        <el-table-column prop="port" label="端口" width="70" class-name="mono" />
        <el-table-column label="URI" min-width="160" show-overflow-tooltip>
          <template #default="{row}">
            <a v-if="row.uri" :href="row.uri" target="_blank" rel="noopener" class="uri-link mono">{{ row.uri }}</a>
          </template>
        </el-table-column>
        <el-table-column prop="title" label="标题" min-width="150" show-overflow-tooltip />
        <el-table-column prop="status_code" label="状态码" width="75" />
        <el-table-column label="指纹" min-width="140">
          <template #default="{row}">
            <el-tag v-for="f in fingerList(row.finger)" :key="f" size="small" class="finger-tag">{{ f }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="所属任务" width="150" show-overflow-tooltip>
          <template #default="{row}">{{ taskName(row.task_id) }}</template>
        </el-table-column>
        <el-table-column label="最近发现" width="145"><template #default="{row}">{{ fmtTime(row.last_seen) }}</template></el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{row}">
            <el-button size="small" text type="primary" @click="mark(row)">标记/备注</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div style="display:flex;justify-content:flex-end;padding:10px 4px">
        <el-pagination v-model:current-page="page" :page-size="ps" :total="total" layout="total, prev, pager, next, jumper" @current-change="load" />
      </div>
    </div>
  </div>
</template>
<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, fmtTime } from '../api'
const rows = ref([]), total = ref(0), page = ref(1), ps = ref(50)
const tasks = ref([])
const tableH = window.innerHeight - 220
const q = reactive({ search: '', type: '', finger: '', task_ids: '' })
// 多节点子任务聚合: "象山 [vps96]"等4条 → 一个"象山 (4节点并行)"选项, 值=逗号拼接子任务ID
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
const types = ['IPAlive', 'PortScan', 'Nmap', 'Web', 'Finger', 'DNS-SubFinder', 'RealIP', 'Hunter', 'Fofa']
const typeText = t => ({ IPAlive: '存活主机', PortScan: '开放端口', Nmap: '服务识别', Web: 'Web服务', Finger: '指纹', 'DNS-SubFinder': '子域名', RealIP: '真实IP' }[t] || t)
const fingerList = f => (f || '').split(',').filter(x => x)
const exporting = ref(false)
async function doExport(format = 'xlsx') {
  exporting.value = true
  try {
    const r = await api.post('/exports', { type: 'assets', format, task_id: '', task_ids: q.task_ids || '' }, { timeout: 300000 })
    ElMessage.success('已生成 ' + r.rows + ' 行, 开始下载')
    window.open('/api/exports/' + r.id + '/download?token=' + localStorage.getItem('token'), '_blank')
  } catch (e) { ElMessage.error('导出失败') } finally { exporting.value = false }
}
const taskName = id => { const t = tasks.value.find(x => x.id === id); return t ? (t.name || t.id) : (id || '-') }
function goLoad() { page.value = 1; load() }
async function load() {
  try {
    const r = await api.get('/assets', { params: { ...q, page: page.value, page_size: ps.value } })
    rows.value = r.rows || []; total.value = r.total || 0
  } catch (e) { rows.value = [] }
}
async function mark(row) {
  try {
    const { value } = await ElMessageBox.prompt('标记或备注该资产', '资产标记', { inputValue: row.remark || row.tag })
    await api.patch('/assets/' + row.id, { remark: value, tag: value })
    ElMessage.success('已保存'); load()
  } catch (e) { /* 取消 */ }
}
onMounted(() => { load(); api.get('/tasks').then(r => tasks.value = r || []).catch(() => {}) })
</script>
<style scoped>
a.uri-link { color: #67e8f9; text-decoration: none; }
a.uri-link:hover { text-decoration: underline; }
.finger-tag { margin: 1px 3px 1px 0; background: rgba(34,211,238,.1); border-color: rgba(34,211,238,.3); color: #67e8f9; }
</style>
