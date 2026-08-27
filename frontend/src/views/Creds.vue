<template>
  <div class="page">
    <h2 class="page-title">凭据台账</h2>
    <div class="toolbar">
      <el-select v-model="q.task_ids" placeholder="按任务筛选" clearable filterable style="width:260px" @change="load">
        <el-option v-for="t in taskOptions" :key="t.value" :value="t.value" :label="t.label" />
      </el-select>
      <el-input v-model="q.search" placeholder="搜索 目标 / 凭据 / 服务" clearable style="width:220px" @keyup.enter="load" />
      <el-button type="primary" @click="load">查询</el-button>
      <span class="count-tip">共 {{ total }} 条弱口令/未授权凭据</span>
    </div>
    <div class="card">
      <el-table :data="rows" size="small" :height="tableH" :fit="true" style="width:100%">
        <el-table-column prop="id" label="#" width="70" />
        <el-table-column label="服务" width="150">
          <template #default="{row}"><el-tag size="small" effect="plain" class="mono">{{ row.service }}</el-tag></template>
        </el-table-column>
        <el-table-column label="目标" width="180">
          <template #default="{row}"><span class="mono">{{ row.target }}</span></template>
        </el-table-column>
        <el-table-column label="凭据/详情" min-width="260" show-overflow-tooltip>
          <template #default="{row}"><span class="mono" style="color:#34d399">{{ row.detail }}</span></template>
        </el-table-column>
        <el-table-column label="所属任务" width="170" show-overflow-tooltip>
          <template #default="{row}">{{ taskName(row.task_id) }}</template>
        </el-table-column>
        <el-table-column label="发现节点" width="140" show-overflow-tooltip>
          <template #default="{row}"><span class="mono" style="font-size:11px">{{ row.node_id || '-' }}</span></template>
        </el-table-column>
        <el-table-column label="最近验证" width="145"><template #default="{row}">{{ fmtTime(row.last_seen) }}</template></el-table-column>
      </el-table>
      <div style="display:flex;justify-content:flex-end;padding:10px 4px">
        <el-pagination v-model:current-page="page" :page-size="ps" :total="total" layout="total, prev, pager, next, jumper" @current-change="load" />
      </div>
    </div>
  </div>
</template>
<script setup>
import { ref, reactive, computed, onMounted } from 'vue'
import { api, fmtTime } from '../api'
const rows = ref([]), total = ref(0), page = ref(1), ps = ref(50)
const tasks = ref([])
const tableH = window.innerHeight - 250
const q = reactive({ search: '', task_ids: '' })
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
  try {
    const r = await api.get('/credentials', { params: { page: page.value, page_size: ps.value, search: q.search || '', task_id: q.task_ids || '' } })
    rows.value = r.rows || []; total.value = r.total || 0
  } catch { rows.value = [] }
}
const taskName = id => { const t = tasks.value.find(x => x.id === id); return t ? (t.name || t.id) : (id || '-') }
onMounted(() => { load(); api.get('/tasks').then(r => tasks.value = r || []).catch(() => {}) })
</script>
