<template>
  <div class="page">
    <h2 class="page-title">总览大盘</h2>
    <div style="font-size:12px;color:#00d4aa;opacity:.75;margin:2px 0 0 2px">by 月落安全</div>
    <div class="stat-grid">
      <div class="stat-card"><el-icon class="stat-icon" color="#22d3ee"><Cpu /></el-icon>
        <div class="stat-label">在线节点</div><div class="stat-value">{{ s.nodes_online }}<span class="mini"> / {{ s.nodes_total }}</span></div></div>
      <div class="stat-card"><el-icon class="stat-icon" color="#818cf8"><List /></el-icon>
        <div class="stat-label">执行中任务</div><div class="stat-value">{{ s.tasks_running }}</div></div>
      <div class="stat-card"><el-icon class="stat-icon" color="#34d399"><FolderOpened /></el-icon>
        <div class="stat-label">累计资产</div><div class="stat-value">{{ s.assets_total }}</div></div>
      <div class="stat-card"><el-icon class="stat-icon" color="#fbbf24"><WarningFilled /></el-icon>
        <div class="stat-label">累计漏洞</div><div class="stat-value">{{ s.vulns_total }}</div></div>
      <div class="stat-card"><el-icon class="stat-icon" color="#f87171"><CircleCloseFilled /></el-icon>
        <div class="stat-label">未修高危</div><div class="stat-value">{{ s.vulns_high_open }}</div></div>
    </div>
    <div class="card">
      <div style="font-weight:700;margin-bottom:12px">最近任务</div>
      <el-table :data="tasks" size="small">
        <el-table-column prop="id" label="任务ID" width="180" class-name="mono" />
        <el-table-column prop="name" label="名称" min-width="120" />
        <el-table-column prop="target_count" label="目标数" width="80" />
        <el-table-column label="状态" width="100">
          <template #default="{row}"><el-tag :type="statusType(row.status)" size="small">{{ statusText(row.status) }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="found_assets" label="资产" width="70" />
        <el-table-column prop="found_vulns" label="漏洞" width="70" />
        <el-table-column label="创建时间" width="160">
          <template #default="{row}">{{ fmtTime(row.created_at) }}</template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>
<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api, fmtTime } from '../api'
const s = ref({}); const tasks = ref([])
let timer
async function load() {
  try { s.value = await api.get('/stats'); tasks.value = (await api.get('/tasks')).slice(0, 8) || [] } catch {}
}
const statusType = st => ({done:'success', scanning:'primary', queued:'warning', pending:'info', failed:'danger', stopped:'info', stopping:'warning', scheduled:'info'}[st] || 'info')
const statusText = st => ({done:'已完成', scanning:'扫描中', queued:'已派发', pending:'待执行', failed:'失败', stopped:'已终止', stopping:'停止中', scheduled:'定时'}[st] || st)
onMounted(() => { load(); timer = setInterval(load, 5000) })
onUnmounted(() => clearInterval(timer))
</script>
