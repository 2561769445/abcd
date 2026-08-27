<template>
  <div class="page">
    <h2 class="page-title">节点集群</h2>
    <div class="card deploy-card">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
        <div style="font-weight:700">🚀 新节点一键纳管 <span style="color:var(--muted);font-size:12px;font-weight:400">在任意Linux服务器root执行, 30秒自动上线</span></div>
        <el-button size="small" type="primary" @click="copyCmd"><el-icon><CopyDocument /></el-icon>&nbsp;复制命令</el-button>
      </div>
      <div class="cmd-line mono">{{ installCmd || '加载中...' }}</div>
      <div style="color:var(--muted);font-size:12px;margin-top:6px">
        批量: for h in $(cat ips.txt); do ssh root@$h '<span style="color:#67e8f9">把上面命令贴这里</span>' &amp; done; wait — 装完的节点自动参与调度, 无需任何配置
      </div>
    </div>
    <div class="toolbar"><el-button type="primary" plain @click="load"><el-icon><Refresh /></el-icon>&nbsp;刷新</el-button></div>
    <el-row :gutter="14">
      <el-col :span="8" v-for="n in rows" :key="n.id" style="margin-bottom:14px">
        <div class="card node-card" :class="{ off: !n.online }">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <div style="display:flex;gap:10px;align-items:center">
              <div class="node-badge" :class="n.online ? 'on' : 'off'">
                <el-icon><Cpu /></el-icon>
              </div>
              <div>
                <div style="font-weight:700">{{ n.name }} <el-tag size="small" :type="n.online ? 'success' : 'danger'">{{ n.online ? '在线' : '离线' }}</el-tag></div>
                <div class="mono" style="color:var(--muted)">{{ n.ip }} · {{ n.os }}</div>
              </div>
            </div>
            <el-tag effect="plain" size="small">权重 {{ n.weight }}</el-tag>
          </div>
          <div style="margin-top:14px">
            <div class="meter-label"><span>CPU</span><span>{{ n.cpu_percent.toFixed(1) }}%</span></div>
            <el-progress :percentage="+n.cpu_percent.toFixed(1)" :stroke-width="8" :color="barColor(n.cpu_percent)" :show-text="false" />
            <div class="meter-label"><span>内存</span><span>{{ n.mem_percent.toFixed(1) }}%</span></div>
            <el-progress :percentage="+n.mem_percent.toFixed(1)" :stroke-width="8" :color="barColor(n.mem_percent)" :show-text="false" />
          </div>
          <div style="margin-top:12px;font-size:12px;color:var(--muted);display:flex;justify-content:space-between">
            <span>{{ n.running_task ? '执行中: ' + n.running_task : '空闲' }}</span>
            <span>心跳: {{ fmtTime(n.last_heartbeat) }}</span>
          </div>
          <div style="margin-top:10px;display:flex;gap:8px">
            <el-button size="small" plain @click="editWeight(n)">调整权重</el-button>
            <el-button size="small" type="warning" plain @click="openTerm(n)">终端</el-button>
            <el-button size="small" type="success" plain @click="openFm(n)">文件</el-button>
            <el-button size="small" type="danger" @click="del(n)">删除</el-button>
          </div>
        </div>
      </el-col>
    </el-row>
    <el-empty v-if="!rows.length" description="暂无节点, 在扫描机上执行: abcd -node -r <主控Redis地址>" />
  </div>
  <NodeTerminal v-model:show="termShow" :node="termNode" />
  <NodeFileManager v-model:show="fmShow" :node="fmNode" />
</template>
<script setup>
import NodeTerminal from './NodeTerminal.vue'
import NodeFileManager from './NodeFileManager.vue'
import { ref, onMounted, onUnmounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api, fmtTime } from '../api'
const rows = ref([])
const installCmd = ref('')
let timer
async function load() { try { rows.value = (await api.get('/nodes')) || [] } catch {} }
async function loadCmd() { try { const r = await api.get('/install-cmd'); installCmd.value = r.cmd } catch {} }
async function copyCmd() {
  try { await navigator.clipboard.writeText(installCmd.value); ElMessage.success('已复制, 去新服务器粘贴执行') }
  catch (e) {
    const ta = document.createElement('textarea'); ta.value = installCmd.value
    document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove()
    ElMessage.success('已复制')
  }
}
async function editWeight(n) {
  try {
    const { value } = await ElMessageBox.prompt(`设置 ${n.name} 的调度权重 (1-100, 越大分到越多任务)`, '权重', { inputValue: String(n.weight) })
    await api.post(`/nodes/${n.id}/weight`, { weight: +value }); ElMessage.success('已更新'); load()
  } catch {}
}
const termNode = ref(null), termShow = ref(false)
const openTerm = n => { termNode.value = n; termShow.value = true }
const fmNode = ref(null), fmShow = ref(false)
const openFm = n => { fmNode.value = n; fmShow.value = true }

async function del(n) {
  await ElMessageBox.confirm(`删除节点 ${n.name} ? 在线节点会被远程下线并从集群移除`, '删除节点', { type: 'error', confirmButtonText: '删除' })
  await api.delete(`/nodes/${n.id}`); ElMessage.success('已删除'); load()
}
const barColor = v => v > 80 ? '#f87171' : v > 60 ? '#fbbf24' : '#22d3ee'
onMounted(() => { load(); loadCmd(); timer = setInterval(load, 5000) })
onUnmounted(() => clearInterval(timer))
</script>
<style scoped>
.node-card.off { opacity: .65; }
.deploy-card { border-color: rgba(0,212,170,.35); background: linear-gradient(145deg, rgba(0,212,170,.06), var(--panel)); margin-bottom: 14px; }
.cmd-line {
  background: var(--bg-input); border: 1px solid var(--line); border-radius: 6px;
  padding: 10px 14px; color: #67e8f9; word-break: break-all; font-size: 12px;
}
.node-badge { width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 20px; }
.node-badge.on { background: rgba(52,211,153,.15); color: #34d399; box-shadow: 0 0 12px rgba(52,211,153,.25); }
.node-badge.off { background: rgba(248,113,113,.12); color: #f87171; }
.meter-label { display: flex; justify-content: space-between; font-size: 12px; color: var(--muted); margin: 8px 0 2px; }
</style>
