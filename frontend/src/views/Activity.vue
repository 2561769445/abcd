<template>
  <div class="page">
    <h2 class="page-title">实时日志</h2>
    <div class="toolbar">
      <el-switch v-model="auto" active-text="自动刷新(3s)" />
      <el-button size="small" @click="load">手动刷新</el-button>
      <el-tag v-if="live" size="small" type="success" effect="dark">LIVE</el-tag>
    </div>
    <div class="card feed" ref="feedBox">
      <div v-if="!rows.length" style="padding:30px;text-align:center;color:var(--muted)">暂无动态, 节点扫描产生结果后会实时出现在这里</div>
      <div v-for="r in rows" :key="r.kind + r.id" class="feed-line">
        <span class="feed-time">{{ fmtTime(r.time).slice(5) }}</span>
        <span class="feed-tag" :style="tagStyle(r)">{{ r.kind === 'vuln' ? '漏洞' : '资产' }}</span>
        <span class="feed-text">{{ r.text }}</span>
        <span style="color:var(--muted);flex-shrink:0">{{ r.node_id }}</span>
      </div>
    </div>
  </div>
</template>
<script setup>
import { ref, onMounted, onUnmounted } from 'vue'
import { api, fmtTime } from '../api'
const rows = ref([]), auto = ref(true), live = ref(false)
let timer
async function load() {
  try {
    const r = await api.get('/activity')
    const fresh = r && r.length !== rows.value.length
    rows.value = r || []
    if (fresh) live.value = true, setTimeout(() => live.value = false, 2000)
  } catch (e) { rows.value = [] }
}
const tagStyle = r => r.kind === 'vuln'
  ? 'color:#f87171;background:rgba(239,68,68,.12);padding:1px 6px;border-radius:4px'
  : 'color:#00d4aa;background:rgba(0,212,170,.1);padding:1px 6px;border-radius:4px'
onMounted(() => { load(); timer = setInterval(() => auto.value && load(), 3000) })
onUnmounted(() => clearInterval(timer))
</script>
