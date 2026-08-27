<template>
  <el-drawer v-model="show" :title="`终端 — ${node?.name || ''}`" size="62%" :close-on-click-modal="false" @opened="focusInput">
    <div class="term" ref="termBox">
      <div class="term-head">
        <span class="dot red"></span><span class="dot yellow"></span><span class="dot green"></span>
        <span class="term-title">root@{{ node?.name || 'node' }} — abcd web shell</span>
        <el-button size="small" text style="margin-left:auto;color:#94a3b8" @click="clearScr">清屏</el-button>
      </div>
      <div class="term-body" ref="termBody" @click="focusInput">
        <div v-for="(l, i) in lines" :key="i" class="term-line" :class="l.cls" v-text="l.text"></div>
        <div class="term-input-row">
          <span class="prompt">root@{{ node?.name || 'node' }}:{{ cwd || '~'}}#</span>
          <input ref="cmdInput" v-model="cmd" class="term-input" :disabled="busy"
            placeholder="输入命令回车执行 (↑↓历史)" @keyup.enter="run" @keyup.up="histUp" @keyup.down="histDown" />
        </div>
        <div v-if="busy" class="term-line busy">... 执行中</div>
      </div>
    </div>
  </el-drawer>
</template>
<script setup>
import { ref, nextTick } from 'vue'
import { api } from '../api'
const props = defineProps({ node: Object })
const show = defineModel('show')
const lines = ref([{ text: '● abcd 节点交互终端 (每命令独立bash执行, cd/目录会话内保持)', cls: 'sys' }])
const cmd = ref(''), busy = ref(false), cwd = ref('')
const history = ref([]), hidx = ref(-1)
const cmdInput = ref(null), termBody = ref(null)
const emit = defineEmits(['cwd'])
async function run() {
  const c = cmd.value.trim()
  if (!c || busy.value) return
  history.value.push(c); hidx.value = history.value.length
  lines.value.push({ text: `root@${props.node?.name}:${cwd.value || '~'}# ${c}`, cls: 'cmd' })
  cmd.value = ''; busy.value = true
  scrollBottom()
  try {
    const r = await api.post(`/nodes/${props.node.id}/exec`, { cmd: c, timeout: 120, session: props.node.id }, { timeout: 150000 })
    let out = r.output || '(无输出)'
    // 节点会话维持: 尾部带 __CWD__ 标记
    const m = out.match(/\n?__CWD__:(.+)$/)
    if (m) { cwd.value = m[1].trim(); out = out.replace(/\n?__CWD__:.+$/, '') }
    out.split('\n').forEach(t => lines.value.push({ text: t, cls: 'out' }))
    emit('cwd', cwd.value)
  } catch (e) {
    lines.value.push({ text: '[错误] ' + (e?.response?.data?.error || '执行失败/节点离线'), cls: 'err' })
  }
  busy.value = false
  scrollBottom()
  nextTick(focusInput)
}
function histUp() { if (hidx.value > 0) { hidx.value--; cmd.value = history.value[hidx.value] || '' } }
function histDown() { if (hidx.value < history.value.length - 1) { hidx.value++; cmd.value = history.value[hidx.value] || '' } else { hidx.value = history.value.length; cmd.value = '' } }
function scrollBottom() { nextTick(() => { if (termBody.value) termBody.value.scrollTop = termBody.value.scrollHeight }) }
function clearScr() { lines.value = [] }
function focusInput() { cmdInput.value?.focus() }
</script>
<style scoped>
.term{display:flex;flex-direction:column;height:100%;background:#060b14;border:1px solid #1e2d45;border-radius:8px;overflow:hidden}
.term-head{display:flex;align-items:center;gap:6px;padding:8px 12px;background:#0d1420;border-bottom:1px solid #1e2d45}
.dot{width:11px;height:11px;border-radius:50%}
.dot.red{background:#ef4444}.dot.yellow{background:#f59e0b}.dot.green{background:#10b981}
.term-title{margin-left:8px;font:11px Consolas,monospace;color:#94a3b8}
.term-body{flex:1;overflow-y:auto;padding:10px 14px;font:13px/1.55 Consolas,'Cascadia Code',monospace}
.term-line{white-space:pre-wrap;word-break:break-all;color:#a0b4cc}
.term-line.cmd{color:#00d4aa}
.term-line.sys{color:#64748b;font-size:12px}
.term-line.err{color:#ef4444}
.term-line.busy{color:#f59e0b}
.term-input-row{display:flex;align-items:center;gap:8px;margin-top:2px}
.prompt{color:#00d4aa;white-space:nowrap;font-weight:600}
.term-input{flex:1;background:transparent;border:none;outline:none;color:#e2e8f0;font:13px Consolas,monospace;caret-color:#00d4aa}
</style>
