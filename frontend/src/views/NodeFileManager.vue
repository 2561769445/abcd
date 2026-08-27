<template>
  <el-drawer v-model="show" :title="`文件管理 — ${node?.name || ''}`" size="58%">
    <div class="fm">
      <div class="fm-bar">
        <el-input v-model="path" class="mono" size="small" style="flex:1" @keyup.enter="ls">
          <template #prepend>路径</template>
        </el-input>
        <el-button size="small" @click="ls">刷新</el-button>
        <el-button size="small" type="primary" @click="up()">上一级</el-button>
        <el-button size="small" type="success" @click="pickUpload">⬆ 上传</el-button>
        <input ref="fileInp" type="file" style="display:none" @change="doUpload" />
      </div>
      <el-table :data="entries" size="small" height="calc(100vh - 210px)" @row-dblclick="enter">
        <el-table-column label="名称" min-width="240">
          <template #default="{row}">
            <span :class="row.dir ? 'dirname mono' : 'mono'">{{ row.dir ? '📁 ' + row.name : row.name }}</span>
          </template>
        </el-table-column>
        <el-table-column label="大小" width="110">
          <template #default="{row}">{{ row.dir ? '-' : fmtSize(row.size) }}</template>
        </el-table-column>
        <el-table-column prop="mod" label="修改时间" width="110" />
        <el-table-column label="操作" width="170">
          <template #default="{row}">
            <el-button v-if="!row.dir" size="small" text type="primary" @click="dl(row)">下载</el-button>
            <el-button size="small" text type="warning" @click="mv(row)">重命名</el-button>
            <el-button size="small" text type="danger" @click="rm(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="fm-tip">双击目录进入 · 上传默认存到当前目录 · 单文件≤50MB</div>
    </div>
  </el-drawer>
</template>
<script setup>
import { ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api'
const props = defineProps({ node: Object })
const show = defineModel('show')
const path = ref('/'), entries = ref([]), fileInp = ref(null)
let upTarget = ''
watch(show, v => { if (v && props.node) ls() })
async function ls() {
  try {
    const r = await api.get(`/nodes/${props.node.id}/ls`, { params: { path: path.value } })
    entries.value = (r.entries || []).sort((a, b) => (b.dir ? 1 : 0) - (a.dir ? 1 : 0) || a.name.localeCompare(b.name))
    if (r.path) path.value = r.path
  } catch (e) { ElMessage.error(e?.response?.data?.error || '读取目录失败') }
}
function enter(row) { if (row.dir) { path.value = join(path.value, row.name); ls() } }
function up() { path.value = path.value.replace(/\/[^/]+\/?$/, '') || '/'; ls() }
function join(p, n) { return (p === '/' ? '' : p) + '/' + n }
async function exec0(cmd) { return api.post(`/nodes/${props.node.id}/exec`, { cmd, timeout: 30 }) }
async function rm(row) {
  await ElMessageBox.confirm(`删除 ${row.name}?`, '警告', { type: 'warning' })
  await exec0('rm -rf ' + q(join(path.value, row.name))); ElMessage.success('已删'); ls()
}
async function mv(row) {
  const { value } = await ElMessageBox.prompt('新名称', '重命名', { inputValue: row.name })
  await exec0(`mv ${q(join(path.value, row.name))} ${q(join(path.value, value))}`); ls()
}
function dl(row) { window.open(`/api/nodes/${props.node.id}/file?path=${encodeURIComponent(join(path.value, row.name))}&token=${localStorage.getItem('token')}`, '_blank') }
function pickUpload() { upTarget = path.value; fileInp.value?.click() }
async function doUpload(ev) {
  const f = ev.target.files[0]; if (!f) return
  const fd = new FormData(); fd.append('file', f); fd.append('path', join(upTarget, f.name))
  ElMessage.info(`上传中: ${f.name} (${fmtSize(f.size)})`)
  try {
    const r = await api.post(`/nodes/${props.node.id}/file`, fd, { timeout: 120000 })
    ElMessage.success(r.output || '上传成功'); ls()
  } catch (e) { ElMessage.error(e?.response?.data?.error || '上传失败') }
  ev.target.value = ''
}
const q = s => "'" + s.replace(/'/g, "'\\''") + "'"
const fmtSize = n => n > 1048576 ? (n / 1048576).toFixed(1) + 'M' : n > 1024 ? (n / 1024).toFixed(1) + 'K' : n + 'B'
</script>
<style scoped>
.fm { display: flex; flex-direction: column; gap: 8px; height: 100%; }
.fm-bar { display: flex; gap: 8px; }
.dirname { color: #67e8f9; cursor: pointer; }
.fm-tip { color: var(--muted, #94a3b8); font-size: 11px; }
</style>
