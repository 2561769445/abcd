<template>
  <div class="page">
    <h2 class="page-title">数据导出</h2>
    <div class="card" style="margin-bottom:14px;max-width:560px">
      <div style="font-weight:700;margin-bottom:12px">新建导出</div>
      <el-form label-width="80px">
        <el-form-item label="数据类型">
          <el-radio-group v-model="form.type">
            <el-radio-button value="assets">资产清单</el-radio-button>
            <el-radio-button value="vulns">漏洞清单</el-radio-button>
            <el-radio-button value="tasks">任务报表</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="格式">
          <el-radio-group v-model="form.format">
            <el-radio value="xlsx">Excel</el-radio><el-radio value="csv">CSV</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-button type="primary" :loading="saving" @click="create">生成导出文件</el-button>
      </el-form>
    </div>
    <div class="card">
      <div style="font-weight:700;margin-bottom:12px">导出历史</div>
      <el-table :data="rows" size="small">
        <el-table-column prop="id" label="#" width="70" />
        <el-table-column label="类型" width="110">
          <template #default="{row}">{{ typeText(row.export_type) }}</template>
        </el-table-column>
        <el-table-column prop="row_count" label="行数" width="90" />
        <el-table-column prop="file_path" label="文件" min-width="220" show-overflow-tooltip class-name="mono" />
        <el-table-column prop="created_by" label="操作人" width="90" />
        <el-table-column label="时间" width="160"><template #default="{row}">{{ fmtTime(row.created_at) }}</template></el-table-column>
        <el-table-column label="操作" width="110">
          <template #default="{row}">
            <el-button size="small" type="primary" plain @click="dl(row)">下载</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>
<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api, fmtTime } from '../api'
const rows = ref([])
const saving = ref(false)
const form = reactive({ type: 'assets', format: 'xlsx' })
async function load() {
  try { rows.value = (await api.get('/exports')) || [] } catch (e) { rows.value = [] }
}
async function create() {
  saving.value = true
  try {
    const r = await api.post('/exports', form)
    ElMessage.success('已生成 ' + r.rows + ' 行'); load()
  } catch (e) {
    ElMessage.error((e.response && e.response.data && e.response.data.error) || '导出失败')
  } finally { saving.value = false }
}
function dl(row) {
  window.open('/api/exports/' + row.id + '/download?token=' + localStorage.getItem('token'), '_blank')
}
const typeText = t => ({ assets: '资产清单', vulns: '漏洞清单', tasks: '任务报表' }[t] || t)
onMounted(load)
</script>
