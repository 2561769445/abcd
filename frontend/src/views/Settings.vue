<template>
  <div class="page">
    <h2 class="page-title">系统设置</h2>
    <div class="card" style="max-width:720px;padding:24px">
      <h3 style="color:#00d4aa;font-size:15px;margin-bottom:6px">🔔 通知推送(企业微信 / 钉钉机器人)</h3>
      <p style="color:var(--muted);font-size:12px;margin-bottom:16px">
        高危/严重漏洞实时推送(10分钟防抖合并) + 任务完成通知。填群机器人的 Webhook 地址,保存即生效无需重启;留空=关闭推送。
      </p>
      <el-form label-width="90px">
        <el-form-item label="Webhook">
          <el-input v-model="wh" placeholder="https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx 或 https://oapi.dingtalk.com/robot/send?access_token=xxx" clearable />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="saving" @click="save">保存</el-button>
          <el-button :loading="testing" @click="test">发送测试消息</el-button>
        </el-form-item>
      </el-form>
      <h3 style="color:#00d4aa;font-size:15px;margin:28px 0 6px">🗺️ 资产测绘引擎 Key(节点共用)</h3>
      <p style="color:var(--muted);font-size:12px;margin-bottom:16px">
        保存后全节点即配即用(执行任务时自动拉取)。扫描目标含域名时, 自动调用 Hunter+Fofa 收集资产补全子域名 — 正好补上砍掉子域爆破后的缺口。
      </p>
      <el-form label-width="110px">
        <el-form-item label="Hunter(鹰图)">
          <div style="display:flex;gap:8px;width:100%">
            <el-input v-model="form.hunter_key" placeholder="鹰图平台 https://hunter.qianxin.com 的 API Key" clearable />
            <el-button size="small" :loading="tk==='hunter'" @click="tk && tk==='hunter' ? null : testKey('hunter')">验证</el-button>
          </div>
        </el-form-item>
        <el-form-item label="FOFA">
          <div style="display:flex;gap:8px;width:100%">
            <el-input v-model="form.fofa_key" placeholder="格式: 邮箱:key (如 xxx@qq.com:abcdef)" clearable />
            <el-button size="small" :loading="tk==='fofa'" @click="testKey('fofa')">验证</el-button>
          </div>
        </el-form-item>
        <el-form-item label="Quake(360)">
          <div style="display:flex;gap:8px;width:100%">
            <el-input v-model="form.quake_key" placeholder="Quake API Key" clearable />
            <el-button size="small" :loading="tk==='quake'" @click="testKey('quake')">验证</el-button>
          </div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="saving" @click="save">保存全部</el-button>
        </el-form-item>
        <div v-if="keyResult" class="mono" style="font-size:12px;color:#67e8f9;margin:-6px 0 8px">{{ keyResult }}</div>
      </el-form>
      <h3 style="color:#00d4aa;font-size:15px;margin:28px 0 6px">🔑 修改登录密码</h3>
      <p style="color:var(--muted);font-size:12px;margin-bottom:16px">改完立即生效且持久化(重启不丢), 无需改配置文件。</p>
      <el-form label-width="90px" style="max-width:420px">
        <el-form-item label="旧密码"><el-input v-model="pw.old" type="password" show-password /></el-form-item>
        <el-form-item label="新密码"><el-input v-model="pw.new1" type="password" show-password placeholder="至少6位" /></el-form-item>
        <el-form-item label="确认新密码"><el-input v-model="pw.new2" type="password" show-password /></el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="changing" @click="changePw">修改密码</el-button>
        </el-form-item>
      </el-form>
            <el-alert type="info" :closable="false" style="margin-top:8px"
        title="机器人配置指引"
        description="企业微信: 群设置→添加群机器人→复制Webhook地址(markdown类型)。钉钉: 群设置→智能群助手→自定义机器人→安全设置选'自定义关键词'填 ABCD 或加IP白名单。" />
    </div>
  </div>
</template>
<script setup>
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api'
const wh = ref(''), saving = ref(false), testing = ref(false)
const form = reactive({ hunter_key: '', fofa_key: '', quake_key: '' })
onMounted(async () => {
  try {
    const r = await api.get('/settings')
    wh.value = r.webhook_url || ''
    form.hunter_key = r.hunter_key || ''
    form.fofa_key = r.fofa_key || ''
    form.quake_key = r.quake_key || ''
  } catch {}
})
async function save() {
  saving.value = true
  try {
    await api.put('/settings', { webhook_url: wh.value.trim(), ...form })
    ElMessage.success('已保存, 全节点即配即用')
  } catch { ElMessage.error('保存失败') } finally { saving.value = false }
}
const tk = ref(''), keyResult = ref('')
const pw = reactive({ old: '', new1: '', new2: '' }), changing = ref(false)
async function changePw() {
  if (!pw.old || pw.new1.length < 6) return ElMessage.warning('旧密码必填, 新密码至少6位')
  if (pw.new1 !== pw.new2) return ElMessage.warning('两次新密码不一致')
  changing.value = true
  try {
    const r = await api.post('/settings/password', { old_pass: pw.old, new_pass: pw.new1 })
    ElMessage.success(r.note || '修改成功, 请用新密码重新登录')
    pw.old = pw.new1 = pw.new2 = ''
  } catch (e) { ElMessage.error(e?.response?.data?.error || '修改失败') } finally { changing.value = false }
}
async function testKey(engine) {
  tk.value = engine
  try {
    await save()
    const r = await api.post('/settings/map-test', { engine }, { timeout: 20000 })
    keyResult.value = (engine.toUpperCase()) + ': ' + (r.ok ? '✅ ' : '❌ ') + r.msg
    ElMessage[r.ok ? 'success' : 'warning'](engine.toUpperCase() + ' ' + r.msg)
  } catch (e) {
    keyResult.value = engine + ': ' + (e?.response?.data?.error || '请求失败')
    ElMessage.error(keyResult.value)
  } finally { tk.value = '' }
}
async function test() {
  testing.value = true
  try {
    await save()
    const r = await api.post('/settings/webhook-test', {}, { timeout: 15000 })
    ElMessage.success(r.note || '已发送')
  } catch (e) { ElMessage.error(e?.response?.data?.error || '测试失败') } finally { testing.value = false }
}
</script>
