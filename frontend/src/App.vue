<template>
  <div v-if="!token" class="login-wrap">
    <div class="login-card">
      <div class="login-logo">ABCD</div>
      <div class="login-sub">分布式资产扫描平台 · 主控控制台</div>
      <el-form @submit.prevent="login">
        <el-input v-model="user" placeholder="用户名" size="large" prefix-icon="User" class="mb" />
        <el-input v-model="pass" placeholder="密码" size="large" prefix-icon="Lock" type="password" show-password class="mb" @keyup.enter="login" />
        <el-button type="primary" size="large" style="width:100%" :loading="loading" @click="login">登 录</el-button>
      </el-form>
    </div>
  </div>
  <el-container v-else style="height:100%">
    <el-aside width="210px" class="sidebar">
      <div class="logo-block">
        <div class="logo-badge">A</div>
        <div>
          <div class="logo-text">ABCD Scanner</div>
          <div class="logo-sub">红队分布式打点平台</div>
        </div>
      </div>
      <el-menu :default-active="tab" router-less class="side-menu" @select="k => tab = k">
        <el-menu-item index="dash"><el-icon><Odometer /></el-icon>工作台</el-menu-item>
        <el-menu-item index="tasks"><el-icon><List /></el-icon>任务管理</el-menu-item>
        <el-menu-item index="nodes"><el-icon><Cpu /></el-icon>节点集群</el-menu-item>
        <el-menu-item index="assets"><el-icon><FolderOpened /></el-icon>资产台账</el-menu-item>
        <el-menu-item index="vulns"><el-icon><WarningFilled /></el-icon>漏洞管理</el-menu-item>
        <el-menu-item index="creds"><el-icon><Key /></el-icon>凭据台账</el-menu-item>
        <el-menu-item index="exports"><el-icon><Download /></el-icon>数据导出</el-menu-item>
        <el-menu-item index="logs"><el-icon><Monitor /></el-icon>实时日志</el-menu-item>
        <el-menu-item index="settings"><el-icon><Setting /></el-icon>系统设置</el-menu-item>
      </el-menu>
      <div class="sidebar-foot">
        <el-button text size="small" @click="logout"><el-icon><SwitchButton /></el-icon> 退出</el-button>
      </div>
    </el-aside>
    <el-main style="padding:0; overflow:auto">
      <component :is="views[tab]" />
    </el-main>
  </el-container>
</template>

<script setup>
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from './api'
import Dashboard from './views/Dashboard.vue'
import Tasks from './views/Tasks.vue'
import Nodes from './views/Nodes.vue'
import Assets from './views/Assets.vue'
import Vulns from './views/Vulns.vue'
import Creds from './views/Creds.vue'
import Settings from './views/Settings.vue'
import Exports from './views/Exports.vue'
import Activity from './views/Activity.vue'

const views = { dash: Dashboard, tasks: Tasks, nodes: Nodes, assets: Assets, vulns: Vulns, creds: Creds, exports: Exports, logs: Activity, settings: Settings }
const token = ref(localStorage.getItem('token') || '')
const tab = ref('dash')
const user = ref('admin'), pass = ref(''), loading = ref(false)

async function login() {
  if (!user.value || !pass.value) return
  loading.value = true
  try {
    const r = await api.post('/login', { username: user.value, password: pass.value })
    token.value = r.token
    localStorage.setItem('token', r.token)
  } catch (e) {
    ElMessage.error(e.response?.data?.error || '登录失败')
  } finally { loading.value = false }
}
function logout() { localStorage.removeItem('token'); token.value = '' }
</script>

<style scoped>
.login-wrap { height: 100%; display: flex; align-items: center; justify-content: center; }
.login-card {
  width: 380px; padding: 42px 38px; border-radius: 16px;
  background: linear-gradient(160deg, var(--panel), var(--panel-2));
  border: 1px solid var(--line);
  box-shadow: 0 20px 60px rgba(0,0,0,.5);
  text-align: center;
}
.login-logo { font-size: 42px; font-weight: 900; letter-spacing: 6px;
  background: linear-gradient(90deg, var(--cyan), var(--violet));
  -webkit-background-clip: text; background-clip: text; color: transparent; }
.login-sub { color: var(--muted); margin: 6px 0 26px; font-size: 13px; }
.mb { margin-bottom: 16px; }
.sidebar { background: var(--panel); border-right: 1px solid var(--line);
  display: flex; flex-direction: column; }
.logo-block { display: flex; gap: 10px; align-items: center; padding: 18px 16px; border-bottom: 1px solid var(--line); }
.logo-badge { width: 38px; height: 38px; border-radius: 10px; display: flex; align-items: center; justify-content: center;
  font-weight: 900; font-size: 20px; color: #06121f;
  background: linear-gradient(135deg, var(--cyan), var(--violet)); }
.logo-text { font-weight: 800; letter-spacing: 2px; }
.logo-sub { font-size: 11px; color: var(--muted); }
.side-menu { border-right: none; flex: 1; padding-top: 10px; }
.sidebar-foot { padding: 10px 16px; border-top: 1px solid var(--line); }
:deep(.el-menu-item.is-active) { background: linear-gradient(90deg, rgba(34,211,238,.15), transparent); }
</style>
