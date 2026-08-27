import axios from 'axios'

export const api = axios.create({ baseURL: '/api', timeout: 30000 })

api.interceptors.request.use(cfg => {
  const t = localStorage.getItem('token')
  if (t) cfg.headers.Authorization = 'Bearer ' + t
  return cfg
})
api.interceptors.response.use(
  r => r.data,
  err => {
    if (err.response && err.response.status === 401) {
      localStorage.removeItem('token')
      location.reload()
    }
    return Promise.reject(err)
  }
)

export const fmtTime = t => (t ? new Date(t).toLocaleString('zh-CN', { hour12: false }) : '-')
