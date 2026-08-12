import axios from 'axios'
import type { Zone, DNSRecord, SSLSetting, CFResponse } from '../types'

export interface ForwardRule {
  id: number
  zone_id: string
  zone_name: string
  hostname: string
  origin_port: number
  origin_host: string
  enabled: boolean
  cf_ruleset_id: string
  cf_rule_id: string
  dns_record_id: string
  user_id: number
  username?: string
}

export interface User {
  id: number
  username: string
  role: string
  is_active: boolean
  subscription?: string | null  // 订阅过期时间，null 表示永久
  created_at: string
  updated_at: string
}

const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
})

// 请求拦截器 - 自动添加 token
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// 响应拦截器 - 处理 401 / 403 错误
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.href = '/login'
    } else if (error.response?.status === 403) {
      const msg = error.response?.data?.error || ''
      // 首次登录需修改密码：跳转到改密页
      if (msg.includes('修改密码') || msg.includes('change-password')) {
        window.location.href = '/change-password'
      }
    }
    const message = error.response?.data?.error || error.message || '请求失败'
    return Promise.reject(new Error(message))
  }
)

// Zones
export const getZones = () => api.get<CFResponse<Zone[]>>('/zones')
export const getZone = (id: string) => api.get<CFResponse<Zone>>(`/zones/${id}`)

// DNS Records
export const getDNSRecords = (zoneId: string, type?: string) => {
  const params = type ? { type } : {}
  return api.get<CFResponse<DNSRecord[]>>(`/zones/${zoneId}/dns`, { params })
}
export const createDNSRecord = (zoneId: string, data: Partial<DNSRecord>) =>
  api.post<CFResponse<DNSRecord>>(`/zones/${zoneId}/dns`, data)
export const updateDNSRecord = (zoneId: string, recordId: string, data: Partial<DNSRecord>) =>
  api.put<CFResponse<DNSRecord>>(`/dns/${recordId}?zone_id=${zoneId}`, data)
export const deleteDNSRecord = (zoneId: string, recordId: string) =>
  api.delete(`/dns/${recordId}?zone_id=${zoneId}`)

// SSL/TLS
export const getSSLSettings = (zoneId: string) =>
  api.get<CFResponse<SSLSetting>>(`/zones/${zoneId}/ssl`)
export const updateSSLSettings = (zoneId: string, value: string) =>
  api.patch<CFResponse<SSLSetting>>(`/zones/${zoneId}/ssl`, { value })

// Forward Rules (全局端口转发)
export const getForwardRules = () =>
  api.get<CFResponse<ForwardRule[]>>('/forward-rules')
export const createForwardRule = (data: {
  origin_port: number
  origin_host: string
  enabled: boolean
}) => api.post<CFResponse<ForwardRule>>('/forward-rules', data)
export const updateForwardRule = (ruleId: number, data: {
  origin_port: number
  origin_host: string
  enabled: boolean
}) => api.put<CFResponse<ForwardRule>>(`/forward-rules/${ruleId}`, data)
export const deleteForwardRule = (ruleId: number) =>
  api.delete(`/forward-rules/${ruleId}`)
export const toggleForwardRule = (ruleId: number) =>
  api.post<CFResponse<ForwardRule>>(`/forward-rules/${ruleId}/toggle`)

// Settings
export interface PanelSettings {
  cf_api_token: string
  telegram_bot_token: string
  telegram_chat_id: string
}
export const getSettings = () =>
  api.get<CFResponse<PanelSettings>>('/settings')
export const updateSettings = (data: PanelSettings) =>
  api.put<CFResponse<{ message: string }>>('/settings', data)
export const testConnection = () =>
  api.post<CFResponse<{ status: string; zones_count: number }>>('/settings/test')
export const testTelegram = () =>
  api.post<CFResponse<{ message: string }>>('/settings/test-telegram')

// Accounts
export interface CFAccount {
  id: number
  name: string
  email: string
  api_key: string
  account_id: string
  is_active: boolean
  is_blocked: boolean
  error_msg: string
  last_used: string
  created_at: string
}
export const getAccounts = () =>
  api.get<CFResponse<CFAccount[]>>('/accounts')
export const createAccount = (data: { email: string; api_key: string; account_id?: string }) =>
  api.post<CFResponse<CFAccount>>('/accounts', data)
export const updateAccount = (id: number, data: { email?: string; api_key?: string; account_id?: string }) =>
  api.put<CFResponse<{ message: string }>>(`/accounts/${id}`, data)
export const deleteAccount = (id: number) =>
  api.delete(`/accounts/${id}`)
export const toggleAccount = (id: number) =>
  api.post<CFResponse<CFAccount>>(`/accounts/${id}/toggle`)
export const unblockAccount = (id: number) =>
  api.post<CFResponse<{ message: string }>>(`/accounts/${id}/unblock`)

// Auth
export const login = (username: string, password: string) =>
  api.post<CFResponse<{ token: string; username: string; role: string; must_change_password: boolean }>>('/auth/login', { username, password })
export const changePassword = (oldPassword: string, newPassword: string) =>
  api.post<CFResponse<{ token: string }>>('/auth/change-password', { old_password: oldPassword, new_password: newPassword })
export const getCurrentUser = () =>
  api.get<CFResponse<{ user_id: number; username: string; role: string }>>('/auth/me')

// Users
export const getUsers = () =>
  api.get<CFResponse<User[]>>('/users')
export const createUser = (data: { username: string; password: string; role: string; subscription?: string }) =>
  api.post<CFResponse<User>>('/users', data)
export const updateUser = (id: number, data: { password?: string; role?: string; subscription?: string }) =>
  api.put<CFResponse<User>>(`/users/${id}`, data)
export const deleteUser = (id: number) =>
  api.delete(`/users/${id}`)
export const toggleUser = (id: number) =>
  api.post<CFResponse<User>>(`/users/${id}/toggle`)

// Origin Certificates
export interface OriginCertificate {
  id: string
  certificate: string
  private_key: string
  csr: string
  hostnames: string[]
  issuer: string
  expires_on: string
  request_type: string
  status: string
}

export const generateOriginCertificate = (data: {
  zone_id: string
  hostnames: string[]
}) => api.post<CFResponse<OriginCertificate>>('/origin-certificates', data)

// Domain Registrars
export interface DomainRegistrar {
  id: number
  name: string
  type: 'porkbun' | 'spaceship'
  api_key: string
  is_active: boolean
  created_at: string
  updated_at: string
}

export const getRegistrars = () =>
  api.get<CFResponse<DomainRegistrar[]>>('/registrars')
export const createRegistrar = (data: {
  name: string
  type: string
  api_key: string
  api_secret: string
}) => api.post<CFResponse<DomainRegistrar>>('/registrars', data)
export const updateRegistrar = (id: number, data: {
  name?: string
  api_key?: string
  api_secret?: string
}) => api.put<CFResponse<DomainRegistrar>>(`/registrars/${id}`, data)
export const deleteRegistrar = (id: number) =>
  api.delete(`/registrars/${id}`)
export const toggleRegistrar = (id: number) =>
  api.post<CFResponse<DomainRegistrar>>(`/registrars/${id}/toggle`)
export const testRegistrarConnection = (id: number) =>
  api.post<CFResponse<{ message: string }>>(`/registrars/${id}/test`)

// Registrar Domains（数据库表中手动添加的域名）
export interface RegistrarDomain {
  id: number
  domain: string
  registrar_id: number
  status: 'pending' | 'processing' | 'success' | 'failed' | 'skipped' | 'partial'
  error_msg: string
  exists: boolean
  queued: boolean
  created_at: string
  updated_at: string
}
export const getRegistrarDomains = (id: number) =>
  api.get<CFResponse<RegistrarDomain[]>>(`/registrars/${id}/domains`)
export const deleteRegistrarDomain = (registrarId: number, domainId: number) =>
  api.delete(`/registrars/${registrarId}/domains/${domainId}`)

export interface AvailableDomain {
  domain: string
  added: boolean
  exists: boolean
  registrar_id: number
}
export const getAvailableRegistrarDomains = (id: number) =>
  api.get<CFResponse<AvailableDomain[]>>(`/registrars/${id}/available-domains`)

export interface ImportResult {
  domain: string
  status: 'queued' | 'skipped' | 'failed'
  message: string
}
export interface ImportResponse {
  results: ImportResult[]
  success: number
  skipped: number
  failed: number
}
export const importRegistrarDomains = (id: number, domains: string[]) =>
  api.post<CFResponse<ImportResponse>>(`/registrars/${id}/domains/import`, { domains })

// 重试失败/跳过的导入任务
export const retryImportTasks = (registrarId: number) =>
  api.post<CFResponse<{ message: string }>>(`/registrars/${registrarId}/tasks/retry`)
