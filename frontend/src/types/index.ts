export interface Zone {
  id: string
  name: string
  status: string
  name_servers: string[]
  plan: { name: string }
  created_on: string
}

export interface DNSRecord {
  id: string
  zone_id: string
  name: string
  type: string
  content: string
  ttl: number
  proxied: boolean
  comment?: string
}

export interface OriginRuleset {
  id: string
  name: string
  description: string
  kind: string
  phase: string
  version: string
  rules: OriginRule[]
}

export interface OriginRule {
  id: string
  description: string
  expression: string
  action: string
  action_parameters?: {
    origin?: {
      port?: number
      host?: string
    }
    host_header?: string
  }
  enabled: boolean
}

export interface SSLSetting {
  id: string
  value: string
  editable: boolean
}

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
}

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

export interface User {
  id: number
  username: string
  role: string
  is_active: boolean
  subscription?: string | null  // 订阅过期时间，null 表示永久
  created_at: string
  updated_at: string
}

export interface CFResponse<T> {
  success: boolean
  result: T
  errors?: Array<{ code: number; message: string }>
}

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

export interface DomainRegistrar {
  id: number
  name: string
  type: 'porkbun' | 'spaceship'
  api_key: string
  is_active: boolean
  created_at: string
  updated_at: string
}
