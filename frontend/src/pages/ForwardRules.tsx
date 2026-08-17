import { useEffect, useState } from 'react'
import { Table, Tag, Button, Space, Typography, Modal, Form, Input, InputNumber, Switch, Select, message, Popconfirm, Alert, Tabs, Spin, Statistic } from 'antd'
import { ReloadOutlined, PlusOutlined, DeleteOutlined, EditOutlined, CopyOutlined, DownloadOutlined } from '@ant-design/icons'
import { getForwardRules, createForwardRule, updateForwardRule, deleteForwardRule, toggleForwardRule, generateOriginCertificate, getLocalZones, getRuleAnalytics } from '../api/client'
import type { ForwardRule, OriginCertificate, LocalZone } from '../types'
import type { RuleAnalyticsData } from '../api/client'

const { Title, Text, Paragraph } = Typography
const { TextArea } = Input

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  const val = bytes / Math.pow(1024, i)
  return `${val.toFixed(i === 0 ? 0 : 2)} ${units[i]}`
}

function ForwardRules() {
  const [rules, setRules] = useState<ForwardRule[]>([])
  const [loading, setLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<ForwardRule | null>(null)
  const [form] = Form.useForm()
  // 创建/编辑请求进行中，用于禁用提交按钮防止重复提交
  const [submitting, setSubmitting] = useState(false)

  // 证书相关状态
  const [certModalOpen, setCertModalOpen] = useState(false)
  const [certLoading, setCertLoading] = useState(false)
  const [certificate, setCertificate] = useState<OriginCertificate | null>(null)
  const [selectedRule, setSelectedRule] = useState<ForwardRule | null>(null)
  // 删除中的规则 ID，用于防重复提交
  const [deletingId, setDeletingId] = useState<number | null>(null)
  // 可选域名下拉列表
  const [localZones, setLocalZones] = useState<LocalZone[]>([])

  // 流量统计（按规则 ID 索引）
  const [analyticsMap, setAnalyticsMap] = useState<Record<number, RuleAnalyticsData | null>>({})
  const [analyticsLoading, setAnalyticsLoading] = useState<Record<number, boolean>>({})

  const fetchData = async () => {
    setLoading(true)
    try {
      const rulesRes = await getForwardRules()
      const rules = rulesRes.data.result || []
      setRules(rules)

      // 并行拉取所有规则的 analytics
      const loadingMap: Record<number, boolean> = {}
      rules.forEach((r: ForwardRule) => { loadingMap[r.id] = true })
      setAnalyticsLoading(loadingMap)

      const results = await Promise.allSettled(
        rules.map((r: ForwardRule) => getRuleAnalytics(r.id, '24h'))
      )
      const newMap: Record<number, RuleAnalyticsData | null> = {}
      const newLoading: Record<number, boolean> = {}
      rules.forEach((r: ForwardRule, i: number) => {
        newLoading[r.id] = false
        if (results[i].status === 'fulfilled') {
          newMap[r.id] = results[i].value.data.data
        } else {
          newMap[r.id] = null
        }
      })
      setAnalyticsMap(newMap)
      setAnalyticsLoading(newLoading)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const fetchZones = async () => {
    try {
      const res = await getLocalZones()
      setLocalZones(res.data.result || [])
    } catch {
      // 下拉加载失败不阻塞表单，用户仍可「自动选择」
    }
  }

  useEffect(() => {
    fetchData()
    fetchZones()
  }, [])

  const handleCreate = () => {
    setEditingRule(null)
    form.resetFields()
    form.setFieldsValue({ enabled: true, zone_id: undefined })
    setModalOpen(true)
  }

  const handleEdit = (rule: ForwardRule) => {
    setEditingRule(rule)
    form.setFieldsValue({
      origin_port: rule.origin_port,
      origin_host: rule.origin_host,
      enabled: rule.enabled,
      zone_id: rule.zone_id, // 预填当前 zone
    })
    setModalOpen(true)
  }

  const handleDelete = async (id: number) => {
    if (deletingId !== null) return // 防止重复点击
    setDeletingId(id)
    try {
      await deleteForwardRule(id)
      message.success('删除成功')
      fetchData()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '删除失败'
      message.error(errorMessage)
    } finally {
      setDeletingId(null)
    }
  }

  const handleToggle = async (id: number) => {
    try {
      await toggleForwardRule(id)
      message.success('状态已切换')
      fetchData()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '操作失败'
      message.error(errorMessage)
    }
  }

  const handleSubmit = async () => {
    if (submitting) return // 请求进行中，防止重复提交
    try {
      const values = await form.validateFields()
      const zoneId = values.zone_id || undefined // 空 → 自动选择
      setSubmitting(true)

      if (editingRule) {
        await updateForwardRule(editingRule.id, {
          origin_port: values.origin_port,
          origin_host: values.origin_host || '',
          enabled: editingRule.enabled,
          zone_id: zoneId,
        })
        message.success('更新成功')
      } else {
        await createForwardRule({
          origin_port: values.origin_port,
          origin_host: values.origin_host || '',
          enabled: true,
          zone_id: zoneId,
        })
        message.success('创建成功')
      }
      setModalOpen(false)
      fetchData()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    } finally {
      setSubmitting(false)
    }
  }

  // 下载证书（按域名生成通配符证书）
  const handleDownloadCert = async (zoneId: string, zoneName: string) => {
    setSelectedRule({ zone_id: zoneId, zone_name: zoneName, hostname: '' } as ForwardRule)
    setCertModalOpen(true)
    setCertLoading(true)
    setCertificate(null)

    try {
      const hostnames = [`*.${zoneName}`]
      const res = await generateOriginCertificate({
        zone_id: zoneId,
        hostnames: hostnames,
      })
      setCertificate(res.data.result)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '生成证书失败'
      message.error(errorMessage)
    } finally {
      setCertLoading(false)
    }
  }

  // 复制到剪贴板
  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text).then(() => {
      message.success(`${label} 已复制到剪贴板`)
    }).catch(() => {
      message.error('复制失败')
    })
  }

  // 按域名分组统计
  const zoneStats: Record<string, number> = rules.reduce((acc, rule) => {
    // 按端口去重：同端口多目标共享一条 CF Origin Rule，只计为 1
    const key = `${rule.zone_name}:${rule.origin_port}`
    if (!acc[key]) {
      acc[key] = 1
    }
    return acc
  }, {} as Record<string, number>)
  // 按域名汇总端口数
  const zonePortCounts: Record<string, number> = {}
  Object.entries(zoneStats).forEach(([key]) => {
    const zoneName = key.split(':')[0]
    zonePortCounts[zoneName] = (zonePortCounts[zoneName] || 0) + 1
  })

  const columns = [
    {
      title: '域名',
      dataIndex: 'zone_name',
      key: 'zone_name',
      render: (text: string) => <Text strong>{text}</Text>,
    },
    {
      title: '主机名',
      dataIndex: 'hostname',
      key: 'hostname',
    },
    {
      title: '转发端口',
      dataIndex: 'origin_port',
      key: 'origin_port',
      render: (port: number) => <Tag color="blue">{port}</Tag>,
    },
    {
      title: '目标主机',
      dataIndex: 'origin_host',
      key: 'origin_host',
      render: (text: string) => text || <Text type="secondary">-</Text>,
    },
    {
      title: '创建者',
      dataIndex: 'username',
      key: 'username',
      render: (text: string) => text || <Text type="secondary">-</Text>,
    },
    {
      title: '状态',
      dataIndex: 'enabled',
      key: 'enabled',
      render: (enabled: boolean, record: ForwardRule) => (
        <Switch
          checked={enabled}
          checkedChildren="启用"
          unCheckedChildren="禁用"
          onChange={() => handleToggle(record.id)}
        />
      ),
    },
    {
      title: '请求数（24h）',
      key: 'requests',
      width: 140,
      render: (_: unknown, record: ForwardRule) => {
        const loading = analyticsLoading[record.id]
        if (loading) return <Spin size="small" />
        const data = analyticsMap[record.id]
        if (!data) return <Text type="secondary">-</Text>
        return <Statistic value={data.metrics.total_requests} valueStyle={{ fontSize: 14 }} suffix="req" />
      },
    },
    {
      title: '带宽（24h）',
      key: 'bandwidth',
      width: 140,
      render: (_: unknown, record: ForwardRule) => {
        const loading = analyticsLoading[record.id]
        if (loading) return <Spin size="small" />
        const data = analyticsMap[record.id]
        if (!data) return <Text type="secondary">-</Text>
        return <Statistic value={data.metrics.total_bytes} valueStyle={{ fontSize: 14 }} formatter={v => formatBytes(Number(v))} />
      },
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: ForwardRule) => (
        <Space>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Popconfirm title="确定删除此规则？" onConfirm={() => handleDelete(record.id)}
            okButtonProps={{ loading: deletingId === record.id, danger: true }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />} disabled={deletingId !== null}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>全局端口转发</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchData} loading={loading}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>添加规则</Button>
        </Space>
      </div>

      <Alert
        message={
          <span>
            每个域名最多支持 <strong>10</strong> 条转发规则。
            当前已有 <strong>{Object.keys(zonePortCounts).length}</strong> 个域名，共 <strong>{rules.length}</strong> 条规则。
            创建规则时会自动将 SSL/TLS 设置为 Full 模式。
          </span>
        }
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />

      {/* 域名使用统计 */}
      {Object.keys(zonePortCounts).length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <Text type="secondary">各域名端口使用情况：</Text>
          <Space style={{ marginTop: 8 }} wrap>
            {Object.entries(zonePortCounts).map(([name, count]) => {
              // 获取该域名对应的 zone_id
              const zoneRule = rules.find(r => r.zone_name === name)
              return (
                <Space key={name} size={0}>
                  <Tag color={count >= 10 ? 'red' : count >= 5 ? 'orange' : 'green'}>
                    {name}: {count}/10
                  </Tag>
                  <Button
                    type="link"
                    size="small"
                    icon={<DownloadOutlined />}
                    onClick={() => zoneRule && handleDownloadCert(zoneRule.zone_id, name)}
                  >
                    证书
                  </Button>
                </Space>
              )
            })}
          </Space>
        </div>
      )}

      <Table
        columns={columns}
        dataSource={rules}
        rowKey="id"
        loading={loading}
        pagination={false}
      />

      <Modal
        title={editingRule ? '编辑转发规则' : '添加转发规则'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        okText="保存"
        cancelText="取消"
        width={500}
        confirmLoading={submitting}
        okButtonProps={{ disabled: submitting }}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="origin_host"
            label="目标地址"
            tooltip="支持 IPv4（A 记录）、IPv6（AAAA 记录）或域名（CNAME 记录）"
            rules={[{ required: true, message: '请输入目标地址' }]}
          >
            <Input placeholder="例如: 192.168.1.1 或 example.com" />
          </Form.Item>
          <Form.Item
            name="origin_port"
            label="目标端口"
            rules={[{ required: true, message: '请输入端口号' }]}
          >
            <InputNumber
              min={1}
              max={65535}
              style={{ width: '100%' }}
              placeholder="例如: 8080"
            />
          </Form.Item>
          <Form.Item
            name="zone_id"
            label="域名"
            tooltip="不选则自动选择 Cloudflare 侧规则数最少的域名；编辑时清空则保持当前域名"
          >
            <Select
              allowClear
              placeholder="自动选择"
              options={localZones.map(z => ({ value: z.cf_id, label: z.name }))}
            />
          </Form.Item>
        </Form>
      </Modal>

      {/* Origin 证书下载模态框 */}
      <Modal
        title={`Origin 证书 - *.${selectedRule?.zone_name || ''}`}
        open={certModalOpen}
        onCancel={() => setCertModalOpen(false)}
        footer={null}
        width={700}
      >
        {certLoading ? (
          <div style={{ textAlign: 'center', padding: '40px 0' }}>
            <div>正在生成证书...</div>
          </div>
        ) : certificate ? (
          <div>
            <Alert
              message="证书已生成"
              description="请将以下证书和私钥配置到源站服务器。证书有效期为 15 年。"
              type="success"
              showIcon
              style={{ marginBottom: 16 }}
            />

            <Tabs
              items={[
                {
                  key: 'certificate',
                  label: '证书 (PEM)',
                  children: (
                    <div>
                      <Button
                        icon={<CopyOutlined />}
                        onClick={() => handleCopy(certificate.certificate, '证书')}
                        style={{ marginBottom: 8 }}
                      >
                        复制证书
                      </Button>
                      <TextArea
                        value={certificate.certificate}
                        readOnly
                        rows={10}
                        style={{ fontFamily: 'monospace', fontSize: 12 }}
                      />
                    </div>
                  ),
                },
                {
                  key: 'private_key',
                  label: '私钥 (PEM)',
                  children: (
                    <div>
                      <Button
                        icon={<CopyOutlined />}
                        onClick={() => handleCopy(certificate.private_key, '私钥')}
                        style={{ marginBottom: 8 }}
                      >
                        复制私钥
                      </Button>
                      <TextArea
                        value={certificate.private_key}
                        readOnly
                        rows={10}
                        style={{ fontFamily: 'monospace', fontSize: 12 }}
                      />
                    </div>
                  ),
                },
                {
                  key: 'info',
                  label: '证书信息',
                  children: (
                    <div>
                      <Paragraph><strong>证书 ID:</strong> {certificate.id}</Paragraph>
                      <Paragraph><strong>域名:</strong> {certificate.hostnames?.join(', ')}</Paragraph>
                      <Paragraph><strong>颁发者:</strong> {certificate.issuer}</Paragraph>
                      <Paragraph><strong>过期时间:</strong> {certificate.expires_on}</Paragraph>
                      <Paragraph><strong>类型:</strong> {certificate.request_type}</Paragraph>
                      <Alert
                        message="使用说明"
                        description={
                          <ol style={{ margin: 0, paddingLeft: 20 }}>
                            <li>将证书保存为 <code>.pem</code> 或 <code>.crt</code> 文件</li>
                            <li>配置到 Nginx/Apache 等 Web 服务器</li>
                            <li>确保 SSL/TLS 模式为 Full（已自动设置）</li>
                          </ol>
                        }
                        type="info"
                        showIcon
                        style={{ marginTop: 16 }}
                      />
                    </div>
                  ),
                },
              ]}
            />
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '40px 0', color: '#999' }}>
            生成证书失败，请重试
          </div>
        )}
      </Modal>
    </div>
  )
}

export default ForwardRules
