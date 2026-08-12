import { useEffect, useState } from 'react'
import { Table, Tag, Button, Space, Typography, Modal, Form, Input, InputNumber, Switch, message, Popconfirm, Alert, Tabs } from 'antd'
import { ReloadOutlined, PlusOutlined, DeleteOutlined, EditOutlined, CopyOutlined, DownloadOutlined } from '@ant-design/icons'
import { getForwardRules, createForwardRule, updateForwardRule, deleteForwardRule, toggleForwardRule, generateOriginCertificate } from '../api/client'
import type { ForwardRule, OriginCertificate } from '../types'

const { Title, Text, Paragraph } = Typography
const { TextArea } = Input

function ForwardRules() {
  const [rules, setRules] = useState<ForwardRule[]>([])
  const [loading, setLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<ForwardRule | null>(null)
  const [form] = Form.useForm()

  // 证书相关状态
  const [certModalOpen, setCertModalOpen] = useState(false)
  const [certLoading, setCertLoading] = useState(false)
  const [certificate, setCertificate] = useState<OriginCertificate | null>(null)
  const [selectedRule, setSelectedRule] = useState<ForwardRule | null>(null)

  const fetchData = async () => {
    setLoading(true)
    try {
      const rulesRes = await getForwardRules()
      setRules(rulesRes.data.result || [])
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleCreate = () => {
    setEditingRule(null)
    form.resetFields()
    form.setFieldsValue({ enabled: true })
    setModalOpen(true)
  }

  const handleEdit = (rule: ForwardRule) => {
    setEditingRule(rule)
    form.setFieldsValue({
      origin_port: rule.origin_port,
      origin_host: rule.origin_host,
      enabled: rule.enabled,
    })
    setModalOpen(true)
  }

  const handleDelete = async (id: number) => {
    try {
      await deleteForwardRule(id)
      message.success('删除成功')
      fetchData()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '删除失败'
      message.error(errorMessage)
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
    try {
      const values = await form.validateFields()

      if (editingRule) {
        await updateForwardRule(editingRule.id, {
          origin_port: values.origin_port,
          origin_host: values.origin_host || '',
          enabled: values.enabled,
        })
        message.success('更新成功')
      } else {
        await createForwardRule({
          origin_port: values.origin_port,
          origin_host: values.origin_host || '',
          enabled: values.enabled,
        })
        message.success('创建成功')
      }
      setModalOpen(false)
      fetchData()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
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
    acc[rule.zone_name] = (acc[rule.zone_name] || 0) + 1
    return acc
  }, {} as Record<string, number>)

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
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: ForwardRule) => (
        <Space>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Popconfirm title="确定删除此规则？" onConfirm={() => handleDelete(record.id)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>
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
            当前已有 <strong>{Object.keys(zoneStats).length}</strong> 个域名，共 <strong>{rules.length}</strong> 条规则。
            创建规则时会自动将 SSL/TLS 设置为 Full 模式。
          </span>
        }
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
      />

      {/* 域名使用统计 */}
      {Object.keys(zoneStats).length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <Text type="secondary">各域名规则使用情况：</Text>
          <Space style={{ marginTop: 8 }} wrap>
            {Object.entries(zoneStats).map(([name, count]) => {
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
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="origin_host"
            label="目标地址"
            tooltip="支持 IPv4（A 记录）、IPv6（AAAA 记录）或域名（CNAME 记录）"
            rules={[{ required: true, message: '请输入目标地址' }]}
          >
            <Input placeholder="例如: 192.168.1.1 或 example.com" disabled={!!editingRule} />
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
              disabled={!!editingRule}
            />
          </Form.Item>
          <Form.Item name="enabled" label="启用状态" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="禁用" />
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
