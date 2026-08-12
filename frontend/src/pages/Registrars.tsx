import { useEffect, useState } from 'react'
import { Table, Tag, Button, Space, Typography, Modal, Form, Input, Select, Switch, message, Popconfirm, Alert, Tabs } from 'antd'
import { ReloadOutlined, PlusOutlined, DeleteOutlined, EditOutlined, ApiOutlined, GlobalOutlined } from '@ant-design/icons'
import { getRegistrars, createRegistrar, updateRegistrar, deleteRegistrar, toggleRegistrar, testRegistrarConnection, getRegistrarDomains, deleteRegistrarDomain, getAvailableRegistrarDomains, importRegistrarDomains, retryImportTasks } from '../api/client'
import type { DomainRegistrar } from '../types'
import type { RegistrarDomain, AvailableDomain, ImportResult } from '../api/client'

const { Title, Text } = Typography

function Registrars() {
  const [registrars, setRegistrars] = useState<DomainRegistrar[]>([])
  const [loading, setLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRegistrar, setEditingRegistrar] = useState<DomainRegistrar | null>(null)
  const [form] = Form.useForm()

  // 域名管理
  const [domainModalOpen, setDomainModalOpen] = useState(false)
  const [currentRegistrar, setCurrentRegistrar] = useState<DomainRegistrar | null>(null)
  const [selectedDomains, setSelectedDomains] = useState<string[]>([])
  const [importing, setImporting] = useState(false)
  const [importResults, setImportResults] = useState<ImportResult[] | null>(null)

  // 已添加的注册商域名（来自数据库表）
  const [addedDomains, setAddedDomains] = useState<RegistrarDomain[]>([])
  const [addedLoading, setAddedLoading] = useState(false)

  // 从注册商拉取的待选域名
  const [domains, setDomains] = useState<AvailableDomain[]>([])
  const [domainsLoading, setDomainsLoading] = useState(false)

  const fetchRegistrars = async () => {
    setLoading(true)
    try {
      const res = await getRegistrars()
      setRegistrars(res.data.result || [])
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRegistrars()
  }, [])

  const handleCreate = () => {
    setEditingRegistrar(null)
    form.resetFields()
    setModalOpen(true)
  }

  const handleEdit = (registrar: DomainRegistrar) => {
    setEditingRegistrar(registrar)
    form.setFieldsValue({
      name: registrar.name,
      type: registrar.type,
      api_key: registrar.api_key,
    })
    setModalOpen(true)
  }

  const handleDelete = async (id: number) => {
    try {
      await deleteRegistrar(id)
      message.success('删除成功')
      fetchRegistrars()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '删除失败'
      message.error(errorMessage)
    }
  }

  const handleToggle = async (id: number) => {
    try {
      await toggleRegistrar(id)
      message.success('状态已切换')
      fetchRegistrars()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '操作失败'
      message.error(errorMessage)
    }
  }

  const handleTestConnection = async (id: number) => {
    try {
      await testRegistrarConnection(id)
      message.success('连接测试成功')
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '连接测试失败'
      message.error(errorMessage)
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()

      if (editingRegistrar) {
        await updateRegistrar(editingRegistrar.id, {
          name: values.name,
          api_key: values.api_key,
          api_secret: values.api_secret || undefined,
        })
        message.success('更新成功')
      } else {
        await createRegistrar({
          name: values.name,
          type: values.type,
          api_key: values.api_key,
          api_secret: values.api_secret,
        })
        message.success('创建成功')
      }
      setModalOpen(false)
      fetchRegistrars()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    }
  }

  // 域名管理
  const handleManageDomains = async (registrar: DomainRegistrar) => {
    setCurrentRegistrar(registrar)
    setDomainModalOpen(true)
    setImportResults(null)
    setSelectedDomains([])
    fetchAddedDomains(registrar.id)
  }

  const handleRetryTasks = async () => {
    if (!currentRegistrar) return
    try {
      const res = await retryImportTasks(currentRegistrar.id)
      message.success(res.data.result.message)
      fetchAddedDomains(currentRegistrar.id)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '重试失败'
      message.error(errorMessage)
    }
  }

  const handleDeleteDomain = async (domain: RegistrarDomain) => {
    if (!currentRegistrar) return
    try {
      await deleteRegistrarDomain(currentRegistrar.id, domain.id)
      message.success('删除成功')
      fetchAddedDomains(currentRegistrar.id)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '删除失败'
      message.error(errorMessage)
    }
  }

  // 打开域名管理 Modal 时轮询已添加域名状态
  useEffect(() => {
    if (!domainModalOpen || !currentRegistrar) return
    const timer = setInterval(() => {
      fetchAddedDomains(currentRegistrar.id)
    }, 5000)
    return () => clearInterval(timer)
  }, [domainModalOpen, currentRegistrar])

  const fetchAddedDomains = async (id: number) => {
    setAddedLoading(true)
    try {
      const res = await getRegistrarDomains(id)
      setAddedDomains(res.data.result || [])
    } catch (err: unknown) {
      // 静默失败，避免轮询时弹错
    } finally {
      setAddedLoading(false)
    }
  }

  const fetchDomains = async (id: number) => {
    setDomainsLoading(true)
    try {
      const res = await getAvailableRegistrarDomains(id)
      setDomains(res.data.result || [])
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '拉取域名失败'
      message.error(errorMessage)
    } finally {
      setDomainsLoading(false)
    }
  }

  const handleImport = async () => {
    if (!currentRegistrar || selectedDomains.length === 0) return
    setImporting(true)
    setImportResults(null)
    try {
      const res = await importRegistrarDomains(currentRegistrar.id, selectedDomains)
      setImportResults(res.data.result.results)
      const { success, skipped, failed } = res.data.result
      message.success(`已加入队列：${success} 个，跳过 ${skipped} 个，失败 ${failed} 个`)
      setSelectedDomains([])
      // 刷新已添加域名列表
      fetchAddedDomains(currentRegistrar.id)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '导入失败'
      message.error(errorMessage)
    } finally {
      setImporting(false)
    }
  }

  const getTypeTag = (type: string) => {
    switch (type) {
      case 'porkbun':
        return <Tag color="green">Porkbun</Tag>
      case 'spaceship':
        return <Tag color="blue">Spaceship</Tag>
      default:
        return <Tag>{type}</Tag>
    }
  }

  const columns = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string) => <Text strong>{text}</Text>,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: (type: string) => getTypeTag(type),
    },
    {
      title: 'API Key',
      dataIndex: 'api_key',
      key: 'api_key',
      render: (text: string) => <Text code>{text}</Text>,
    },
    {
      title: '状态',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (active: boolean, record: DomainRegistrar) => (
        <Switch
          checked={active}
          checkedChildren="启用"
          unCheckedChildren="禁用"
          onChange={() => handleToggle(record.id)}
        />
      ),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: DomainRegistrar) => (
        <Space>
          <Button
            type="link"
            size="small"
            icon={<GlobalOutlined />}
            onClick={() => handleManageDomains(record)}
          >
            域名管理
          </Button>
          <Button
            type="link"
            size="small"
            icon={<ApiOutlined />}
            onClick={() => handleTestConnection(record.id)}
          >
            测试连接
          </Button>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Popconfirm title="确定删除此注册商？" onConfirm={() => handleDelete(record.id)}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  // 已添加域名列表列
  const domainColumns = [
    {
      title: '域名',
      dataIndex: 'domain',
      key: 'domain',
      render: (text: string) => <strong>{text}</strong>,
    },
    {
      title: '状态',
      key: 'status',
      render: (_: unknown, record: RegistrarDomain) => {
        if (record.exists) return <Tag color="green">已接入 CF</Tag>
        switch (record.status) {
          case 'pending':
            return <Tag color="blue">等待接入</Tag>
          case 'processing':
            return <Tag color="processing">接入中</Tag>
          case 'success':
            return <Tag color="green">接入成功</Tag>
          case 'partial':
            return <Tag color="orange">部分成功</Tag>
          case 'skipped':
            return <Tag color="default">已跳过</Tag>
          default:
            return <Tag color="red">接入失败</Tag>
        }
      },
    },
    {
      title: '重试',
      dataIndex: 'retry_count',
      key: 'retry_count',
      render: (count: number) => `${count}/3`,
    },
    {
      title: '说明',
      dataIndex: 'error_msg',
      key: 'error_msg',
      render: (text: string) => text ? <Text type="secondary">{text}</Text> : '-',
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: RegistrarDomain) => (
        <Popconfirm title="确定删除此域名记录？" onConfirm={() => handleDeleteDomain(record)}>
          <Button type="link" size="small" danger icon={<DeleteOutlined />}>
            删除
          </Button>
        </Popconfirm>
      ),
    },
  ]

  // 注册商可选域名列
  const availableColumns = [
    {
      title: '域名',
      dataIndex: 'domain',
      key: 'domain',
      render: (text: string) => <strong>{text}</strong>,
    },
    {
      title: '状态',
      key: 'status',
      render: (_: unknown, record: AvailableDomain) => {
        if (record.exists) return <Tag color="green">已接入 CF</Tag>
        if (record.added) return <Tag color="blue">已添加</Tag>
        return <Tag color="orange">未添加</Tag>
      },
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>注册商管理</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchRegistrars} loading={loading}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>添加注册商</Button>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={registrars}
        rowKey="id"
        loading={loading}
        pagination={false}
      />

      <Modal
        title={editingRegistrar ? '编辑注册商' : '添加注册商'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        okText="保存"
        cancelText="取消"
        width={500}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="name"
            label="名称"
            rules={[{ required: true, message: '请输入名称' }]}
          >
            <Input placeholder="便于识别的名称" />
          </Form.Item>
          <Form.Item
            name="type"
            label="类型"
            rules={[{ required: true, message: '请选择类型' }]}
          >
            <Select placeholder="选择注册商类型" disabled={!!editingRegistrar}>
              <Select.Option value="porkbun">Porkbun</Select.Option>
              <Select.Option value="spaceship">Spaceship</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item
            name="api_key"
            label="API Key"
            rules={[{ required: true, message: '请输入 API Key' }]}
          >
            <Input placeholder="API Key" />
          </Form.Item>
          <Form.Item
            name="api_secret"
            label={editingRegistrar ? 'API Secret (留空则不修改)' : 'API Secret'}
            rules={editingRegistrar ? [] : [{ required: true, message: '请输入 API Secret' }]}
          >
            <Input.Password placeholder="API Secret" />
          </Form.Item>
        </Form>
      </Modal>

      {/* 域名管理 Modal */}
      <Modal
        title={`域名管理 - ${currentRegistrar?.name || ''}`}
        open={domainModalOpen}
        onCancel={() => setDomainModalOpen(false)}
        footer={null}
        width={800}
      >
        <Tabs
          items={[
            {
              key: 'domains',
              label: '已添加域名',
              children: (
                <>
                  <Space style={{ marginBottom: 16 }}>
                    <Button
                      icon={<ReloadOutlined />}
                      onClick={() => currentRegistrar && fetchAddedDomains(currentRegistrar.id)}
                      loading={addedLoading}
                    >
                      刷新
                    </Button>
                    <Button
                      danger
                      onClick={handleRetryTasks}
                      disabled={!addedDomains.some(d => ['failed', 'skipped', 'partial'].includes(d.status))}
                    >
                      重试失败域名
                    </Button>
                  </Space>
                  <Table
                    columns={domainColumns}
                    dataSource={addedDomains}
                    rowKey="id"
                    loading={addedLoading}
                    pagination={{ pageSize: 10 }}
                  />
                </>
              ),
            },
            {
              key: 'import',
              label: '添加域名',
              children: (
                <>
                  <Alert
                    message="从注册商拉取域名并勾选加入。只有手动勾选的域名才会被接入 CF"
                    type="info"
                    showIcon
                    style={{ marginBottom: 16 }}
                  />
                  <Space style={{ marginBottom: 16 }}>
                    <Button
                      icon={<ReloadOutlined />}
                      onClick={() => currentRegistrar && fetchDomains(currentRegistrar.id)}
                      loading={domainsLoading}
                    >
                      拉取域名
                    </Button>
                    <Button
                      type="primary"
                      icon={<GlobalOutlined />}
                      onClick={handleImport}
                      loading={importing}
                      disabled={selectedDomains.length === 0}
                    >
                      加入队列（{selectedDomains.length}）
                    </Button>
                  </Space>

                  <Table
                    columns={availableColumns}
                    dataSource={domains}
                    rowKey="domain"
                    loading={domainsLoading}
                    pagination={{ pageSize: 10 }}
                    rowSelection={{
                      selectedRowKeys: selectedDomains,
                      onChange: (keys: React.Key[]) => setSelectedDomains(keys.map(String)),
                      getCheckboxProps: (record: AvailableDomain) => ({
                        // 已接入或已添加过的域名不可勾选
                        disabled: record.exists || record.added,
                      }),
                    }}
                  />

                  {importResults && (
                    <div style={{ marginTop: 16 }}>
                      <Title level={5}>导入结果</Title>
                      <Table
                        columns={[
                          { title: '域名', dataIndex: 'domain', key: 'domain' },
                          {
                            title: '结果',
                            dataIndex: 'status',
                            key: 'status',
                            render: (status: string) => {
                              const map: Record<string, React.ReactNode> = {
                                queued: <Tag color="blue">已排队</Tag>,
                                skipped: <Tag color="default">跳过</Tag>,
                                failed: <Tag color="red">失败</Tag>,
                              }
                              return map[status] || <Tag>{status}</Tag>
                            },
                          },
                          {
                            title: '说明',
                            dataIndex: 'message',
                            key: 'message',
                            render: (text: string) => <Text type="secondary">{text}</Text>,
                          },
                        ]}
                        dataSource={importResults}
                        rowKey="domain"
                        pagination={false}
                        size="small"
                      />
                    </div>
                  )}
                </>
              ),
            },
          ]}
        />
      </Modal>
    </div>
  )
}

export default Registrars
