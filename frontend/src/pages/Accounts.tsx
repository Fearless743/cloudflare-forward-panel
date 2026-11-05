import { useEffect, useState } from 'react'
import { Table, Tag, Button, Space, Typography, Modal, Form, Input, Switch, Select, message, Popconfirm, Alert } from 'antd'
import { ReloadOutlined, PlusOutlined, DeleteOutlined, EditOutlined, CheckCircleOutlined } from '@ant-design/icons'
import { getAccounts, createAccount, updateAccount, deleteAccount, toggleAccount, unblockAccount } from '../api/client'
import type { CFAccount } from '../types'

const { Title, Text } = Typography

function Accounts() {
  const [accounts, setAccounts] = useState<CFAccount[]>([])
  const [loading, setLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingAccount, setEditingAccount] = useState<CFAccount | null>(null)
  const [form] = Form.useForm()
  const authType = Form.useWatch('auth_type', form)
  const isToken = authType !== 'global_key'
  const [deletingId, setDeletingId] = useState<number | null>(null)

  // 根据凭证前缀自动切换认证方式，避免 cfk_ 的 Global API Key 被当成 Token 发送。
  const handleApiKeyChange = (event: { target: { value: string } }) => {
    const value = event.target.value
    if (value.startsWith('cfk_')) {
      form.setFieldsValue({ auth_type: 'global_key' })
    } else if (value.startsWith('cfat_') || value.startsWith('cfut_')) {
      form.setFieldsValue({ auth_type: 'token' })
    }
  }

  const fetchAccounts = async () => {
    setLoading(true)
    try {
      const res = await getAccounts()
      setAccounts(res.data.result || [])
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchAccounts()
  }, [])

  const handleCreate = () => {
    setEditingAccount(null)
    form.resetFields()
    form.setFieldsValue({ auth_type: 'token' })
    setModalOpen(true)
  }

  const handleEdit = (account: CFAccount) => {
    setEditingAccount(account)
    form.setFieldsValue({
      name: account.name,
      email: account.email,
      api_key: account.api_key,
      auth_type: account.auth_type || 'global_key',
      account_id: account.account_id,
    })
    setModalOpen(true)
  }

  const handleDelete = async (id: number) => {
    if (deletingId !== null) return
    setDeletingId(id)
    try {
      await deleteAccount(id)
      message.success('删除成功')
      fetchAccounts()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '删除失败'
      message.error(errorMessage)
    } finally {
      setDeletingId(null)
    }
  }

  const handleToggle = async (id: number) => {
    try {
      await toggleAccount(id)
      message.success('状态已切换')
      fetchAccounts()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '操作失败'
      message.error(errorMessage)
    }
  }

  const handleUnblock = async (id: number) => {
    try {
      await unblockAccount(id)
      message.success('已解除封禁')
      fetchAccounts()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '操作失败'
      message.error(errorMessage)
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()

      if (editingAccount) {
        await updateAccount(editingAccount.id, {
          email: values.email,
          api_key: values.api_key,
          auth_type: values.auth_type,
          // 传空字符串表示清空 CF 账号 ID（undefined 会被 axios 丢弃，无法清空）
          account_id: values.account_id ?? '',
        })
        message.success('更新成功')
      } else {
        await createAccount({
          email: values.email || '',
          api_key: values.api_key,
          auth_type: values.auth_type,
          account_id: values.account_id || '',
        })
        message.success('创建成功')
      }
      setModalOpen(false)
      fetchAccounts()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    }
  }

  const getStatusTag = (account: CFAccount) => {
    if (account.is_blocked) {
      return <Tag color="red">已封禁</Tag>
    }
    if (!account.is_active) {
      return <Tag color="default">已禁用</Tag>
    }
    return <Tag color="green">正常</Tag>
  }

  const columns = [
    {
      title: '账号名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string) => <Text strong>{text}</Text>,
    },
    {
      title: '认证方式',
      dataIndex: 'auth_type',
      key: 'auth_type',
      render: (text: string) => (
        <Tag color={text === 'token' ? 'blue' : 'default'}>
          {text === 'token' ? 'Account API Token' : 'Global API Key'}
        </Tag>
      ),
    },
    {
      title: '邮箱',
      dataIndex: 'email',
      key: 'email',
      render: (text: string) => <Text>{text || '-'}</Text>,
    },
    {
      title: '凭证',
      dataIndex: 'api_key',
      key: 'api_key',
      render: (text: string) => <Text code>{text}</Text>,
    },
    {
      title: '状态',
      key: 'status',
      render: (_: unknown, record: CFAccount) => getStatusTag(record),
    },
    {
      title: '启用',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (active: boolean, record: CFAccount) => (
        <Switch
          checked={active}
          disabled={record.is_blocked}
          checkedChildren="启用"
          unCheckedChildren="禁用"
          onChange={() => handleToggle(record.id)}
        />
      ),
    },
    {
      title: '最后错误',
      dataIndex: 'error_msg',
      key: 'error_msg',
      render: (text: string) => text ? <Text type="danger">{text}</Text> : '-',
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: CFAccount) => (
        <Space>
          {record.is_blocked && (
            <Button type="link" size="small" icon={<CheckCircleOutlined />} onClick={() => handleUnblock(record.id)}>
              解除封禁
            </Button>
          )}
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Popconfirm title="确定删除此账号？" onConfirm={() => handleDelete(record.id)}
            okButtonProps={{ loading: deletingId === record.id, danger: true }}>
            <Button type="link" size="small" danger icon={<DeleteOutlined />} disabled={deletingId !== null}>
              删除
            </Button>
          </Popconfirm>
        </Space>
      ),
    },
  ]

  const activeCount = accounts.filter(a => a.is_active && !a.is_blocked).length
  const blockedCount = accounts.filter(a => a.is_blocked).length

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>CF 账号管理</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchAccounts} loading={loading}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>添加账号</Button>
        </Space>
      </div>

      <Alert
        message={
          <span>
            当前有 <strong>{activeCount}</strong> 个可用账号，
            {blockedCount > 0 && <span style={{ color: 'red' }}>{blockedCount} 个已封禁</span>}
            {blockedCount === 0 && <span>0 个已封禁</span>}。
            当账号被封禁时会自动切换到下一个可用账号。
          </span>
        }
        type={blockedCount > 0 ? 'warning' : 'info'}
        showIcon
        style={{ marginBottom: 16 }}
      />

      <Table
        columns={columns}
        dataSource={accounts}
        rowKey="id"
        loading={loading}
        pagination={false}
      />

      <Modal
        title={editingAccount ? '编辑账号' : '添加账号'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        okText="保存"
        cancelText="取消"
        width={500}
      >
        <Form form={form} layout="vertical" initialValues={{ auth_type: 'token' }}>
          <Form.Item
            name="auth_type"
            label="认证方式"
            rules={[{ required: true, message: '请选择认证方式' }]}
          >
            <Select
              options={[
                { value: 'token', label: 'Account API Token（推荐）' },
                { value: 'global_key', label: 'Global API Key（旧版）' },
              ]}
            />
          </Form.Item>

          {isToken ? (
            <>
              <Form.Item
                name="api_key"
                label="Account API Token"
                rules={[{ required: true, message: '请输入 Account API Token' }]}
                extra="在 Cloudflare 控制台「Manage account → Account API tokens」创建，使用 cfat_ 前缀的 Token。"
              >
                <Input.Password placeholder="cfat_xxxxxxxxxxxxxxxx" onChange={handleApiKeyChange} />
              </Form.Item>
              <Form.Item
                name="account_id"
                label="CF 账号 ID"
                rules={[{ required: true, message: '请输入 CF 账号 ID' }]}
                tooltip="Account API Token 绑定到具体账号，需要填写对应的 Account ID"
              >
                <Input placeholder="例如 abc123def456" />
              </Form.Item>
            </>
          ) : (
            <>
              <Form.Item
                name="email"
                label="登录邮箱"
                rules={[{ required: true, message: '请输入 CF 登录邮箱' }]}
              >
                <Input placeholder="your@email.com" />
              </Form.Item>
              <Form.Item
                name="api_key"
                label="Global API Key"
                rules={[{ required: true, message: '请输入 Global API Key' }]}
              >
                <Input.Password placeholder="cfk_xxxxxxxxxxxxxxxx" onChange={handleApiKeyChange} />
              </Form.Item>
              <Form.Item
                name="account_id"
                label="CF 账号 ID"
                tooltip="创建 Zone 时需要指定账号，可在 Cloudflare 控制台找到。留空则使用默认账号"
              >
                <Input placeholder="例如 abc123def456（可选）" />
              </Form.Item>
            </>
          )}

          <Alert
            type="info"
            showIcon
            message="Account API Token 需要至少具备 Zone 读取/编辑、DNS 编辑、Zone Settings 编辑、Account Rulesets 编辑权限。"
          />
        </Form>
      </Modal>
    </div>
  )
}

export default Accounts
