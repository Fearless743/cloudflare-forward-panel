import { useEffect, useState } from 'react'
import { Table, Tag, Button, Space, Typography, Modal, Form, Input, Select, Switch, DatePicker, message, Popconfirm } from 'antd'
import { ReloadOutlined, PlusOutlined, DeleteOutlined, EditOutlined } from '@ant-design/icons'
import { getUsers, createUser, updateUser, deleteUser, toggleUser } from '../api/client'
import type { User } from '../types'
import dayjs from 'dayjs'

const { Title } = Typography

function Users() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(false)
  const [modalOpen, setModalOpen] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [form] = Form.useForm()
  const [deletingId, setDeletingId] = useState<number | null>(null)

  const fetchUsers = async () => {
    setLoading(true)
    try {
      const res = await getUsers()
      setUsers(res.data.result || [])
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchUsers()
  }, [])

  const handleCreate = () => {
    setEditingUser(null)
    form.resetFields()
    form.setFieldsValue({ role: 'user' })
    setModalOpen(true)
  }

  const handleEdit = (user: User) => {
    setEditingUser(user)
    form.setFieldsValue({
      username: user.username,
      role: user.role,
      subscription: user.subscription ? dayjs(user.subscription) : null,
    })
    setModalOpen(true)
  }

  const handleDelete = async (id: number) => {
    if (deletingId !== null) return
    setDeletingId(id)
    try {
      await deleteUser(id)
      message.success('删除成功')
      fetchUsers()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '删除失败'
      message.error(errorMessage)
    } finally {
      setDeletingId(null)
    }
  }

  const handleToggle = async (id: number) => {
    try {
      await toggleUser(id)
      message.success('状态已切换')
      fetchUsers()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '操作失败'
      message.error(errorMessage)
    }
  }

  const handleSubmit = async () => {
    try {
      const values = await form.validateFields()

      // 处理 DatePicker 的值
      const subscription = values.subscription
        ? values.subscription.format('YYYY-MM-DD')
        : undefined

      if (editingUser) {
        await updateUser(editingUser.id, {
          password: values.password || undefined,
          role: values.role,
          subscription,
        })
        message.success('更新成功')
      } else {
        await createUser({
          username: values.username,
          password: values.password,
          role: values.role,
          subscription,
        })
        message.success('创建成功')
      }
      setModalOpen(false)
      fetchUsers()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    }
  }

  const formatSubscription = (subscription?: string | null) => {
    if (!subscription) return '永久'
    const date = new Date(subscription)
    const now = new Date()
    if (date < now) {
      return <Tag color="red">已过期</Tag>
    }
    return date.toLocaleDateString('zh-CN')
  }

  const columns = [
    {
      title: '用户名',
      dataIndex: 'username',
      key: 'username',
    },
    {
      title: '角色',
      dataIndex: 'role',
      key: 'role',
      render: (role: string) => (
        <Tag color={role === 'admin' ? 'red' : 'blue'}>
          {role === 'admin' ? '管理员' : '普通用户'}
        </Tag>
      ),
    },
    {
      title: '状态',
      dataIndex: 'is_active',
      key: 'is_active',
      render: (active: boolean, record: User) => (
        <Switch
          checked={active}
          checkedChildren="启用"
          unCheckedChildren="禁用"
          onChange={() => handleToggle(record.id)}
        />
      ),
    },
    {
      title: '订阅',
      dataIndex: 'subscription',
      key: 'subscription',
      render: (subscription: string | null) => formatSubscription(subscription),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: User) => (
        <Space>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Popconfirm title="确定删除此用户？" onConfirm={() => handleDelete(record.id)}
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
        <Title level={4} style={{ margin: 0 }}>用户管理</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchUsers} loading={loading}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>添加用户</Button>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={users}
        rowKey="id"
        loading={loading}
        pagination={false}
      />

      <Modal
        title={editingUser ? '编辑用户' : '添加用户'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        okText="保存"
        cancelText="取消"
        width={400}
      >
        <Form form={form} layout="vertical">
          <Form.Item
            name="username"
            label="用户名"
            rules={[{ required: !editingUser, message: '请输入用户名' }]}
          >
            <Input disabled={!!editingUser} placeholder="至少3位" />
          </Form.Item>
          <Form.Item
            name="password"
            label="密码"
            rules={editingUser ? [] : [{ required: true, message: '请输入密码' }]}
          >
            <Input.Password placeholder={editingUser ? '留空则不修改' : '至少6位'} />
          </Form.Item>
          <Form.Item
            name="role"
            label="角色"
          >
            <Select>
              <Select.Option value="admin">管理员</Select.Option>
              <Select.Option value="user">普通用户</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item
            name="subscription"
            label="订阅时间"
            tooltip="留空表示永久有效"
          >
            <DatePicker
              style={{ width: '100%' }}
              placeholder="选择订阅截止日期"
              disabledDate={(current) => current && current < dayjs().startOf('day')}
            />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default Users
