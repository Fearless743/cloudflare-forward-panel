import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Table, Tag, Button, Space, Typography, message, Modal, Select, Alert, Form, Input } from 'antd'
import { ReloadOutlined, SettingOutlined, TeamOutlined, PlusOutlined } from '@ant-design/icons'
import { getZones, getUsers, updateZoneUsers, getAccounts, createZone } from '../api/client'
import type { Zone, User, CFAccount } from '../types'

const { Title, Text } = Typography

function Zones() {
  const [zones, setZones] = useState<Zone[]>([])
  const [users, setUsers] = useState<User[]>([])
  const [accounts, setAccounts] = useState<CFAccount[]>([])
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  // 域名分配弹窗
  const [assignOpen, setAssignOpen] = useState(false)
  const [assigningZone, setAssigningZone] = useState<Zone | null>(null)
  const [selectedUserIds, setSelectedUserIds] = useState<number[]>([])
  const [saving, setSaving] = useState(false)

  // 手动添加域名弹窗
  const [addOpen, setAddOpen] = useState(false)
  const [adding, setAdding] = useState(false)
  const [addForm] = Form.useForm()

  const fetchZones = async () => {
    setLoading(true)
    try {
      const res = await getZones()
      setZones(res.data.result)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const fetchUsers = async () => {
    try {
      const res = await getUsers()
      setUsers(res.data.result || [])
    } catch {
      // 用户列表加载失败不阻塞域名列表
    }
  }

  const fetchAccounts = async () => {
    try {
      const res = await getAccounts()
      setAccounts(res.data.result || [])
    } catch {
      // 账号列表加载失败不阻塞域名列表
    }
  }

  useEffect(() => {
    fetchZones()
    fetchUsers()
    fetchAccounts()
  }, [])

  const handleOpenAdd = () => {
    addForm.resetFields()
    const firstAvailable = accounts.find((a) => a.is_active && !a.is_blocked)
    if (firstAvailable) {
      addForm.setFieldsValue({ account_id: firstAvailable.id })
    }
    setAddOpen(true)
  }

  const handleAddZone = async () => {
    if (adding) return
    try {
      const values = await addForm.validateFields()
      setAdding(true)
      const res = await createZone({
        account_id: values.account_id,
        domain: values.domain.trim(),
      })
      const zone = res.data.result
      const nameServers = zone.name_servers || []

      setAddOpen(false)
      addForm.resetFields()
      fetchZones()

      Modal.success({
        title: res.data.existed ? '域名已存在，已同步到本地' : '域名添加成功',
        width: 560,
        content: (
          <div>
            <p style={{ marginTop: 8 }}>
              域名 <strong>{zone.name}</strong> 已归属账号 <strong>{res.data.account_name}</strong>。
            </p>
            {nameServers.length > 0 ? (
              <>
                <p>请到域名注册商处，把 NS 修改为 Cloudflare 提供的：</p>
                <ul style={{ paddingLeft: 20, marginBottom: 0 }}>
                  {nameServers.map((ns) => (
                    <li key={ns}><Text code>{ns}</Text></li>
                  ))}
                </ul>
              </>
            ) : (
              <p>Cloudflare 暂未返回 NS，请稍后刷新域名列表查看。</p>
            )}
          </div>
        ),
      })
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    } finally {
      setAdding(false)
    }
  }

  const handleOpenAssign = (zone: Zone) => {
    setAssigningZone(zone)
    setSelectedUserIds(zone.user_ids || [])
    setAssignOpen(true)
  }

  const handleAssign = async () => {
    if (!assigningZone || saving) return
    setSaving(true)
    try {
      await updateZoneUsers(assigningZone.id, selectedUserIds)
      message.success('域名分配已保存')
      setAssignOpen(false)
      fetchZones()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '保存失败'
      message.error(errorMessage)
    } finally {
      setSaving(false)
    }
  }

  const columns = [
    {
      title: '域名',
      dataIndex: 'name',
      key: 'name',
      render: (text: string) => <strong>{text}</strong>,
    },
    {
      title: '账号',
      dataIndex: 'account_name',
      key: 'account_name',
      render: (text: string) => text || '-',
    },
    {
      title: '状态',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => {
        const colorMap: Record<string, string> = {
          active: 'green',
          pending: 'orange',
          initializing: 'blue',
        }
        return <Tag color={colorMap[status] || 'default'}>{status}</Tag>
      },
    },
    {
      title: '计划',
      dataIndex: ['plan', 'name'],
      key: 'plan',
      render: (text: string) => text || 'Free',
    },
    {
      title: 'NS 服务器',
      dataIndex: 'name_servers',
      key: 'name_servers',
      render: (servers: string[]) => servers?.join(', ') || '-',
    },
    {
      title: '授权用户',
      key: 'users',
      render: (_: unknown, record: Zone) => {
        const names = (record.usernames || []).filter(Boolean)
        if (names.length === 0) {
          return <Tag>仅管理员</Tag>
        }
        return (
          <Space size={[0, 4]} wrap>
            {names.map((name) => (
              <Tag key={name} color="blue">{name}</Tag>
            ))}
          </Space>
        )
      },
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: Zone) => (
        <Space>
          <Button
            type="link"
            icon={<SettingOutlined />}
            onClick={() => navigate(`/zones/${record.id}/dns`)}
          >
            管理
          </Button>
          <Button
            type="link"
            icon={<TeamOutlined />}
            onClick={() => handleOpenAssign(record)}
          >
            分配用户
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Title level={4} style={{ margin: 0 }}>域名列表</Title>
        <Space>
          <Button icon={<ReloadOutlined />} onClick={fetchZones} loading={loading}>
            刷新
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleOpenAdd}>
            添加域名
          </Button>
        </Space>
      </div>
      <Table
        columns={columns}
        dataSource={zones}
        rowKey="id"
        loading={loading}
        pagination={{ pageSize: 20 }}
      />

      <Modal
        title={`分配用户${assigningZone ? ` - ${assigningZone.name}` : ''}`}
        open={assignOpen}
        onOk={handleAssign}
        onCancel={() => setAssignOpen(false)}
        okText="保存"
        cancelText="取消"
        confirmLoading={saving}
        okButtonProps={{ disabled: saving }}
        width={480}
      >
        <Alert
          type="info"
          showIcon
          message="所有用户（包括管理员）只能使用分配给自己的域名；未分配的域名不可用。"
          style={{ marginBottom: 16 }}
        />
        <Select
          mode="multiple"
          style={{ width: '100%' }}
          placeholder="选择可使用该域名的用户"
          value={selectedUserIds}
          onChange={setSelectedUserIds}
          options={users.map((u) => ({
            value: u.id,
            label: u.username,
            disabled: !u.is_active,
          }))}
          optionFilterProp="label"
          allowClear
        />
      </Modal>

      <Modal
        title="手动添加域名"
        open={addOpen}
        onOk={handleAddZone}
        onCancel={() => setAddOpen(false)}
        okText="添加"
        cancelText="取消"
        confirmLoading={adding}
        okButtonProps={{ disabled: adding }}
        width={520}
      >
        <Alert
          type="warning"
          showIcon
          message="此操作只在所选 Cloudflare 账号下创建 Zone，不会修改域名注册商的 NS。添加成功后请自行到注册商处把 NS 改为 Cloudflare 提供的名称服务器。"
          style={{ marginBottom: 16 }}
        />
        <Form form={addForm} layout="vertical">
          <Form.Item
            name="account_id"
            label="CF 账号"
            rules={[{ required: true, message: '请选择 CF 账号' }]}
          >
            <Select
              placeholder="选择要添加到的账号"
              options={accounts.map((a) => ({
                value: a.id,
                label: `${a.name}${a.is_blocked ? '（已封禁）' : !a.is_active ? '（已禁用）' : ''}`,
                disabled: a.is_blocked,
              }))}
            />
          </Form.Item>
          <Form.Item
            name="domain"
            label="根域名"
            extra="请输入根域名，例如 example.com（不要填写子域名或带协议前缀）"
            rules={[{ required: true, message: '请输入域名' }]}
          >
            <Input placeholder="example.com" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default Zones
