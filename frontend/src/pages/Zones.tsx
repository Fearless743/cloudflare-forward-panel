import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Table, Tag, Button, Space, Typography, message, Modal, Select, Alert } from 'antd'
import { ReloadOutlined, SettingOutlined, TeamOutlined } from '@ant-design/icons'
import { getZones, getUsers, updateZoneUsers } from '../api/client'
import type { Zone, User } from '../types'

const { Title } = Typography

function Zones() {
  const [zones, setZones] = useState<Zone[]>([])
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  // 域名分配弹窗
  const [assignOpen, setAssignOpen] = useState(false)
  const [assigningZone, setAssigningZone] = useState<Zone | null>(null)
  const [selectedUserIds, setSelectedUserIds] = useState<number[]>([])
  const [saving, setSaving] = useState(false)

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

  useEffect(() => {
    fetchZones()
    fetchUsers()
  }, [])

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
        <Button icon={<ReloadOutlined />} onClick={fetchZones} loading={loading}>
          刷新
        </Button>
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
          message="普通用户只能使用分配给自己的域名；未分配或清空后仅管理员可用。"
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
    </div>
  )
}

export default Zones
