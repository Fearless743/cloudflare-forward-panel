import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Table, Tag, Button, Space, Typography, message } from 'antd'
import { ReloadOutlined, SettingOutlined } from '@ant-design/icons'
import { getZones } from '../api/client'
import type { Zone } from '../types'

const { Title } = Typography

function Zones() {
  const [zones, setZones] = useState<Zone[]>([])
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

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

  useEffect(() => {
    fetchZones()
  }, [])

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
    </div>
  )
}

export default Zones
