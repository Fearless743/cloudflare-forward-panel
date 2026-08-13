import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Table, Tag, Button, Space, Typography, Select, Modal, Form, Input, InputNumber, Switch, message, Popconfirm } from 'antd'
import { ReloadOutlined, PlusOutlined, DeleteOutlined, EditOutlined, ArrowLeftOutlined } from '@ant-design/icons'
import { getDNSRecords, createDNSRecord, updateDNSRecord, deleteDNSRecord } from '../api/client'
import type { DNSRecord } from '../types'

const { Title } = Typography

const RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SRV', 'CAA', 'PTR']

function DnsRecords() {
  const { zoneId } = useParams<{ zoneId: string }>()
  const navigate = useNavigate()
  const [records, setRecords] = useState<DNSRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [typeFilter, setTypeFilter] = useState<string | undefined>()
  const [modalOpen, setModalOpen] = useState(false)
  const [editingRecord, setEditingRecord] = useState<DNSRecord | null>(null)
  const [form] = Form.useForm()
  const [deletingId, setDeletingId] = useState<string | null>(null)

  const fetchRecords = async () => {
    if (!zoneId) return
    setLoading(true)
    try {
      const res = await getDNSRecords(zoneId, typeFilter)
      setRecords(res.data.result)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchRecords()
  }, [zoneId, typeFilter])

  const handleCreate = () => {
    setEditingRecord(null)
    form.resetFields()
    form.setFieldsValue({ type: 'A', ttl: 1, proxied: true })
    setModalOpen(true)
  }

  const handleEdit = (record: DNSRecord) => {
    setEditingRecord(record)
    form.setFieldsValue(record)
    setModalOpen(true)
  }

  const handleDelete = async (recordId: string) => {
    if (!zoneId || deletingId !== null) return
    setDeletingId(recordId)
    try {
      await deleteDNSRecord(zoneId, recordId)
      message.success('删除成功')
      fetchRecords()
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '删除失败'
      message.error(errorMessage)
    } finally {
      setDeletingId(null)
    }
  }

  const handleSubmit = async () => {
    if (!zoneId) return
    try {
      const values = await form.validateFields()
      if (editingRecord) {
        await updateDNSRecord(zoneId, editingRecord.id, values)
        message.success('更新成功')
      } else {
        await createDNSRecord(zoneId, values)
        message.success('创建成功')
      }
      setModalOpen(false)
      fetchRecords()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    }
  }

  const columns = [
    {
      title: '名称',
      dataIndex: 'name',
      key: 'name',
      render: (text: string) => <strong>{text}</strong>,
    },
    {
      title: '类型',
      dataIndex: 'type',
      key: 'type',
      render: (type: string) => <Tag color="blue">{type}</Tag>,
    },
    {
      title: '内容',
      dataIndex: 'content',
      key: 'content',
    },
    {
      title: 'TTL',
      dataIndex: 'ttl',
      key: 'ttl',
      render: (ttl: number) => ttl === 1 ? '自动' : ttl,
    },
    {
      title: '代理',
      dataIndex: 'proxied',
      key: 'proxied',
      render: (proxied: boolean) => (
        <Tag color={proxied ? 'orange' : 'default'}>
          {proxied ? '已代理' : '仅 DNS'}
        </Tag>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      render: (_: unknown, record: DNSRecord) => (
        <Space>
          <Button type="link" size="small" icon={<EditOutlined />} onClick={() => handleEdit(record)}>
            编辑
          </Button>
          <Popconfirm title="确定删除此记录？" onConfirm={() => handleDelete(record.id)}
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
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/zones')}>返回</Button>
          <Title level={4} style={{ margin: 0 }}>DNS 记录</Title>
        </Space>
        <Space>
          <Select
            placeholder="筛选类型"
            allowClear
            style={{ width: 120 }}
            value={typeFilter}
            onChange={setTypeFilter}
            options={RECORD_TYPES.map(t => ({ label: t, value: t }))}
          />
          <Button icon={<ReloadOutlined />} onClick={fetchRecords} loading={loading}>刷新</Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={handleCreate}>添加记录</Button>
        </Space>
      </div>

      <Table
        columns={columns}
        dataSource={records}
        rowKey="id"
        loading={loading}
        pagination={{ pageSize: 20 }}
      />

      <Modal
        title={editingRecord ? '编辑 DNS 记录' : '添加 DNS 记录'}
        open={modalOpen}
        onOk={handleSubmit}
        onCancel={() => setModalOpen(false)}
        okText="保存"
        cancelText="取消"
      >
        <Form form={form} layout="vertical">
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '请输入名称' }]}>
            <Input placeholder="例如: sub.example.com" />
          </Form.Item>
          <Form.Item name="type" label="类型" rules={[{ required: true }]}>
            <Select options={RECORD_TYPES.map(t => ({ label: t, value: t }))} />
          </Form.Item>
          <Form.Item name="content" label="内容" rules={[{ required: true, message: '请输入内容' }]}>
            <Input placeholder="例如: 192.168.1.1" />
          </Form.Item>
          <Form.Item name="ttl" label="TTL">
            <InputNumber min={1} max={86400} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="proxied" label="代理状态" valuePropName="checked">
            <Switch checkedChildren="代理" unCheckedChildren="仅 DNS" />
          </Form.Item>
          <Form.Item name="comment" label="备注">
            <Input.TextArea rows={2} />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  )
}

export default DnsRecords
