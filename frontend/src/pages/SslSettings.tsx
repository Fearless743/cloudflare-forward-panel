import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Card, Radio, Button, Typography, Space, message, Spin, Alert } from 'antd'
import { ArrowLeftOutlined, SaveOutlined } from '@ant-design/icons'
import { getSSLSettings, updateSSLSettings } from '../api/client'

const { Title, Text, Paragraph } = Typography

const SSL_MODES = [
  { value: 'off', label: '关闭', description: '不加密' },
  { value: 'flexible', label: '灵活 (Flexible)', description: '到 Cloudflare 使用 HTTPS，到源站使用 HTTP' },
  { value: 'full', label: '完全 (Full)', description: '到源站使用 HTTPS（不验证证书）' },
  { value: 'strict', label: '完全-严格 (Full Strict)', description: '到源站使用 HTTPS（验证证书）' },
]

function SslSettings() {
  const { zoneId } = useParams<{ zoneId: string }>()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [currentValue, setCurrentValue] = useState<string>('full')
  const [selectedValue, setSelectedValue] = useState<string>('full')

  const fetchSettings = async () => {
    if (!zoneId) return
    setLoading(true)
    try {
      const res = await getSSLSettings(zoneId)
      setCurrentValue(res.data.result.value)
      setSelectedValue(res.data.result.value)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchSettings()
  }, [zoneId])

  const handleSave = async () => {
    if (!zoneId || selectedValue === currentValue) return
    setSaving(true)
    try {
      await updateSSLSettings(zoneId, selectedValue)
      setCurrentValue(selectedValue)
      message.success('SSL 设置已更新')
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '更新失败'
      message.error(errorMessage)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <Space>
          <Button icon={<ArrowLeftOutlined />} onClick={() => navigate('/zones')}>返回</Button>
          <Title level={4} style={{ margin: 0 }}>SSL/TLS 设置</Title>
        </Space>
        <Button
          type="primary"
          icon={<SaveOutlined />}
          onClick={handleSave}
          loading={saving}
          disabled={selectedValue === currentValue}
        >
          保存设置
        </Button>
      </div>

      <Spin spinning={loading}>
        <Card>
          <Title level={5}>加密模式</Title>
          <Paragraph type="secondary">
            选择 Cloudflare 与源站之间的加密方式
          </Paragraph>

          <Radio.Group
            value={selectedValue}
            onChange={(e) => setSelectedValue(e.target.value)}
            style={{ width: '100%' }}
          >
            <Space direction="vertical" style={{ width: '100%' }}>
              {SSL_MODES.map((mode) => (
                <Card
                  key={mode.value}
                  size="small"
                  hoverable
                  style={{
                    borderColor: selectedValue === mode.value ? '#1677ff' : undefined,
                  }}
                  onClick={() => setSelectedValue(mode.value)}
                >
                  <Radio value={mode.value}>
                    <Text strong>{mode.label}</Text>
                    <br />
                    <Text type="secondary">{mode.description}</Text>
                  </Radio>
                </Card>
              ))}
            </Space>
          </Radio.Group>

          {currentValue === 'strict' && (
            <Alert
              message="当前使用严格模式"
              description="源站需要有效的 SSL 证书（Let's Encrypt 或 Cloudflare Origin CA）"
              type="info"
              showIcon
              style={{ marginTop: 16 }}
            />
          )}
        </Card>
      </Spin>
    </div>
  )
}

export default SslSettings
