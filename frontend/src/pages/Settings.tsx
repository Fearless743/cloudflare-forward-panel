import { useEffect, useState } from 'react'
import { Card, Form, Input, Button, Space, Typography, message, Alert } from 'antd'
import { SaveOutlined, SendOutlined } from '@ant-design/icons'
import { getSettings, updateSettings, testTelegram } from '../api/client'

const { Title, Text } = Typography

function Settings() {
  const [loading, setLoading] = useState(false)
  const [telegramLoading, setTelegramLoading] = useState(false)
  const [form] = Form.useForm()

  const fetchSettings = async () => {
    setLoading(true)
    try {
      const res = await getSettings()
      form.setFieldsValue(res.data.result)
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '加载失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchSettings()
  }, [])

  const handleSave = async () => {
    try {
      const values = await form.validateFields()
      await updateSettings(values)
      message.success('设置已保存')
      fetchSettings()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    }
  }

  const handleTestTelegram = async () => {
    setTelegramLoading(true)
    try {
      await testTelegram()
      message.success('测试通知已发送，请检查 Telegram')
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '发送失败'
      message.error(errorMessage)
    } finally {
      setTelegramLoading(false)
    }
  }

  return (
    <div>
      <Title level={4} style={{ marginBottom: 24 }}>系统设置</Title>

      <Card title="Telegram 通知">
        <Alert
          message="配置 Telegram 机器人后，当 CF 账号出现异常时会发送通知"
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
        />
        <Form form={form} layout="vertical">
          <Form.Item
            name="telegram_bot_token"
            label="Bot Token"
          >
            <Input.Password placeholder="输入 Telegram Bot Token" />
          </Form.Item>
          <Form.Item
            name="telegram_chat_id"
            label="Chat ID"
          >
            <Input placeholder="输入 Telegram Chat ID" />
          </Form.Item>
          <Form.Item>
            <Space>
              <Button
                type="primary"
                icon={<SaveOutlined />}
                onClick={handleSave}
                loading={loading}
              >
                保存
              </Button>
              <Button
                icon={<SendOutlined />}
                onClick={handleTestTelegram}
                loading={telegramLoading}
              >
                测试通知
              </Button>
            </Space>
          </Form.Item>
        </Form>
        <Alert
          message={
            <Text type="secondary">
              获取 Bot Token：在 Telegram 中搜索 @BotFather，创建机器人后获取 Token。
              获取 Chat ID：向机器人发送消息后，访问 https://api.telegram.org/bot&lt;TOKEN&gt;/getUpdates 获取。
            </Text>
          }
          type="info"
          showIcon
          style={{ marginTop: 16 }}
        />
      </Card>
    </div>
  )
}

export default Settings
