import { useEffect, useState } from 'react'
import {
  Card,
  Form,
  Input,
  Button,
  Space,
  Typography,
  message,
  Alert,
  Switch,
  InputNumber,
  Table,
  Tag,
} from 'antd'
import {
  SaveOutlined,
  SendOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import {
  getSettings,
  updateSettings,
  testTelegram,
  runForwardCheck,
  getForwardCheckStatus,
} from '../api/client'
import type { ForwardCheckIssue, ForwardCheckReport } from '../api/client'

const { Title, Text } = Typography

function formatCheckedAt(value?: string) {
  if (!value) return '-'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString()
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms))

// 检查在后台执行，这里轮询状态直到完成（最多等待 10 分钟）。
async function waitForForwardCheck(): Promise<ForwardCheckReport | null> {
  const deadline = Date.now() + 10 * 60 * 1000
  while (Date.now() < deadline) {
    await sleep(2000)
    try {
      const res = await getForwardCheckStatus()
      if (!res.data.result.running) {
        return res.data.result.last_report
      }
    } catch {
      // 网络抖动时继续轮询，避免一次失败就中断等待。
    }
  }
  return null
}

function Settings() {
  const [loading, setLoading] = useState(false)
  const [telegramLoading, setTelegramLoading] = useState(false)
  const [checkSaving, setCheckSaving] = useState(false)
  const [checking, setChecking] = useState(false)
  const [checkReport, setCheckReport] = useState<ForwardCheckReport | null>(null)
  const [telegramForm] = Form.useForm()
  const [checkForm] = Form.useForm()

  const fetchSettings = async () => {
    setLoading(true)
    try {
      const res = await getSettings()
      const data = res.data.result
      telegramForm.setFieldsValue(data)
      checkForm.setFieldsValue({
        check_enabled: data.check_enabled,
        check_interval_minutes: data.check_interval_minutes,
        check_auto_fix: data.check_auto_fix,
      })
      setCheckReport(data.check_last_report)
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

  const handleSaveTelegram = async () => {
    try {
      const values = await telegramForm.validateFields()
      await updateSettings({
        telegram_bot_token: values.telegram_bot_token,
        telegram_chat_id: values.telegram_chat_id,
      })
      message.success('设置已保存')
      fetchSettings()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    }
  }

  const handleSaveCheck = async () => {
    setCheckSaving(true)
    try {
      const values = await checkForm.validateFields()
      await updateSettings(values)
      message.success('检查设置已保存')
      fetchSettings()
    } catch (err: unknown) {
      if (err instanceof Error) {
        message.error(err.message)
      }
    } finally {
      setCheckSaving(false)
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

  const handleRunCheck = async () => {
    setChecking(true)
    try {
      await runForwardCheck()
      const report = await waitForForwardCheck()
      if (!report) {
        message.info('检查仍在后台运行，请稍后刷新页面查看结果')
        return
      }
      setCheckReport(report)
      if (report.issues.length === 0) {
        message.success(
          report.fixed > 0
            ? `检查完成，已自动修复 ${report.fixed} 个问题`
            : '检查完成，DNS 与 Origin Rules 均与面板一致'
        )
      } else {
        message.warning(`检查完成，仍有 ${report.issues.length} 个问题`)
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '检查失败'
      message.error(errorMessage)
    } finally {
      setChecking(false)
    }
  }

  const issueColumns = [
    {
      title: '域名',
      dataIndex: 'zone_name',
      key: 'zone_name',
    },
    {
      title: '主机名',
      dataIndex: 'hostname',
      key: 'hostname',
    },
    {
      title: '类型',
      dataIndex: 'target',
      key: 'target',
      render: (target: string) => (
        <Tag color={target === 'DNS' ? 'blue' : 'purple'}>{target}</Tag>
      ),
    },
    {
      title: '问题',
      dataIndex: 'message',
      key: 'message',
    },
  ]

  return (
    <div>
      <Title level={4} style={{ marginBottom: 24 }}>系统设置</Title>

      <Space direction="vertical" size={24} style={{ display: 'flex' }}>
        <Card title="定时检查 DNS / Origin Rules">
          <Alert
            message="定时对比面板中的转发规则与 Cloudflare 侧的 DNS 记录、Origin Rules；一致时不做修改，不一致时按面板配置修改，缺失时自动创建。开启自动修复后会严格以面板为准，面板外手工添加的主机名也会被移除。"
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
          />
          <Form form={checkForm} layout="vertical">
            <Space size="large" wrap>
              <Form.Item
                name="check_enabled"
                label="启用定时检查"
                valuePropName="checked"
                style={{ marginBottom: 0 }}
              >
                <Switch checkedChildren="开" unCheckedChildren="关" />
              </Form.Item>
              <Form.Item
                name="check_interval_minutes"
                label="检查间隔（分钟）"
                style={{ marginBottom: 0 }}
              >
                <InputNumber min={1} max={1440} style={{ width: 160 }} />
              </Form.Item>
              <Form.Item
                name="check_auto_fix"
                label="发现不一致时自动修复"
                valuePropName="checked"
                style={{ marginBottom: 0 }}
              >
                <Switch checkedChildren="开" unCheckedChildren="关" />
              </Form.Item>
            </Space>
            <Form.Item style={{ marginTop: 20, marginBottom: 0 }}>
              <Space>
                <Button
                  type="primary"
                  icon={<SaveOutlined />}
                  onClick={handleSaveCheck}
                  loading={checkSaving}
                >
                  保存
                </Button>
                <Button
                  icon={<SafetyCertificateOutlined />}
                  onClick={handleRunCheck}
                  loading={checking}
                >
                  {checking ? '检查中…' : '立即检查'}
                </Button>
                <Text type="secondary">
                  {checking
                    ? '检查在后台运行，可能需要几分钟…'
                    : `上次检查：${formatCheckedAt(checkReport?.checked_at)}`}
                </Text>
              </Space>
            </Form.Item>
          </Form>

          {checkReport && (
            <div style={{ marginTop: 20 }}>
              {checkReport.issues.length === 0 ? (
                <Alert
                  type="success"
                  showIcon
                  message={
                    checkReport.fixed > 0
                      ? `检查完成，已自动修复 ${checkReport.fixed} 个问题，当前 DNS 与 Origin Rules 均与面板一致。`
                      : '检查完成，DNS 与 Origin Rules 均与面板一致。'
                  }
                  description={
                    checkReport.errors.length > 0
                      ? `检查过程中有 ${checkReport.errors.length} 个错误，可查看服务端日志。`
                      : undefined
                  }
                />
              ) : (
                <Alert
                  type="warning"
                  showIcon
                  message={`发现 ${checkReport.issues.length} 个与面板不一致的问题${
                    checkReport.fixed > 0 ? `（本次已修复 ${checkReport.fixed} 个）` : ''
                  }`}
                  description={
                    <Text type="secondary">
                      检查域名 {checkReport.checked_zones} 个，规则 {checkReport.checked_rules} 条。
                      请确认自动修复已开启，或检查 Cloudflare 账号权限。
                    </Text>
                  }
                />
              )}

              {checkReport.errors.length > 0 && (
                <Alert
                  type="error"
                  showIcon
                  style={{ marginTop: 12 }}
                  message="检查错误"
                  description={
                    <ul style={{ margin: 0, paddingLeft: 20 }}>
                      {checkReport.errors.map((err, index) => (
                        <li key={`${index}-${err}`}>{err}</li>
                      ))}
                    </ul>
                  }
                />
              )}

              {checkReport.issues.length > 0 && (
                <Table<ForwardCheckIssue>
                  style={{ marginTop: 12 }}
                  size="small"
                  rowKey={(row, index) => `${row.rule_id}-${row.target}-${index}`}
                  dataSource={checkReport.issues}
                  columns={issueColumns}
                  pagination={{ pageSize: 10, hideOnSinglePage: true }}
                />
              )}
            </div>
          )}
        </Card>

        <Card title="Telegram 通知">
          <Alert
            message="配置 Telegram 机器人后，CF 账号异常或定时检查发现不一致时会发送通知"
            type="info"
            showIcon
            style={{ marginBottom: 16 }}
          />
          <Form form={telegramForm} layout="vertical">
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
                  onClick={handleSaveTelegram}
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
      </Space>
    </div>
  )
}

export default Settings
