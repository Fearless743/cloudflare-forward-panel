import { useState } from 'react'
import { Form, Input, Button, Card, Typography, message } from 'antd'
import { LockOutlined } from '@ant-design/icons'
import { useNavigate } from 'react-router-dom'
import { changePassword } from '../api/client'

const { Title, Text } = Typography

function ChangePassword() {
  const [loading, setLoading] = useState(false)
  const navigate = useNavigate()

  const onFinish = async (values: { old_password: string; new_password: string; confirm_password: string }) => {
    setLoading(true)
    try {
      const res = await changePassword(values.old_password, values.new_password)
      if (res.data.success) {
        // 用新 token 替换旧 token，并清除强制改密标记
        localStorage.setItem('token', res.data.result.token)
        message.success('密码修改成功')
        navigate('/forward-rules')
      }
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : '修改失败'
      message.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '100vh',
      background: '#f0f2f5',
    }}>
      <Card style={{ width: 400 }}>
        <Title level={3} style={{ textAlign: 'center', marginBottom: 8 }}>
          修改密码
        </Title>
        <Text type="secondary" style={{ display: 'block', textAlign: 'center', marginBottom: 24 }}>
          首次登录需修改默认密码后才能继续使用
        </Text>
        <Form
          name="change-password"
          onFinish={onFinish}
          autoComplete="off"
          size="large"
        >
          <Form.Item
            name="old_password"
            rules={[{ required: true, message: '请输入原密码' }]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="原密码" />
          </Form.Item>

          <Form.Item
            name="new_password"
            rules={[
              { required: true, message: '请输入新密码' },
              { min: 6, message: '新密码至少6位' },
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="新密码（至少6位）" />
          </Form.Item>

          <Form.Item
            name="confirm_password"
            dependencies={['new_password']}
            rules={[
              { required: true, message: '请再次输入新密码' },
              ({ getFieldValue }) => ({
                validator(_, value) {
                  if (!value || getFieldValue('new_password') === value) {
                    return Promise.resolve()
                  }
                  return Promise.reject(new Error('两次输入的密码不一致'))
                },
              }),
            ]}
          >
            <Input.Password prefix={<LockOutlined />} placeholder="确认新密码" />
          </Form.Item>

          <Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} block>
              确认修改
            </Button>
          </Form.Item>
        </Form>
      </Card>
    </div>
  )
}

export default ChangePassword
