import { useState, useEffect } from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import { Layout as AntLayout, Menu, Typography, Dropdown, Avatar, Space } from 'antd'
import {
  GlobalOutlined,
  ClusterOutlined,
  SafetyCertificateOutlined,
  SwapOutlined,
  UserOutlined,
  TeamOutlined,
  LogoutOutlined,
  SettingOutlined,
} from '@ant-design/icons'

const { Header, Sider, Content } = AntLayout
const { Title } = Typography

function Layout() {
  const [collapsed, setCollapsed] = useState(false)
  const [user, setUser] = useState<{ username: string; role: string } | null>(null)
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    const userStr = localStorage.getItem('user')
    if (userStr) {
      setUser(JSON.parse(userStr))
    }
  }, [])

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    navigate('/login')
  }

  const menuItems = [
    {
      key: '/forward-rules',
      icon: <SwapOutlined />,
      label: '端口转发',
    },
    {
      key: '/zones',
      icon: <GlobalOutlined />,
      label: '域名管理',
    },
    {
      key: '/accounts',
      icon: <UserOutlined />,
      label: '账号管理',
    },
  ]

  // 只有管理员能看到用户管理和设置
  if (user?.role === 'admin') {
    menuItems.push({
      key: '/users',
      icon: <TeamOutlined />,
      label: '用户管理',
    })
    menuItems.push({
      key: '/registrars',
      icon: <GlobalOutlined />,
      label: '注册商管理',
    })
    menuItems.push({
      key: '/settings',
      icon: <SettingOutlined />,
      label: '系统设置',
    })
  }

  // 从 URL 中提取 zoneId 并添加子菜单
  const zoneMatch = location.pathname.match(/\/zones\/([^/]+)/)
  const currentZoneId = zoneMatch?.[1]

  const getSelectedKey = () => {
    if (location.pathname.includes('/dns')) return 'dns'
    if (location.pathname.includes('/origin-rules')) return 'origin-rules'
    if (location.pathname.includes('/ssl')) return 'ssl'
    return location.pathname
  }

  const userMenuItems = [
    {
      key: 'logout',
      icon: <LogoutOutlined />,
      label: '退出登录',
      onClick: handleLogout,
    },
  ]

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      <Sider
        collapsible
        collapsed={collapsed}
        onCollapse={setCollapsed}
        theme="dark"
      >
        <div style={{ padding: '16px', textAlign: 'center' }}>
          <Title level={4} style={{ color: '#fff', margin: 0 }}>
            {collapsed ? 'CF' : 'CF Panel'}
          </Title>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[getSelectedKey()]}
          onClick={({ key }) => {
            navigate(key)
          }}
          items={menuItems}
        />

        {currentZoneId && (
          <>
            <div style={{ padding: '8px 16px', color: 'rgba(255,255,255,0.45)', fontSize: 12 }}>
              {collapsed ? '' : '当前域名'}
            </div>
            <Menu
              theme="dark"
              mode="inline"
              selectedKeys={[getSelectedKey()]}
              onClick={({ key }) => {
                navigate(`/zones/${currentZoneId}/${key}`)
              }}
              items={[
                { key: 'dns', icon: <ClusterOutlined />, label: 'DNS 记录' },
                { key: 'ssl', icon: <SafetyCertificateOutlined />, label: 'SSL/TLS' },
              ]}
            />
          </>
        )}
      </Sider>
      <AntLayout>
        <Header style={{ padding: '0 24px', background: '#fff', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <Title level={4} style={{ margin: 0 }}>Cloudflare 转发面板</Title>
          <Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
            <Space style={{ cursor: 'pointer' }}>
              <Avatar icon={<UserOutlined />} />
              <span>{user?.username || '用户'}</span>
            </Space>
          </Dropdown>
        </Header>
        <Content style={{ margin: '24px 16px', padding: 24, background: '#fff', borderRadius: 8, minHeight: 360 }}>
          <Outlet />
        </Content>
      </AntLayout>
    </AntLayout>
  )
}

export default Layout
