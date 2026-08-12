import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import Layout from './components/Layout'
import Login from './pages/Login'
import Zones from './pages/Zones'
import DnsRecords from './pages/DnsRecords'
import ForwardRules from './pages/ForwardRules'
import SslSettings from './pages/SslSettings'
import Accounts from './pages/Accounts'
import Users from './pages/Users'
import Settings from './pages/Settings'
import Registrars from './pages/Registrars'

// 路由守卫
function PrivateRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('token')
  if (!token) {
    return <Navigate to="/login" replace />
  }
  return <>{children}</>
}

function App() {
  return (
    <ConfigProvider locale={zhCN}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <PrivateRoute>
                <Layout />
              </PrivateRoute>
            }
          >
            <Route index element={<Navigate to="/forward-rules" replace />} />
            <Route path="forward-rules" element={<ForwardRules />} />
            <Route path="zones" element={<Zones />} />
            <Route path="zones/:zoneId/dns" element={<DnsRecords />} />
            <Route path="zones/:zoneId/ssl" element={<SslSettings />} />
            <Route path="accounts" element={<Accounts />} />
            <Route path="users" element={<Users />} />
            <Route path="settings" element={<Settings />} />
            <Route path="registrars" element={<Registrars />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ConfigProvider>
  )
}

export default App
