package registrar

// Registrar 注册商统一接口
// 用于创建/导入域名时统一处理不同注册商
type Registrar interface {
	// ListDomains 获取账户下所有域名
	ListDomains() ([]string, error)
	// UpdateNameservers 更新域名的 NS 记录
	UpdateNameservers(domain string, ns1, ns2 string) error
	// TestConnection 测试 API 连接
	TestConnection() error
}

// GetClient 根据注册商类型创建对应的客户端
func GetClient(registrarType, apiKey, apiSecret string) Registrar {
	switch registrarType {
	case "porkbun":
		return NewPorkbunClient(apiKey, apiSecret)
	case "spaceship":
		return NewSpaceshipClient(apiKey, apiSecret)
	default:
		return nil
	}
}
