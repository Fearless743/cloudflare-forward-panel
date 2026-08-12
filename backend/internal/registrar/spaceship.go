package registrar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const spaceshipBaseURL = "https://spaceship.dev/api"

// SpaceshipClient Spaceship API 客户端
// 认证方式：使用 X-API-Key 和 X-API-Secret 请求头
// API 文档：https://docs.spaceship.dev
type SpaceshipClient struct {
	apiKey    string
	apiSecret string
	client    *http.Client
}

func NewSpaceshipClient(apiKey, apiSecret string) *SpaceshipClient {
	return &SpaceshipClient{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// ListDomains 获取账户下所有域名（分页拉取）
func (c *SpaceshipClient) ListDomains() ([]string, error) {
	var all []string
	for skip := 0; ; skip += 100 {
		path := fmt.Sprintf("/v1/domains?take=100&skip=%d", skip)
		resp, err := c.request("GET", path, nil)
		if err != nil {
			return nil, err
		}
		var result struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		}
		if err := json.Unmarshal(resp, &result); err != nil {
			return nil, fmt.Errorf("解析响应失败: %w", err)
		}
		for _, item := range result.Items {
			all = append(all, item.Name)
		}
		if len(result.Items) < 100 {
			break
		}
	}
	return all, nil
}

// UpdateNameservers 更新域名的 NS 记录
// provider 为 custom，hosts 为自定义 NS 列表
func (c *SpaceshipClient) UpdateNameservers(domain string, ns1, ns2 string) error {
	payload := map[string]interface{}{
		"provider": "custom",
		"hosts":    []string{ns1, ns2},
	}
	_, err := c.request("PUT", "/v1/domains/"+domain+"/nameservers", payload)
	return err
}

// TestConnection 测试 API 连接
func (c *SpaceshipClient) TestConnection() error {
	_, err := c.request("GET", "/v1/domains?take=1&skip=0", nil)
	return err
}

// request 发送带认证头的请求并返回响应体
func (c *SpaceshipClient) request(method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("序列化请求失败: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequest(method, spaceshipBaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("X-API-Secret", c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("spaceship API 请求失败: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("spaceship API 错误: 状态码 %d, %s", resp.StatusCode, string(data))
	}
	return data, nil
}
