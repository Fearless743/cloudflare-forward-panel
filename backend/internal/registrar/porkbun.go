package registrar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const porkbunBaseURL = "https://api.porkbun.com/api/json/v3"

// PorkbunClient Porkbun API 客户端
// 认证方式：X-API-Key / X-Secret-API-Key 请求头
// 文档：https://porkbun.com/llms-full.txt
type PorkbunClient struct {
	apiKey    string
	apiSecret string
	client    *http.Client
}

// PorkbunResponse 通用响应结构
type PorkbunResponse struct {
	Status  string          `json:"status"`
	Message string          `json:"message"`
	Code    string          `json:"code"`
	Domains []PorkbunDomain `json:"domains"`
}

type PorkbunDomain struct {
	Domain     string   `json:"domain"`
	Ns         []string `json:"ns"`
	Status     string   `json:"status"`
	ExpireDate string   `json:"expireDate"`
}

func NewPorkbunClient(apiKey, apiSecret string) *PorkbunClient {
	return &PorkbunClient{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		client:    &http.Client{Timeout: 30 * time.Second},
	}
}

// doRequest 发送带认证头的请求
func (c *PorkbunClient) doRequest(method, path string, body interface{}) (*PorkbunResponse, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("序列化请求失败: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequest(method, porkbunBaseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("X-Secret-API-Key", c.apiSecret)

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("porkbun API 请求失败: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %w", err)
	}

	var result PorkbunResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if result.Status != "SUCCESS" {
		return nil, fmt.Errorf("porkbun API 错误: %s (code: %s)", result.Message, result.Code)
	}
	return &result, nil
}

// ListDomains 获取账户下所有域名
func (c *PorkbunClient) ListDomains() ([]string, error) {
	resp, err := c.doRequest("GET", "/domain/listAll", nil)
	if err != nil {
		return nil, err
	}
	domains := make([]string, 0, len(resp.Domains))
	for _, d := range resp.Domains {
		domains = append(domains, d.Domain)
	}
	return domains, nil
}

// UpdateNameservers 更新域名的 NS 记录（v3 updateNs）
func (c *PorkbunClient) UpdateNameservers(domain string, ns1, ns2 string) error {
	payload := map[string]interface{}{
		"ns": []string{ns1, ns2},
	}
	_, err := c.doRequest("POST", "/domain/updateNs/"+domain, payload)
	return err
}

// TestConnection 测试 API 连接
func (c *PorkbunClient) TestConnection() error {
	_, err := c.doRequest("GET", "/ping", nil)
	return err
}
