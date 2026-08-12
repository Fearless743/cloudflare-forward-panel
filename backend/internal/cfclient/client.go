package cfclient

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

const baseURL = "https://api.cloudflare.com/client/v4"

type Client struct {
	httpClient        *http.Client
	apiKey            string // Global API Key
	email             string // 登录邮箱
	accountID         uint
	accountIdentifier string // CF 账号 ID（创建 Zone 时用于指定 account 参数）
	accountName       string
	manager           *Manager // 引用管理器用于错误报告
}

type CFResponse struct {
	Success bool            `json:"success"`
	Errors  []CFError       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type CFError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Zone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	NameServers []string `json:"name_servers"`
	Plan        struct {
		Name string `json:"name"`
	} `json:"plan"`
}

type DNSRecord struct {
	ID       string `json:"id"`
	ZoneID   string `json:"zone_id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Proxied  bool   `json:"proxied"`
	Comment  string `json:"comment"`
}

type OriginRuleset struct {
	ID          string       `json:"id,omitempty"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Kind        string       `json:"kind"`
	Phase       string       `json:"phase"`
	Version     string       `json:"version,omitempty"`
	Rules       []OriginRule `json:"rules"`
}

type OriginRule struct {
	ID               string           `json:"id,omitempty"`
	Description      string           `json:"description"`
	Expression       string           `json:"expression"`
	Action           string           `json:"action"`
	ActionParameters *ActionParams    `json:"action_parameters"`
	Enabled          bool             `json:"enabled"`
}

type ActionParams struct {
	Origin     *OriginParams `json:"origin"`
	// HostHeader 留空时不发送，避免 CF API 报 cannot be empty
	HostHeader string `json:"host_header,omitempty"`
}

type OriginParams struct {
	Port int `json:"port"`
	// Host 和 SNI 字段留空时均不发送（免费计划不支持 Origin Host override）
	Host string `json:"host,omitempty"`
	SNI  *SNI   `json:"sni,omitempty"`
}

type SNI struct {
	Value string `json:"value"`
}

type SSLSetting struct {
	ID       string `json:"id"`
	Value    string `json:"value"`
	Editable bool   `json:"editable"`
}

// NewClient 创建客户端（Global API Key 认证）
func NewClient(apiKey, email string) *Client {
	return &Client{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		apiKey:     apiKey,
		email:      email,
	}
}

// SetManager 设置管理器引用
func (c *Client) SetManager(m *Manager) {
	c.manager = m
}

// SetAccountIdentifier 设置 CF 账号 ID
func (c *Client) SetAccountIdentifier(id string) {
	c.accountIdentifier = id
}

// setAuthHeaders 设置 Global API Key 认证请求头
// X-Auth-Key=<Global API Key> + X-Auth-Email=<登录邮箱>
func (c *Client) setAuthHeaders(req *http.Request) {
	req.Header.Set("X-Auth-Key", c.apiKey)
	req.Header.Set("X-Auth-Email", c.email)
}

func (c *Client) doRequest(method, path string, body interface{}) (*CFResponse, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal body: %w", err)
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequest(method, baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	// 调试日志：显示 api key 前缀
	keyPrefix := c.apiKey
	if len(keyPrefix) > 10 {
		keyPrefix = keyPrefix[:10] + "..."
	}
	log.Printf("[CF API] %s %s, email: %s, key prefix: %s", method, path, c.email, keyPrefix)

	req.Header.Set("Content-Type", "application/json")
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	// DELETE 等请求可能返回空 body，2xx 状态码视为成功
	if len(respBody) == 0 {
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return &CFResponse{Success: true}, nil
		}
		return nil, fmt.Errorf("cloudflare error: HTTP %d (empty response)", resp.StatusCode)
	}

	var cfResp CFResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if !cfResp.Success {
		errMsg := ""
		for _, e := range cfResp.Errors {
			errMsg += fmt.Sprintf("[%d] %s ", e.Code, e.Message)
		}

		// 报告错误给管理器
		if c.manager != nil && c.accountID > 0 {
			go c.manager.ReportError(c.accountID, errMsg)
		}

		return nil, fmt.Errorf("cloudflare error: %s", errMsg)
	}

	return &cfResp, nil
}

// Zones

func (c *Client) ListZones() ([]Zone, error) {
	resp, err := c.doRequest("GET", "/zones?per_page=50", nil)
	if err != nil {
		return nil, err
	}
	var zones []Zone
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return nil, err
	}
	return zones, nil
}

func (c *Client) GetZone(zoneID string) (*Zone, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/zones/%s", zoneID), nil)
	if err != nil {
		return nil, err
	}
	var zone Zone
	if err := json.Unmarshal(resp.Result, &zone); err != nil {
		return nil, err
	}
	return &zone, nil
}

// ListAllZones 分页拉取全部 Zone
func (c *Client) ListAllZones() ([]Zone, error) {
	var all []Zone
	for page := 1; ; page++ {
		resp, err := c.doRequest("GET", fmt.Sprintf("/zones?per_page=100&page=%d", page), nil)
		if err != nil {
			return nil, err
		}
		var zones []Zone
		if err := json.Unmarshal(resp.Result, &zones); err != nil {
			return nil, err
		}
		all = append(all, zones...)
		if len(zones) < 100 {
			break
		}
	}
	return all, nil
}

// CreateZone 在 Cloudflare 创建 Zone（接入域名）
// 创建成功后 Zone.NameServers 为 CF 分配的 nameservers
func (c *Client) CreateZone(domain string) (*Zone, error) {
	body := map[string]interface{}{
		"name": domain,
		"type": "full", // full 托管：CF 分配 nameservers
	}

	// 使用账号配置中指定的 account_id 创建 Zone
	// 避免默认账号被禁用或未授权时的 [1067] Invalid account identifier
	if c.accountIdentifier != "" {
		body["account"] = map[string]string{"id": c.accountIdentifier}
	}

	resp, err := c.doRequest("POST", "/zones", body)
	if err != nil {
		return nil, err
	}
	var zone Zone
	if err := json.Unmarshal(resp.Result, &zone); err != nil {
		return nil, err
	}
	return &zone, nil
}

// parseTokenAccountID 尝试从 CF API Token 中解析 account_id
// 若 token 前缀为 "cfat_"，则后面的字符串即为账号 ID
func parseTokenAccountID(token string) string {
	const prefix = "cfat_"
	if strings.HasPrefix(token, prefix) && len(token) > len(prefix) {
		return token[len(prefix):]
	}
	return ""
}

// DNS Records

func (c *Client) ListDNSRecords(zoneID string, recordType string) ([]DNSRecord, error) {
	path := fmt.Sprintf("/zones/%s/dns_records?per_page=100", zoneID)
	if recordType != "" {
		path += "&type=" + recordType
	}
	resp, err := c.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var records []DNSRecord
	if err := json.Unmarshal(resp.Result, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (c *Client) CreateDNSRecord(zoneID string, record *DNSRecord) (*DNSRecord, error) {
	resp, err := c.doRequest("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), record)
	if err != nil {
		return nil, err
	}
	var created DNSRecord
	if err := json.Unmarshal(resp.Result, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

func (c *Client) UpdateDNSRecord(zoneID, recordID string, record *DNSRecord) (*DNSRecord, error) {
	resp, err := c.doRequest("PATCH", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), record)
	if err != nil {
		return nil, err
	}
	var updated DNSRecord
	if err := json.Unmarshal(resp.Result, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func (c *Client) DeleteDNSRecord(zoneID, recordID string) error {
	_, err := c.doRequest("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), nil)
	return err
}

// Origin Rules

func (c *Client) ListOriginRulesets(zoneID string) ([]OriginRuleset, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/zones/%s/rulesets?phase=http_request_origin&kind=zone", zoneID), nil)
	if err != nil {
		return nil, err
	}
	var rulesets []OriginRuleset
	if err := json.Unmarshal(resp.Result, &rulesets); err != nil {
		return nil, err
	}
	return rulesets, nil
}

func (c *Client) GetOriginRuleset(zoneID, rulesetID string) (*OriginRuleset, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/zones/%s/rulesets/%s", zoneID, rulesetID), nil)
	if err != nil {
		return nil, err
	}
	var ruleset OriginRuleset
	if err := json.Unmarshal(resp.Result, &ruleset); err != nil {
		return nil, err
	}
	return &ruleset, nil
}

func (c *Client) CreateOriginRuleset(zoneID string, ruleset *OriginRuleset) (*OriginRuleset, error) {
	resp, err := c.doRequest("POST", fmt.Sprintf("/zones/%s/rulesets", zoneID), ruleset)
	if err != nil {
		return nil, err
	}
	var created OriginRuleset
	if err := json.Unmarshal(resp.Result, &created); err != nil {
		return nil, err
	}
	return &created, nil
}

func (c *Client) UpdateOriginRuleset(zoneID, rulesetID string, ruleset *OriginRuleset) (*OriginRuleset, error) {
	resp, err := c.doRequest("PUT", fmt.Sprintf("/zones/%s/rulesets/%s", zoneID, rulesetID), ruleset)
	if err != nil {
		return nil, err
	}
	var updated OriginRuleset
	if err := json.Unmarshal(resp.Result, &updated); err != nil {
		return nil, err
	}
	return &updated, nil
}

func (c *Client) DeleteOriginRuleset(zoneID, rulesetID string) error {
	_, err := c.doRequest("DELETE", fmt.Sprintf("/zones/%s/rulesets/%s", zoneID, rulesetID), nil)
	return err
}

// SSL/TLS

func (c *Client) GetSSLSettings(zoneID string) (*SSLSetting, error) {
	resp, err := c.doRequest("GET", fmt.Sprintf("/zones/%s/settings/ssl", zoneID), nil)
	if err != nil {
		return nil, err
	}
	var setting SSLSetting
	if err := json.Unmarshal(resp.Result, &setting); err != nil {
		return nil, err
	}
	return &setting, nil
}

func (c *Client) UpdateSSLSettings(zoneID, value string) (*SSLSetting, error) {
	body := map[string]string{"value": value}
	resp, err := c.doRequest("PATCH", fmt.Sprintf("/zones/%s/settings/ssl", zoneID), body)
	if err != nil {
		return nil, err
	}
	var setting SSLSetting
	if err := json.Unmarshal(resp.Result, &setting); err != nil {
		return nil, err
	}
	return &setting, nil
}

// Origin Certificate

type OriginCertificateRequest struct {
	Hostnames         []string `json:"hostnames"`
	RequestedValidity int      `json:"requested_validity"` // 天数，5475 = 15年
	RequestType       string   `json:"request_type"`       // origin-rsa 或 origin-ecc
	CSR               string   `json:"csr"`                // PEM 格式 CSR（必需）
}

type OriginCertificateResponse struct {
	ID          string   `json:"id"`
	Certificate string   `json:"certificate"` // PEM 格式证书
	PrivateKey  string   `json:"private_key"` // PEM 格式私钥（本地生成）
	CSR         string   `json:"csr"`         // PEM 格式 CSR
	Hostnames   []string `json:"hostnames"`
	Issuer      string   `json:"issuer"`
	ExpiresOn   string   `json:"expires_on"`
	RequestType string   `json:"request_type"`
	Status      string   `json:"status"`
}

// GenerateOriginCertificate 生成 Cloudflare Origin 证书
// Cloudflare 的 /certificates 接口需要本地先生成 CSR，返回证书后拼上本地私钥
func (c *Client) GenerateOriginCertificate(hostnames []string, validityDays int) (*OriginCertificateResponse, error) {
	// 生成 RSA 私钥和 CSR
	csrPEM, privateKeyPEM, err := generateCSR(hostnames)
	if err != nil {
		return nil, fmt.Errorf("生成 CSR 失败: %w", err)
	}

	reqBody := OriginCertificateRequest{
		Hostnames:         hostnames,
		RequestedValidity: validityDays,
		RequestType:       "origin-rsa",
		CSR:               csrPEM,
	}

	resp, err := c.doRequest("POST", "/certificates", reqBody)
	if err != nil {
		return nil, err
	}

	var cert OriginCertificateResponse
	if err := json.Unmarshal(resp.Result, &cert); err != nil {
		return nil, err
	}
	// Cloudflare 只返回证书，私钥用本地生成的
	cert.PrivateKey = privateKeyPEM
	cert.CSR = csrPEM
	return &cert, nil
}

// generateCSR 生成 RSA 私钥和 CSR
func generateCSR(hostnames []string) (csrPEM, keyPEM string, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostnames[0],
		},
		DNSNames: hostnames,
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		return "", "", err
	}

	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: derBytes}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
	return csrPEM, keyPEM, nil
}
