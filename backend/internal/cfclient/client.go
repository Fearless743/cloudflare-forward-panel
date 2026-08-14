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

	// 调试日志：只显示 api key 前缀，避免泄露完整密钥
	keyPrefix := c.apiKey
	if len(keyPrefix) > 4 {
		keyPrefix = keyPrefix[:4] + "..."
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

// CountOriginRules 返回指定 zone 的 http_request_origin (kind=zone) 规则总数。
// 一个 zone 可能有多个 zone 级 http_request_origin ruleset（rare），把每个 ruleset 内的规则数求和。
// 统计的是 CF 侧真实存在的规则（含面板外手工创建、含禁用规则），
// 供「按 CF 规则数最少选域名」的策略使用。
func (c *Client) CountOriginRules(zoneID string) (int, error) {
	rulesets, err := c.ListOriginRulesets(zoneID)
	if err != nil {
		return 0, err
	}
	total := 0
	for i := range rulesets {
		rulesetID := rulesets[i].ID
		if rulesetID == "" {
			continue
		}
		full, err := c.GetOriginRuleset(zoneID, rulesetID)
		if err != nil {
			// 单个 ruleset 拉取失败不阻塞整体计数（该 zone 视为 0，调用方按最少选择仍可兜底）
			continue
		}
		total += len(full.Rules)
	}
	return total, nil
}

// DisableOriginRule 停用 ruleset 中的所有规则（封禁账号时尽力停用 CF 侧规则）
// 失败返回错误，调用方自行决定是否忽略
func (c *Client) DisableOriginRule(zoneID, rulesetID string) error {
	ruleset, err := c.GetOriginRuleset(zoneID, rulesetID)
	if err != nil {
		return err
	}
	for i := range ruleset.Rules {
		ruleset.Rules[i].Enabled = false
	}
	_, err = c.UpdateOriginRuleset(zoneID, rulesetID, ruleset)
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

// EnableWebSockets 开启域名的 WebSockets 支持（转发 TCP/WS 流量需要）
func (c *Client) EnableWebSockets(zoneID string) error {
	body := map[string]string{"value": "on"}
	_, err := c.doRequest("PATCH", fmt.Sprintf("/zones/%s/settings/websockets", zoneID), body)
	return err
}

// EnableGRPC 开启域名的 gRPC 支持（转发 gRPC 流量需要）
func (c *Client) EnableGRPC(zoneID string) error {
	body := map[string]string{"value": "on"}
	_, err := c.doRequest("PATCH", fmt.Sprintf("/zones/%s/settings/grpc", zoneID), body)
	return err
}

// Analytics（GraphQL Analytics API）

// GraphQLRequest GraphQL 请求体
type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables,omitempty"`
}

// GraphQLResponse GraphQL 响应体（与 REST 的 CFResponse 结构不同）
type GraphQLResponse struct {
	Data   json.RawMessage `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors,omitempty"`
}

// ZoneHTTPMetrics httpRequestsAdaptiveGroups 聚合结果（一行 = 一个时间桶）
// Dimensions 含分钟/小时两档粒度与 hostname（ByZone 分组查询时填充）。
type ZoneHTTPMetrics struct {
	Sum struct {
		Requests          int64 `json:"requests"`
		EdgeResponseBytes int64 `json:"edgeResponseBytes"`
		Visits            int64 `json:"visits"`
	} `json:"sum"`
	Uniq struct {
		Uniques int64 `json:"uniques"`
	} `json:"uniq"`
	Dimensions struct {
		DatetimeMinute       string `json:"datetimeMinute"`
		DatetimeHour         string `json:"datetimeHour"`
		ClientRequestHTTPHost string `json:"clientRequestHTTPHost"`
	} `json:"dimensions"`
}

// TimeKey 返回该行的聚合时间桶标识（分钟或小时），用于 timeseries
func (m *ZoneHTTPMetrics) TimeKey() string {
	if m.Dimensions.DatetimeMinute != "" {
		return m.Dimensions.DatetimeMinute
	}
	return m.Dimensions.DatetimeHour
}

// quoteGraphQLString 把字符串转义为合法的 GraphQL 字符串字面量（含引号）。
// JSON 转义子集兼容 GraphQL 字符串语法（\" \\ \uXXXX 等）。
func quoteGraphQLString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// doGraphQL 发送 GraphQL 请求并返回 data 字段原文。
// GraphQL 端点与 REST 使用相同的 X-Auth-Key/X-Auth-Email 认证头，但响应结构为
// {data, errors} 而非 {success, result}，因此单独实现请求与解析（不复用 doRequest）。
func (c *Client) doGraphQL(query string) (json.RawMessage, error) {
	body := GraphQLRequest{Query: query}
	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal graphql request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, baseURL+"/graphql", bytes.NewReader(jsonBytes))
	if err != nil {
		return nil, fmt.Errorf("create graphql request: %w", err)
	}

	log.Printf("[CF API] POST /graphql (analytics)")
	req.Header.Set("Content-Type", "application/json")
	c.setAuthHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do graphql request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read graphql body: %w", err)
	}

	// GraphQL 鉴权失败等错误没有 rest 的 success 字段，直接看 HTTP 状态码
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cloudflare graphql error: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	var gql GraphQLResponse
	if err := json.Unmarshal(respBody, &gql); err != nil {
		return nil, fmt.Errorf("unmarshal graphql response: %w", err)
	}
	if len(gql.Errors) > 0 {
		msgs := make([]string, 0, len(gql.Errors))
		for _, e := range gql.Errors {
			msgs = append(msgs, e.Message)
		}
		return nil, fmt.Errorf("cloudflare graphql error: %s", strings.Join(msgs, "; "))
	}
	return gql.Data, nil
}

// analyticsGrain 根据时间窗口选择聚合粒度，保证行数不超过 CF 的 limit=10000 上限：
//   - ≤26h（对应 range=24h）：分钟级，1440 行
//   - 更长（7d/30d）：小时级，168/720 行
// 分钟级 30d = 43200 行会触发 CF 截断，导致 metrics 聚合值错误，故长窗口降为小时级。
func analyticsGrain(geq, lt time.Time) (dimension, orderBy string) {
	if lt.Sub(geq) <= 26*time.Hour {
		return "datetimeMinute", "datetimeMinute_ASC"
	}
	return "datetimeHour", "datetimeHour_ASC"
}

// queryZoneMetrics 查询 zone 下 hostname 的 HTTP 请求流量指标。
// timeRange [geq, lt)；该 hostname 无流量时返回空列表而非错误（调用方降级为零值）。
// groupByHost 为 true 时不按 hostname 过滤，改为在 dimensions 中返回
// clientRequestHTTPHost，一次查询取回 zone 内所有 hostname 的数据（缓存回填优化用）。
func (c *Client) queryZoneMetrics(zoneID, hostname string, geq, lt time.Time, groupByHost bool) ([]ZoneHTTPMetrics, error) {
	dimension, orderBy := analyticsGrain(geq, lt)

	hostFilter := ""
	if !groupByHost {
		hostFilter = ", clientRequestHTTPHost: " + quoteGraphQLString(hostname)
	}
	dimensions := dimension
	if groupByHost {
		dimensions += " clientRequestHTTPHost"
	}

	query := fmt.Sprintf(`query ZoneHTTPMetrics {
  viewer {
    zones(filter: {zoneTag: %s}) {
      httpRequestsAdaptiveGroups(
        limit: 10000
        filter: {datetime_geq: %s, datetime_lt: %s%s, requestSource: "eyeball"}
        orderBy: [%s]
      ) {
        sum { requests edgeResponseBytes visits }
        uniq { uniques }
        dimensions { %s }
      }
    }
  }
}`,
		quoteGraphQLString(zoneID),
		quoteGraphQLString(geq.UTC().Format(time.RFC3339)),
		quoteGraphQLString(lt.UTC().Format(time.RFC3339)),
		hostFilter,
		orderBy,
		dimensions,
	)

	data, err := c.doGraphQL(query)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Viewer struct {
			Zones []struct {
				HTTPRequestsAdaptiveGroups []ZoneHTTPMetrics `json:"httpRequestsAdaptiveGroups"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse graphql data: %w", err)
	}
	if len(parsed.Viewer.Zones) == 0 {
		// zoneTag 无效或 zone 无数据
		return nil, nil
	}
	return parsed.Viewer.Zones[0].HTTPRequestsAdaptiveGroups, nil
}

// QueryZoneHTTPMetrics 查询指定 zone 下某个 hostname 的 HTTP 请求流量指标。
// 时间范围 [geq, lt)；按窗口自适应分钟/小时粒度，返回聚合桶列表。
func (c *Client) QueryZoneHTTPMetrics(zoneID, hostname string, geq, lt time.Time) ([]ZoneHTTPMetrics, error) {
	return c.queryZoneMetrics(zoneID, hostname, geq, lt, false)
}

// QueryZoneHTTPMetricsByZone 一次 GraphQL 请求取回 zone 下所有 hostname 的流量指标，
// 按 hostname 分组返回（dimensions 含 clientRequestHTTPHost）。
// 供「同一 zone 的多个转发规则合并为一次查询」的缓存回填优化使用。
// 注意：同一窗口下行数 = hostname 数 × 时间桶数，受 limit 10000 限制，
// 大量 hostname 时可能截断，调用方应自行控制（面板场景 zone 内 hostname 极少）。
func (c *Client) QueryZoneHTTPMetricsByZone(zoneID string, geq, lt time.Time) (map[string][]ZoneHTTPMetrics, error) {
	rows, err := c.queryZoneMetrics(zoneID, "", geq, lt, true)
	if err != nil {
		return nil, err
	}
	result := make(map[string][]ZoneHTTPMetrics)
	for _, row := range rows {
		host := row.Dimensions.ClientRequestHTTPHost
		if host == "" {
			continue
		}
		result[host] = append(result[host], row)
	}
	return result, nil
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
