package telegram

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Client Telegram 通知客户端
type Client struct {
	botToken string
	chatID   string
	client   *http.Client
}

// NewClient 创建新的 Telegram 客户端
func NewClient(botToken, chatID string) *Client {
	return &Client{
		botToken: botToken,
		chatID:   chatID,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// SendMessage 发送 Telegram 消息
func (c *Client) SendMessage(text string) error {
	if c.botToken == "" || c.chatID == "" {
		return nil // 未配置则跳过
	}

	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", c.botToken)
	data := url.Values{}
	data.Set("chat_id", c.chatID)
	data.Set("text", text)
	data.Set("parse_mode", "HTML")

	resp, err := c.client.PostForm(apiURL, data)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("telegram API error: HTTP %d", resp.StatusCode)
	}

	// Telegram 错误也返回 HTTP 200，需解析 body 中的 ok 字段判断
	var result struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("解析 telegram 响应失败: %w", err)
	}
	if !result.OK {
		return fmt.Errorf("telegram API error: %s", result.Description)
	}
	return nil
}

// IsConfigured 检查是否已配置
func (c *Client) IsConfigured() bool {
	return c.botToken != "" && c.chatID != ""
}
