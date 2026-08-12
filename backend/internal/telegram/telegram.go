package telegram

import (
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
		return fmt.Errorf("telegram API error: %d", resp.StatusCode)
	}
	return nil
}

// IsConfigured 检查是否已配置
func (c *Client) IsConfigured() bool {
	return c.botToken != "" && c.chatID != ""
}
