//go:build web

package ws

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // 允许所有来源（本地工具）
	},
}

// MessageType WebSocket消息类型
type MessageType string

const (
	// 扫描相关
	MsgScanStarted   MessageType = "scan_started"
	MsgScanProgress  MessageType = "scan_progress"
	MsgScanResult    MessageType = "scan_result"
	MsgScanCompleted MessageType = "scan_completed"
	MsgScanError     MessageType = "scan_error"

	// 系统相关
	MsgConnected MessageType = "connected"
	MsgPing      MessageType = "ping"
	MsgPong      MessageType = "pong"
)

// Message WebSocket消息结构
type Message struct {
	Type      MessageType `json:"type"`
	Timestamp int64       `json:"timestamp"`
	Data      interface{} `json:"data,omitempty"`
}

// Client WebSocket客户端
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// Hub 管理所有WebSocket连接
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// NewHub 创建Hub实例
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run 启动Hub
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()

			// 发送连接成功消息
			msg := Message{
				Type:      MsgConnected,
				Timestamp: time.Now().UnixMilli(),
				Data:      map[string]string{"status": "connected"},
			}
			if data, err := json.Marshal(msg); err == nil {
				client.send <- data
			}

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

// Broadcast 广播消息给所有客户端
func (h *Hub) Broadcast(msgType MessageType, data interface{}) {
	msg := Message{
		Type:      msgType,
		Timestamp: time.Now().UnixMilli(),
		Data:      data,
	}
	if jsonData, err := json.Marshal(msg); err == nil {
		h.broadcast <- jsonData
	}
}

// ClientCount 返回当前连接的客户端数量
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// ServeWs 处理WebSocket连接
func ServeWs(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	client := &Client{
		hub:  hub,
		conn: conn,
		send: make(chan []byte, 256),
	}
	hub.register <- client

	go client.writePump()
	go client.readPump()
}

// readPump 读取客户端消息
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512 * 1024) // 512KB
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}

		// 处理ping消息
		var msg Message
		if json.Unmarshal(message, &msg) == nil {
			if msg.Type == MsgPing {
				pong := Message{
					Type:      MsgPong,
					Timestamp: time.Now().UnixMilli(),
				}
				if data, err := json.Marshal(pong); err == nil {
					c.send <- data
				}
			}
		}
	}
}

// writePump 发送消息给客户端
func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
