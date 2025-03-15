package nanite

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ### WebSocket Wrapper

// wrapWebSocketHandler wraps a WebSocketHandler into a HandlerFunc.
func (r *Router) wrapWebSocketHandler(handler WebSocketHandler) HandlerFunc {
	return func(ctx *Context) {
		conn, err := r.config.Upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
		if err != nil {
			http.Error(ctx.Writer, "Failed to upgrade to WebSocket", http.StatusBadRequest)
			return
		}

		conn.SetReadLimit(r.config.WebSocket.MaxMessageSize)
		wsCtx, cancel := context.WithCancel(context.Background())
		defer cancel()

		var wg sync.WaitGroup

		cleanup := func() {
			cancel()
			conn.Close()
			wg.Wait()
		}
		defer cleanup()

		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(r.config.WebSocket.ReadTimeout))
			return nil
		})

		wg.Add(1)
		go func() {
			defer wg.Done()
			pingTicker := time.NewTicker(r.config.WebSocket.PingInterval)
			defer pingTicker.Stop()

			for {
				select {
				case <-pingTicker.C:
					conn.SetWriteDeadline(time.Now().Add(r.config.WebSocket.WriteTimeout))
					if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
						return
					}
				case <-wsCtx.Done():
					return
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Request.Context().Done():
				conn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseGoingAway, "Server shutting down"),
					time.Now().Add(time.Second),
				)
			case <-wsCtx.Done():
			}
		}()

		conn.SetReadDeadline(time.Now().Add(r.config.WebSocket.ReadTimeout))
		handler(conn, ctx)

		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)
	}
}
