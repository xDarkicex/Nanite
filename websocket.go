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
			// Cancel context to signal all goroutines to stop
			cancel()

			// Close the connection
			conn.Close()

			// Wait for all goroutines to finish
			wg.Wait()

			// Clean up any pooled objects
			ctx.CleanupPooledResources()
		}

		defer cleanup()

		// Set up ping handler for connection keepalive
		conn.SetPongHandler(func(string) error {
			conn.SetReadDeadline(time.Now().Add(r.config.WebSocket.ReadTimeout))
			return nil
		})

		// Start ping goroutine
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

		// Monitor for server shutdown
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

		// Set initial read deadline
		conn.SetReadDeadline(time.Now().Add(r.config.WebSocket.ReadTimeout))

		// Call the actual handler
		handler(conn, ctx)

		// Send normal closure message
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)
	}
}
