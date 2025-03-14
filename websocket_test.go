package nanite

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

func TestWebSocketHandler(t *testing.T) {
	r := New() // Assuming this sets up your router

	// Define the WebSocket handler
	handler := func(conn *websocket.Conn, c *Context) {
		defer conn.Close() // Ensure the connection is closed when the handler exits
		for {
			// Read a message from the client
			_, message, err := conn.ReadMessage()
			if err != nil {
				// Handle normal closure cases
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					break // Exit cleanly on normal closure
				}
				// Log unexpected errors and exit
				t.Errorf("Unexpected error reading message: %v", err)
				break
			}
			// Echo the message back to the client
			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
				t.Errorf("Error writing message: %v", err)
				break
			}
		}
	}

	// Register the WebSocket route
	r.WebSocket("/ws", handler)

	// Rest of your test setup (e.g., starting the server, connecting the client, etc.)
	// For example:
	server := httptest.NewServer(r)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to connect to WebSocket: %v", err)
	}
	defer conn.Close()

	// Send a test message
	err = conn.WriteMessage(websocket.TextMessage, []byte("hello"))
	if err != nil {
		t.Fatalf("Failed to send message: %v", err)
	}

	// Read the response
	_, response, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	// Verify the echo
	if string(response) != "hello" {
		t.Errorf("Expected 'hello', got '%s'", string(response))
	}

	// Close the connection cleanly
	conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}
