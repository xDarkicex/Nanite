package nanite

import (
	"testing"
	"net/http"
	"net/http/httptest"
	"bytes"
	"github.com/stretchr/testify/assert"
	"github.com/gorilla/websocket"
	"fmt"
	"strconv"
)

func BenchmarkRouter(b *testing.B) {
	r := New()

	// Add various routes
	r.Get("/users", func(c *Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "Get users"})
	})

	r.Get("/users/:id", func(c *Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "Get user"})
	})

	r.Post("/users", func(c *Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "Create user"})
	})

	// Run benchmark
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/users/123", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(b, http.StatusOK, rec.Code)
	}
}

func BenchmarkWebSocket(b *testing.B) {
	r := New()

	// Add WebSocket route
	r.WebSocket("/ws", func(ws *websocket.Conn, c *Context) {
		for {
			msgType, msg, err := ws.ReadMessage()
			if err != nil {
				break
			}
			ws.WriteMessage(msgType, msg)
		}
	})

	// Run benchmark
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/ws", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
	}
}

func BenchmarkValidation(b *testing.B) {
	r := New()

	// Add validation middleware
	r.Use(ValidationMiddleware(
		NewValidationChain("name").Required().Custom(func(value string) error {
			if value == "" {
				return fmt.Errorf("name is required")
			}
			return nil
		}),
		NewValidationChain("age").Required().Custom(func(value string) error {
			if value == "" {
				return fmt.Errorf("age is required")
			}
			if _, err := strconv.Atoi(value); err != nil {
				return fmt.Errorf("age must be an integer")
			}
			return nil
		}),
	))

	// Add route
	r.Post("/users", func(c *Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "Create user"})
	})

	// Run benchmark
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("POST", "/users", bytes.NewBufferString(`{"name":"John","age":"30"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(b, http.StatusOK, rec.Code)
	}
}
