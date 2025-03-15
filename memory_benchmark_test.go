package nanite

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkMemoryUsage(b *testing.B) {
	// Create a new router
	r := New()
	
	// Add some routes to test
	r.Get("/users/:id", func(c *Context) {
		id, _ := c.GetParam("id")
		c.JSON(200, map[string]string{"id": id})
	})
	
	r.Post("/users", func(c *Context) {
		var user struct {
			Name string `json:"name"`
		}
		
		if err := c.Bind(&user); err != nil {
			c.Status(400)
			return
		}
		
		c.JSON(201, user)
	})
	
	// Run the benchmark
	b.ReportAllocs()
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		// Test GET request
		req, _ := http.NewRequest("GET", "/users/123", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		
		// Test POST request
		req, _ = http.NewRequest("POST", "/users", bytes.NewBuffer([]byte(`{"name": "test"}`)))
		req.Header.Set("Content-Type", "application/json")
		rec = httptest.NewRecorder()
		r.ServeHTTP(rec, req)
	}
}
