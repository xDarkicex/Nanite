package nanite

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRouterBasicRouting(t *testing.T) {
	r := New()
	handler := func(c *Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "hello"})
	}

	r.Get("/hello", handler)
	r.Post("/hello", handler)

	// Test GET request
	req, _ := http.NewRequest("GET", "/hello", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Test POST request
	req, _ = http.NewRequest("POST", "/hello", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestRouterParameterRouting(t *testing.T) {
	r := New()
	handler := func(c *Context) {
		value, _ := c.GetParam("id")
		c.JSON(http.StatusOK, map[string]string{"id": value})
	}

	r.Get("/users/:id", handler)

	// Test with parameter
	req, _ := http.NewRequest("GET", "/users/123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if response["id"] != "123" {
		t.Errorf("Expected id 123, got %s", response["id"])
	}
}

func TestRouterWildcardRouting(t *testing.T) {
	r := New()
	handler := func(c *Context) {
		value, _ := c.GetParam("path")
		c.JSON(http.StatusOK, map[string]string{"path": value})
	}

	r.Get("/files/*path", handler)

	// Test with wildcard
	req, _ := http.NewRequest("GET", "/files/documents/report.pdf", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode response: %v", err)
	}

	if response["path"] != "documents/report.pdf" {
		t.Errorf("Expected path documents/report.pdf, got %s", response["path"])
	}
}

func TestRouterMiddleware(t *testing.T) {
	r := New()

	// Middleware that adds a value to context
	middleware := func(c *Context, next func()) {
		c.Values["middleware"] = true
		next()
	}

	handler := func(c *Context) {
		if _, exists := c.Values["middleware"]; !exists {
			c.JSON(http.StatusInternalServerError, map[string]string{"error": "middleware not called"})
			return
		}
		c.JSON(http.StatusOK, map[string]string{"message": "success"})
	}

	r.Use(middleware)
	r.Get("/middleware", handler)

	req, _ := http.NewRequest("GET", "/middleware", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestRouterNotFound(t *testing.T) {
	r := New()
	handler := func(c *Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "hello"})
	}

	r.Get("/hello", handler)

	// Test non-existent route
	req, _ := http.NewRequest("GET", "/nonexistent", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}
