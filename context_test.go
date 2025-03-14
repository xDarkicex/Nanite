package nanite

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestContextParams(t *testing.T) {
	r := New()
	handler := func(c *Context) {
		id, exists := c.GetParam("id")
		if !exists {
			t.Errorf("Expected parameter 'id' to exist")
		}
		if id != "123" {
			t.Errorf("Expected parameter 'id' to be '123', got '%s'", id)
		}
		c.JSON(http.StatusOK, map[string]string{"id": id})
	}

	r.Get("/users/:id", handler)

	req, _ := http.NewRequest("GET", "/users/123", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestContextValues(t *testing.T) {
	r := New()
	handler := func(c *Context) {
		c.Values["test"] = "value"
		if c.Values["test"] != "value" {
			t.Errorf("Expected value 'value', got '%v'", c.Values["test"])
		}
		c.JSON(http.StatusOK, map[string]string{"test": "value"})
	}

	r.Get("/test", handler)

	req, _ := http.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}

func TestContextAborted(t *testing.T) {
	r := New()

	// Middleware that aborts the request
	middleware := func(c *Context, next func()) {
		c.Abort()
		next()
	}

	handler := func(c *Context) {
		if !c.IsAborted() {
			t.Errorf("Expected context to be aborted")
		}
		c.JSON(http.StatusOK, map[string]string{"message": "should not reach here"})
	}

	r.Use(middleware)
	r.Get("/test", handler)

	req, _ := http.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", rec.Code)
	}
}

func TestContextClearValues(t *testing.T) {
	r := New()
	handler := func(c *Context) {
		c.Values["test"] = "value"
		c.ClearValues()
		if len(c.Values) != 0 {
			t.Errorf("Expected values to be cleared, got %v", c.Values)
		}
		c.JSON(http.StatusOK, map[string]string{"message": "success"})
	}

	r.Get("/test", handler)

	req, _ := http.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}
}
