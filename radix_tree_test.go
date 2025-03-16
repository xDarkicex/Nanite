package nanite

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRadixTreeParamsAndWildcards(t *testing.T) {
	// Create a new router
	r := New()

	// Test parameter routing
	r.Get("/users/:id", func(c *Context) {
		id, _ := c.GetParam("id")
		c.JSON(http.StatusOK, map[string]string{"id": id})
	})

	// Test wildcard routing
	r.Get("/files/*path", func(c *Context) {
		path, _ := c.GetParam("path")
		c.JSON(http.StatusOK, map[string]string{"path": path})
	})

	// Test combined parameter and wildcard
	r.Get("/api/:version/*path", func(c *Context) {
		version, _ := c.GetParam("version")
		path, _ := c.GetParam("path")
		c.JSON(http.StatusOK, map[string]string{
			"version": version,
			"path":    path,
		})
	})

	// Test server
	server := httptest.NewServer(r)
	defer server.Close()

	// Test parameter routing
	{
		resp, err := http.Get(server.URL + "/users/123")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close() // Important: close the response body

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		var result map[string]string
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if result["id"] != "123" {
			t.Errorf("Expected id 123, got %s", result["id"])
		}
	}

	// Test wildcard routing
	{
		resp, err := http.Get(server.URL + "/files/documents/report.pdf")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		var result map[string]string
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if result["path"] != "documents/report.pdf" {
			t.Errorf("Expected path documents/report.pdf, got %s", result["path"])
		}
	}

	// Test combined parameter and wildcard
	{
		resp, err := http.Get(server.URL + "/api/v1/users/123")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		var result map[string]string
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if result["version"] != "v1" {
			t.Errorf("Expected version v1, got %s", result["version"])
		}
		if result["path"] != "users/123" {
			t.Errorf("Expected path users/123, got %s", result["path"])
		}
	}

	// Test nested routes with segments after parameters
	{
		r.Get("/nested/:param/extra", func(c *Context) {
			param, _ := c.GetParam("param")
			c.JSON(http.StatusOK, map[string]string{"param": param})
		})

		resp, err := http.Get(server.URL + "/nested/value/extra")
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		var result map[string]string
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatalf("Failed to unmarshal response: %v", err)
		}

		if result["param"] != "value" {
			t.Errorf("Expected param value, got %s", result["param"])
		}
	}
}
