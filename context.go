package nanite

import (
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
)

// ### Context Methods

// Set stores a value in the context's value map.
func (c *Context) Set(key string, value interface{}) {
	c.Values[key] = value
}

// Get retrieves a value from the context's value map.
func (c *Context) Get(key string) interface{} {
	if c.Values != nil {
		return c.Values[key]
	}
	return nil
}

// Bind decodes the request body into the provided interface.
func (c *Context) Bind(v interface{}) error {
	if err := json.NewDecoder(c.Request.Body).Decode(v); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}
	return nil
}

// FormValue returns the value of the specified form field.
func (c *Context) FormValue(key string) string {
	return c.Request.FormValue(key)
}

// Query returns the value of the specified query parameter.
func (c *Context) Query(key string) string {
	return c.Request.URL.Query().Get(key)
}

// GetParam retrieves a route parameter by key, including wildcard (*).
func (c *Context) GetParam(key string) (string, bool) {
	for i := 0; i < c.ParamsCount; i++ {
		if c.Params[i].Key == key {
			return c.Params[i].Value, true
		}
	}
	return "", false
}

// MustParam retrieves a required route parameter or returns an error.
func (c *Context) MustParam(key string) (string, error) {
	if val, ok := c.GetParam(key); ok && val != "" {
		return val, nil
	}
	return "", fmt.Errorf("required parameter %s missing or empty", key)
}

// File retrieves a file from the request's multipart form.
func (c *Context) File(key string) (*multipart.FileHeader, error) {
	if c.Request.MultipartForm == nil {
		if err := c.Request.ParseMultipartForm(32 << 20); err != nil {
			return nil, fmt.Errorf("failed to parse multipart form: %w", err)
		}
	}
	_, fh, err := c.Request.FormFile(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get file %s: %w", key, err)
	}
	return fh, nil
}

// JSON sends a JSON response with the specified status code.
func (c *Context) JSON(status int, data interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
		http.Error(c.Writer, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

// String sends a plain text response with the specified status code.
func (c *Context) String(status int, data string) {
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(data))
}

// HTML sends an HTML response with the specified status code.
func (c *Context) HTML(status int, html string) {
	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(html))
}

// SetHeader sets a header on the response writer.
func (c *Context) SetHeader(key, value string) {
	c.Writer.Header().Set(key, value)
}

// Status sets the response status code.
func (c *Context) Status(status int) {
	c.Writer.WriteHeader(status)
}

// Redirect sends a redirect response to the specified URL.
func (c *Context) Redirect(status int, url string) {
	if status < 300 || status > 399 {
		c.String(http.StatusBadRequest, "redirect status must be 3xx")
		return
	}
	c.Writer.Header().Set("Location", url)
	c.Writer.WriteHeader(status)
}

// Cookie sets a cookie on the response.
func (c *Context) Cookie(name, value string, options ...interface{}) {
	cookie := &http.Cookie{Name: name, Value: value}
	for i := 0; i < len(options)-1; i += 2 {
		if key, ok := options[i].(string); ok {
			switch key {
			case "MaxAge":
				if val, ok := options[i+1].(int); ok {
					cookie.MaxAge = val
				}
			case "Path":
				if val, ok := options[i+1].(string); ok {
					cookie.Path = val
				}
			}
		}
	}
	http.SetCookie(c.Writer, cookie)
}

// Abort marks the request as aborted, preventing further processing.
func (c *Context) Abort() {
	c.aborted = true
}

// IsAborted checks if the request has been aborted.
func (c *Context) IsAborted() bool {
	return c.aborted
}

// ClearValues efficiently clears the Values map without reallocating.
func (c *Context) ClearValues() {
	for k := range c.Values {
		delete(c.Values, k)
	}
}

// CheckValidation validates all lazy fields and returns true if validation passed
func (c *Context) CheckValidation() bool {
	// First validate all lazy fields
	fieldsValid := c.ValidateAllFields()

	// Check if we have any validation errors
	if len(c.ValidationErrs) > 0 {
		c.JSON(http.StatusBadRequest, map[string]interface{}{
			"errors": c.ValidationErrs,
		})
		return false
	}

	return fieldsValid
}
