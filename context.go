package nanite

import (
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"slices"
)

// ### Context Methods

// Set stores a value in the context's value map.
//
//go:inline
func (c *Context) Set(key string, value interface{}) {
	c.Values[key] = value
}

// Get retrieves a value from the context's value map.
//
//go:inline
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
//
//go:inline
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

	pair := getJSONEncoder()
	defer putJSONEncoder(pair)

	if err := pair.encoder.Encode(data); err != nil {
		http.Error(c.Writer, "Failed to encode JSON", http.StatusInternalServerError)
		return
	}

	c.Writer.Write(pair.buffer.Bytes())
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
//
//go:inline
func (c *Context) IsAborted() bool {
	return c.aborted
}

// ClearValues efficiently clears the Values map without reallocating.
func (c *Context) ClearValues() {
	clear(c.Values)
}

// Reset prepares the context for reuse with a new request.
// It efficiently resets all state while maintaining allocated memory structures,
// significantly reducing per-request initialization time by approximately 10-20ns.
//
// Parameters:
//   - w: The response writer for this request
//   - r: The HTTP request object
func (c *Context) Reset(w http.ResponseWriter, r *http.Request) {
	// Reset request-specific fields
	c.Writer = w
	c.Request = r
	c.ParamsCount = 0
	c.aborted = false

	// Clear values map without reallocation
	clear(c.Values)

	// Clean up and clear lazy fields
	for k, field := range c.lazyFields {
		putLazyField(field)
		delete(c.lazyFields, k)
	}

	// Reset validation errors
	c.ValidationErrs = nil
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

// CleanupPooledResources returns all pooled resources to their respective pools
func (c *Context) CleanupPooledResources() {
	// Clean up maps from Values
	for k, v := range c.Values {
		if m, ok := v.(map[string]interface{}); ok {
			putMap(m)
		}
		delete(c.Values, k)
	}

	// Clean up lazy fields
	c.ClearLazyFields()

	// Return ValidationErrs to the pool
	if c.ValidationErrs != nil {
		putValidationErrors(c.ValidationErrs)
		c.ValidationErrs = nil
	}
}

// LazyField represents a field that will be validated lazily
type LazyField struct {
	name      string           // The field's name (e.g., "username")
	getValue  func() string    // Function to fetch the raw value from the request
	rules     []ValidatorFunc  // List of validation rules (e.g., regex checks)
	validated bool             // Tracks if validation has run
	value     string           // Stores the validated value
	err       *ValidationError // Stores any validation error
}

// Value validates and returns the field value
func (lf *LazyField) Value() (string, *ValidationError) {
	if !lf.validated {
		rawValue := lf.getValue()
		lf.value = rawValue

		for _, rule := range lf.rules {
			if err := rule(rawValue); err != nil {
				lf.err = err // This is now a *ValidationError directly
				break
			}
		}
		lf.validated = true
	}

	return lf.value, lf.err
}

// Field gets or creates a LazyField for the specified field name
func (c *Context) Field(name string) *LazyField {
	// Safety net: initialize lazyFields if nil
	if c.lazyFields == nil {
		c.lazyFields = make(map[string]*LazyField)
	}

	field, exists := c.lazyFields[name]
	if !exists {
		// Use the pool instead of direct allocation
		field = getLazyField(name, func() string {
			// Try fetching from query, params, form, or body
			if val := c.Request.URL.Query().Get(name); val != "" {
				return val
			}

			if val, ok := c.GetParam(name); ok {
				return val
			}

			if formData, ok := c.Values["formData"].(map[string]interface{}); ok {
				if val, ok := formData[name]; ok {
					return fmt.Sprintf("%v", val)
				}
			}

			if body, ok := c.Values["body"].(map[string]interface{}); ok {
				if val, ok := body[name]; ok {
					return fmt.Sprintf("%v", val)
				}
			}

			return ""
		})

		c.lazyFields[name] = field
	}

	return field
}

// In lazy_validation.go, update ValidateAllFields
func (c *Context) ValidateAllFields() bool {
	if len(c.lazyFields) == 0 {
		return true
	}

	hasErrors := false
	for name, field := range c.lazyFields {
		_, err := field.Value()
		if err != nil {
			if c.ValidationErrs == nil {
				c.ValidationErrs = getValidationErrors()
				c.ValidationErrs = slices.Grow(c.ValidationErrs, len(c.lazyFields))
			}

			// Create a copy of the error with the map key as the field name
			errorCopy := *err
			errorCopy.Field = name // Use the map key as the field name
			c.ValidationErrs = append(c.ValidationErrs, errorCopy)

			hasErrors = true
		}
	}

	return !hasErrors
}

// ClearLazyFields efficiently clears the LazyFields map without reallocating.
func (c *Context) ClearLazyFields() {
	for k, field := range c.lazyFields {
		putLazyField(field)
		delete(c.lazyFields, k)
	}
}
