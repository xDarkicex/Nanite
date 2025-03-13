// Package nanite provides a lightweight, efficient HTTP router with support for middleware,
// WebSockets, static file serving, and a context object with helper methods for common tasks.
package nanite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ### Types and Structs

// HandlerFunc defines a handler function that processes HTTP requests using a Context.
type HandlerFunc func(*Context)

// WebSocketHandler defines a handler function for WebSocket connections.
type WebSocketHandler func(*websocket.Conn, *Context)

// MiddlewareFunc defines a middleware function that wraps handlers or other middleware.
type MiddlewareFunc func(*Context, func())

// Context holds request and response data, route parameters, and user-defined values.
// Fields are designed for reuse via a sync.Pool to minimize allocations.
type Context struct {
	Writer         http.ResponseWriter    // Response writer for sending HTTP responses
	Request        *http.Request          // Incoming HTTP request
	Params         map[string]string      // Route parameters (e.g., ":id")
	Values         map[string]interface{} // User-defined key-value pairs
	ValidationErrs ValidationErrors       // Validation errors from middleware or handlers
	aborted        bool                   // Middleware abortion value
}

// Router manages routes, middleware, and HTTP request handling.
// It uses a trie-based structure and a context pool for efficiency.
type Router struct {
	trees      map[string]*node // Method-specific route trees (e.g., "GET", "POST")
	pool       sync.Pool        // Pool for reusing Context objects
	mutex      sync.RWMutex     // Ensures thread-safe route registration
	middleware []MiddlewareFunc // Global middleware applied to all routes
	config     *Config          // Router configuration options
	httpClient *http.Client     // httpClient field for pooled connections
}

// Config holds router customization options.
type Config struct {
	NotFoundHandler HandlerFunc           // Handler for 404 responses; defaults to http.NotFound
	ErrorHandler    func(*Context, error) // Handler for panics or errors; defaults to 500 response
	Upgrader        *websocket.Upgrader   // WebSocket upgrader; defaults to permissive settings
}

// node represents a segment in the route trie for efficient path matching.
type node struct {
	path       string           // Path segment (e.g., "users", ":id")
	wildcard   bool             // True if this is a wildcard node (e.g., "*")
	handler    HandlerFunc      // Handler for this route
	children   map[string]*node // Child nodes for next segments
	middleware []MiddlewareFunc // Route-specific middleware
}

// ### Validation Types

// ValidationError represents a single validation failure.
type ValidationError struct {
	Field string `json:"field"` // Field name that failed validation
	Error string `json:"error"` // Error message describing the failure
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

// Error implements the error interface, providing a human-readable error string.
func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "validation failed"
	}
	var errs []string
	for _, e := range ve {
		errs = append(errs, fmt.Sprintf("%s: %s", e.Field, e.Error))
	}
	return fmt.Sprintf("validation failed: %s", strings.Join(errs, ", "))
}

// ValidatorFunc defines a validation rule for a field value.
type ValidatorFunc func(string) error

// ValidationChain associates a field with a chain of validation rules.
type ValidationChain struct {
	field string
	rules []ValidatorFunc
}

// NewValidationChain initializes a validation chain for a field.
func NewValidationChain(field string) *ValidationChain {
	return &ValidationChain{field: field}
}

// Required adds a rule ensuring the field is non-empty.
func (vc *ValidationChain) Required() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return fmt.Errorf("field is required")
		}
		return nil
	})
	return vc
}

// IsEmail adds a rule checking for basic email format.
func (vc *ValidationChain) IsEmail() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if !strings.Contains(value, "@") {
			return fmt.Errorf("invalid email format")
		}
		return nil
	})
	return vc
}

// IsInt adds a rule ensuring the field is an integer.
func (vc *ValidationChain) IsInt() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if _, err := strconv.Atoi(value); err != nil {
			return fmt.Errorf("must be an integer")
		}
		return nil
	})
	return vc
}

// ### Router Initialization

// New initializes a Router with default configuration and a context pool.
func New() *Router {
	r := &Router{
		trees: make(map[string]*node),
		config: &Config{
			Upgrader: &websocket.Upgrader{
				CheckOrigin: func(*http.Request) bool { return true },
			},
		},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
	r.pool.New = func() interface{} {
		return &Context{
			Params: make(map[string]string),
			Values: make(map[string]interface{}),
		}
	}
	// Set default config values
	r.config.Upgrader = &websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}
	return r
}

// ### Middleware Support

// Use appends middleware to the router’s global chain.
func (r *Router) Use(middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.middleware = append(r.middleware, middleware...)
}

// Abort is for middleware abort functionality
func (c *Context) Abort() {
	c.aborted = true
}

// IsAborted is a Simple check for abort state
func (c *Context) IsAborted() bool {
	return c.aborted
}

// Add a helper method to the Context
func (c *Context) HTTPClient() *http.Client {
	if client, ok := c.Values["httpClient"].(*http.Client); ok {
		return client
	}
	// Fall back to the router's client
	if router, ok := c.Values["router"].(*Router); ok {
		return router.httpClient
	}
	// Last resort - create a new client
	return http.DefaultClient
}

// ValidationMiddleware validates requests based on provided chains.
// It buffers the request body for reuse, supporting JSON content types.
func ValidationMiddleware(chains ...*ValidationChain) MiddlewareFunc {
	return func(ctx *Context, next func()) {
		var errs ValidationErrors
		if len(chains) > 0 && (ctx.Request.Method == "POST" || ctx.Request.Method == "PUT") {
			contentType := ctx.Request.Header.Get("Content-Type")
			if strings.HasPrefix(contentType, "application/json") {
				bodyBytes, err := io.ReadAll(ctx.Request.Body)
				if err != nil {
					errs = append(errs, ValidationError{Field: "", Error: "failed to read request body"})
				} else {
					// Reset body for subsequent reads
					ctx.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
					var body map[string]interface{}
					if err := json.Unmarshal(bodyBytes, &body); err == nil {
						ctx.Values["body"] = body
					} else {
						errs = append(errs, ValidationError{Field: "", Error: "invalid JSON"})
					}
				}
			}
			// TODO: Support other content types (e.g., form-data) in future enhancements
		}

		for _, chain := range chains {
			value := ""
			if val := ctx.Request.URL.Query().Get(chain.field); val != "" {
				value = val
			} else if val, ok := ctx.Params[chain.field]; ok {
				value = val
			} else if body, ok := ctx.Values["body"].(map[string]interface{}); ok {
				if val, ok := body[chain.field].(string); ok {
					value = val
				}
			}
			for _, rule := range chain.rules {
				if err := rule(value); err != nil {
					errs = append(errs, ValidationError{Field: chain.field, Error: err.Error()})
					break
				}
			}
		}
		if len(errs) > 0 {
			ctx.ValidationErrs = errs
		}
		next()
	}
}

// ### Route Registration

// Get registers a GET route with a handler and optional middleware.
func (r *Router) Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("GET", path, handler, middleware...)
}

// Post registers a POST route with a handler and optional middleware.
func (r *Router) Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("POST", path, handler, middleware...)
}

// Put registers a PUT route with a handler and optional middleware.
func (r *Router) Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("PUT", path, handler, middleware...)
}

// Delete registers a DELETE route with a handler and optional middleware.
func (r *Router) Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("DELETE", path, handler, middleware...)
}

// Patch registers a PATCH route with a handler and optional middleware.
func (r *Router) Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("PATCH", path, handler, middleware...)
}

// Options registers an OPTIONS route with a handler and optional middleware.
func (r *Router) Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("OPTIONS", path, handler, middleware...)
}

// Head registers a HEAD route with a handler and optional middleware.
func (r *Router) Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("HEAD", path, handler, middleware...)
}

// Handle registers a route for a custom HTTP method with a handler and optional middleware.
func (r *Router) Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute(method, path, handler, middleware...)
}

// WebSocket registers a WebSocket endpoint with a handler and optional middleware.
func (r *Router) WebSocket(path string, handler WebSocketHandler, middleware ...MiddlewareFunc) {
	r.addRoute("GET", path, r.wrapWebSocketHandler(handler), middleware...)
}

// ServeStatic serves static files from a directory under a prefix.
func (r *Router) ServeStatic(prefix, root string) {
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	fs := http.FileServer(http.Dir(root))
	handler := func(c *Context) {
		http.StripPrefix(prefix, fs).ServeHTTP(c.Writer, c.Request)
	}
	r.addRoute("GET", prefix+"/*", handler)
	r.addRoute("HEAD", prefix+"/*", handler)
}

// ### Route Grouping

// Group creates a sub-router with a prefix and shared middleware.
func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *Router {
	sub := New()
	sub.middleware = append(sub.middleware, middleware...)
	r.Mount(prefix, sub)
	return sub
}

// Mount attaches a sub-router’s routes under a prefix.
func (r *Router) Mount(prefix string, subRouter *Router) {
	prefix = strings.Trim(prefix, "/")
	parts := strings.Split(prefix, "/")
	for method, tree := range subRouter.trees {
		if _, exists := r.trees[method]; !exists {
			r.trees[method] = &node{children: make(map[string]*node)}
		}
		cur := r.trees[method]
		for _, part := range parts {
			if _, exists := cur.children[part]; !exists {
				cur.children[part] = &node{path: part, children: make(map[string]*node)}
			}
			cur = cur.children[part]
		}
		cur.middleware = subRouter.middleware
		for key, child := range tree.children {
			cur.children[key] = child
		}
	}
}

// ### Routing Logic

// addRoute adds a route to the trie with a handler and middleware.
func (r *Router) addRoute(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if _, exists := r.trees[method]; !exists {
		r.trees[method] = &node{children: make(map[string]*node)}
	}
	cur := r.trees[method]
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for _, part := range parts {
		if strings.HasPrefix(part, ":") {
			if _, exists := cur.children[":"]; !exists {
				cur.children[":"] = &node{path: part, children: make(map[string]*node)}
			}
			cur = cur.children[":"]
		} else if part == "*" {
			cur.wildcard = true
			break
		} else {
			if _, exists := cur.children[part]; !exists {
				cur.children[part] = &node{path: part, children: make(map[string]*node)}
			}
			cur = cur.children[part]
		}
	}
	cur.handler = handler
	cur.middleware = middleware
}

// findHandlerAndMiddleware locates a route’s handler, parameters, and middleware.
func (r *Router) findHandlerAndMiddleware(method, path string) (HandlerFunc, map[string]string, []MiddlewareFunc) {
	middleware := append([]MiddlewareFunc{}, r.middleware...)
	if tree, exists := r.trees[method]; exists {
		parts := strings.Split(strings.Trim(path, "/"), "/")
		cur := tree
		params := make(map[string]string)
		for _, part := range parts {
			if cur.middleware != nil {
				middleware = append(middleware, cur.middleware...)
			}
			if child, exists := cur.children[part]; exists {
				cur = child
			} else if paramChild, exists := cur.children[":"]; exists {
				cur = paramChild
				params[paramChild.path[1:]] = part
			} else if cur.wildcard {
				break
			} else {
				return nil, nil, nil
			}
		}
		if cur.handler != nil {
			if cur.middleware != nil {
				middleware = append(middleware, cur.middleware...)
			}
			return cur.handler, params, middleware
		}
	}
	return nil, nil, nil
}

// ### HTTP Serving

// ServeHTTP handles incoming requests, applying middleware and routing to handlers.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := r.pool.Get().(*Context)
	ctx.Writer = w
	ctx.Request = req
	// Reset fields for reuse
	for k := range ctx.Params {
		delete(ctx.Params, k)
	}
	for k := range ctx.Values {
		delete(ctx.Values, k)
	}
	ctx.ValidationErrs = nil // Clear validation errors to prevent leakage
	ctx.aborted = false      // clear abort state and set to default false

	defer r.pool.Put(ctx)
	handler, params, middleware := r.findHandlerAndMiddleware(req.Method, req.URL.Path)
	if handler == nil {
		if r.config.NotFoundHandler != nil {
			r.config.NotFoundHandler(ctx)
		} else {
			http.NotFound(w, req)
		}
		return
	}
	ctx.Params = params

	wrapped := handler
	for i := len(middleware) - 1; i >= 0; i-- {
		mw := middleware[i]
		next := wrapped
		wrapped = func(c *Context) {
			mw(c, func() { // Check if execution was aborted before calling the next middleware
				// Check if execution was aborted before calling the next middleware
				if !c.IsAborted() {
					next(c)
				}
			})
		}
	}

	defer func() {
		if err := recover(); err != nil {
			if r.config.ErrorHandler != nil {
				r.config.ErrorHandler(ctx, fmt.Errorf("%v", err))
			} else {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}
	}()
	wrapped(ctx)
}

// ### Server Start Methods

// Start runs an HTTP server on the specified port.
func (r *Router) Start(port string) error {
	fmt.Printf("Nanite server running on port %s\n", port)
	return http.ListenAndServe(":"+port, r)
}

// StartTLS runs an HTTPS server with TLS certificates.
func (r *Router) StartTLS(port, certFile, keyFile string) error {
	fmt.Printf("Nanite server running on port %s with TLS\n", port)
	return http.ListenAndServeTLS(":"+port, certFile, keyFile, r)
}

// ### Context Methods - Data Management

// Set stores a value in the context’s Values map.
func (c *Context) Set(key string, value interface{}) {
	if c.Values == nil {
		c.Values = make(map[string]interface{})
	}
	c.Values[key] = value
}

// Get retrieves a value from the context’s Values map.
func (c *Context) Get(key string) interface{} {
	if c.Values != nil {
		return c.Values[key]
	}
	return nil
}

// ### Context Methods - Request Parsing

// Bind decodes the request body into a provided struct, typically JSON.
func (c *Context) Bind(v interface{}) error {
	if err := json.NewDecoder(c.Request.Body).Decode(v); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}
	return nil
}

// FormValue returns a form field value from the request.
func (c *Context) FormValue(key string) string {
	return c.Request.FormValue(key)
}

// Query returns a query parameter value from the request URL.
func (c *Context) Query(key string) string {
	return c.Request.URL.Query().Get(key)
}

// MustParam returns a route parameter, erroring if missing or empty.
func (c *Context) MustParam(key string) (string, error) {
	if val, ok := c.Params[key]; ok && val != "" {
		return val, nil
	}
	return "", fmt.Errorf("required parameter %s missing or empty", key)
}

// File retrieves an uploaded file from a multipart form.
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

// ### Context Methods - Response Handling

// JSON sends a JSON response with a status code.
func (c *Context) JSON(status int, data interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
		http.Error(c.Writer, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

// String sends a plain text response with a status code.
func (c *Context) String(status int, data string) {
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(data))
}

// HTML sends an HTML response with a status code.
func (c *Context) HTML(status int, html string) {
	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(html))
}

// SetHeader sets a response header.
func (c *Context) SetHeader(key, value string) {
	c.Writer.Header().Set(key, value)
}

// Status sets the response status code without a body.
func (c *Context) Status(status int) {
	c.Writer.WriteHeader(status)
}

// Redirect sends a redirect response with a status code and URL.
func (c *Context) Redirect(status int, url string) {
	if status < 300 || status > 399 {
		c.String(http.StatusBadRequest, "redirect status must be 3xx")
		return
	}
	c.Writer.Header().Set("Location", url)
	c.Writer.WriteHeader(status)
}

// Cookie sets a response cookie with optional attributes.
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

// ### Context Methods - Validation

// CheckValidation sends a 400 response if validation errors exist.
func (c *Context) CheckValidation() bool {
	if len(c.ValidationErrs) > 0 {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"errors": c.ValidationErrs})
		return false
	}
	return true
}

// ### WebSocket Support

// wrapWebSocketHandler converts a WebSocketHandler to a HandlerFunc.
func (r *Router) wrapWebSocketHandler(handler WebSocketHandler) HandlerFunc {
	return func(ctx *Context) {
		conn, err := r.config.Upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
		if err != nil {
			http.Error(ctx.Writer, "Failed to upgrade to WebSocket", http.StatusBadRequest)
			return
		}
		defer conn.Close()
		handler(conn, ctx)
	}
}
