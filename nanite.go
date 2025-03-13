// Package nanite provides a lightweight, efficient HTTP router with support for middleware,
// WebSockets, static file serving, and a context object with helper methods for common tasks.
package nanite

import (
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// ### Types and Structs

// HandlerFunc defines a handler function that processes HTTP requests using a Context.
// It takes a pointer to Context, providing access to request/response data and utilities.
type HandlerFunc func(*Context)

// WebSocketHandler defines a handler function for WebSocket connections.
// It receives a WebSocket connection and the request Context for processing.
type WebSocketHandler func(*websocket.Conn, *Context)

// MiddlewareFunc defines a middleware function that can process requests before or after the handler.
// It takes a Context and a "next" function to continue the middleware chain.
type MiddlewareFunc func(*Context, func())

// Context holds request and response data, along with route parameters and user-defined values.
// It serves as the central object passed through handlers and middleware.
type Context struct {
	Writer  http.ResponseWriter    // Response writer for sending HTTP responses
	Request *http.Request          // Incoming HTTP request object
	Params  map[string]string      // Route parameters extracted from the URL (e.g., ":id")
	Values  map[string]interface{} // User-defined key-value pairs (e.g., database connections)
}

// node represents a segment in the route path tree used for efficient route matching.
// It forms part of a trie-like structure for storing and retrieving routes.
type node struct {
	path       string           // Path segment (e.g., "users", ":id", "*")
	wildcard   bool             // Indicates if this node is a wildcard (e.g., "*")
	handler    HandlerFunc      // Handler function for this route, if defined
	children   map[string]*node // Child nodes for subsequent path segments
	middleware []MiddlewareFunc // Middleware specific to this route
}

// Config holds configuration options for the router.
// It allows customization of not found behavior, error handling, and WebSocket upgrades.
type Config struct {
	NotFoundHandler HandlerFunc           // Custom handler for 404 Not Found responses
	ErrorHandler    func(*Context, error) // Custom error handler for panics or errors
	Upgrader        *websocket.Upgrader   // Custom WebSocket upgrader for connection upgrades
}

// Router manages routes, middleware, and handles HTTP requests.
// It provides the core functionality for routing and request processing.
type Router struct {
	trees      map[string]*node // Method-specific route trees (e.g., "GET", "POST")
	pool       sync.Pool        // Pool for reusing Context objects to reduce memory allocations
	mutex      sync.RWMutex     // Mutex for thread-safe route registration
	middleware []MiddlewareFunc // Global middleware chain applied to all routes
	config     *Config          // Router configuration options
}

// ### Router Initialization

// New creates and returns a new Router instance with initialized route trees and context pool.
// It sets up default configuration, including a WebSocket upgrader that allows all origins.
func New() *Router {
	r := &Router{
		trees: make(map[string]*node),
		config: &Config{
			NotFoundHandler: nil, // Default is nil; uses http.NotFound if not set
			Upgrader: &websocket.Upgrader{
				CheckOrigin: func(r *http.Request) bool { return true }, // Allows all origins by default
			},
		},
	}
	// Initialize the context pool to reuse Context objects, reducing garbage collection overhead
	r.pool.New = func() interface{} {
		return &Context{
			Params: make(map[string]string),
			Values: make(map[string]interface{}),
		}
	}
	return r
}

// ### Middleware Support

// Use adds one or more middleware functions to the router's global middleware chain.
// Middleware is executed in the order it is added for all routes.
func (r *Router) Use(middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.middleware = append(r.middleware, middleware...)
}

// ### Route Registration

// Get registers a handler for GET requests to the specified path with optional middleware.
// Example: r.Get("/users/:id", handler) matches "/users/123".
func (r *Router) Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("GET", path, handler, middleware...)
}

// Post registers a handler for POST requests to the specified path with optional middleware.
// Useful for handling form submissions or API endpoints.
func (r *Router) Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("POST", path, handler, middleware...)
}

// Put registers a handler for PUT requests to the specified path with optional middleware.
// Typically used for updating resources.
func (r *Router) Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("PUT", path, handler, middleware...)
}

// Delete registers a handler for DELETE requests to the specified path with optional middleware.
// Used for deleting resources.
func (r *Router) Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("DELETE", path, handler, middleware...)
}

// Patch registers a handler for PATCH requests to the specified path with optional middleware.
// Supports partial updates to resources.
func (r *Router) Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("PATCH", path, handler, middleware...)
}

// Options registers a handler for OPTIONS requests to the specified path with optional middleware.
// Useful for CORS preflight requests.
func (r *Router) Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("OPTIONS", path, handler, middleware...)
}

// Head registers a handler for HEAD requests to the specified path with optional middleware.
// Returns headers without a body, often used for metadata retrieval.
func (r *Router) Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("HEAD", path, handler, middleware...)
}

// Handle registers a handler for any HTTP method to the specified path with optional middleware.
// Provides flexibility for custom or non-standard HTTP methods.
func (r *Router) Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute(method, path, handler, middleware...)
}

// WebSocket registers a WebSocket handler for the specified path with optional middleware.
// It upgrades the HTTP connection to a WebSocket connection.
func (r *Router) WebSocket(path string, handler WebSocketHandler, middleware ...MiddlewareFunc) {
	wrapped := r.wrapWebSocketHandler(handler)
	r.addRoute("GET", path, wrapped, middleware...)
}

// ServeStatic serves static files from the specified root directory under the given prefix.
// It supports GET and HEAD requests with wildcard paths (e.g., "/static/*").
func (r *Router) ServeStatic(prefix, root string) {
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix // Ensure prefix starts with "/"
	}
	fs := http.FileServer(http.Dir(root))
	staticHandler := http.StripPrefix(prefix, fs)
	handler := func(c *Context) {
		staticHandler.ServeHTTP(c.Writer, c.Request)
	}
	r.addRoute("GET", prefix+"/*", handler)
	r.addRoute("HEAD", prefix+"/*", handler)
}

// ### Route Grouping

// Group creates a new sub-router with the specified prefix and middleware.
// It allows organizing routes under a common prefix with shared middleware.
func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *Router {
	subRouter := New()
	subRouter.middleware = middleware
	r.Mount(prefix, subRouter)
	return subRouter
}

// Mount attaches the sub-router's routes under the specified prefix in the parent router.
// It integrates the sub-router's route tree into the parent's tree.
func (r *Router) Mount(prefix string, subRouter *Router) {
	prefix = strings.Trim(prefix, "/")
	parts := strings.Split(prefix, "/")
	for method, tree := range subRouter.trees {
		parentTree, exists := r.trees[method]
		if !exists {
			parentTree = &node{children: make(map[string]*node)}
			r.trees[method] = parentTree
		}
		cur := parentTree
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

// addRoute adds a route for the specified HTTP method and path to the router's tree with optional middleware.
// It supports named parameters (e.g., ":id") and wildcards (e.g., "*").
func (r *Router) addRoute(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	if _, exists := r.trees[method]; !exists {
		r.trees[method] = &node{children: make(map[string]*node)}
	}

	cur := r.trees[method]
	parts := strings.Split(strings.Trim(path, "/"), "/")

	for _, part := range parts {
		if strings.HasPrefix(part, ":") { // Named parameter
			if _, exists := cur.children[":"]; !exists {
				cur.children[":"] = &node{path: part, children: make(map[string]*node)}
			}
			cur = cur.children[":"]
		} else if part == "*" { // Wildcard
			cur.wildcard = true
			break
		} else { // Static segment
			if _, exists := cur.children[part]; !exists {
				cur.children[part] = &node{path: part, children: make(map[string]*node)}
			}
			cur = cur.children[part]
		}
	}
	cur.handler = handler
	cur.middleware = middleware
}

// findHandlerAndMiddleware searches for a handler and collects middleware for the given method and path.
// It returns the handler, extracted parameters, and the collected middleware chain.
func (r *Router) findHandlerAndMiddleware(method, path string) (HandlerFunc, map[string]string, []MiddlewareFunc) {
	middleware := make([]MiddlewareFunc, 0, len(r.middleware))
	middleware = append(middleware, r.middleware...)
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
				params[paramChild.path[1:]] = part // Extract parameter value
			} else if cur.wildcard {
				break
			} else {
				return nil, nil, nil // No match found
			}
		}
		if cur.handler != nil {
			if cur.middleware != nil {
				middleware = append(middleware, cur.middleware...)
			}
			return cur.handler, params, middleware
		}
	}
	return nil, nil, nil // No handler found
}

// ### HTTP Serving

// ServeHTTP implements the http.Handler interface, handling incoming HTTP requests with error handling.
// It applies middleware and dispatches to the appropriate handler, or serves a 404 if no route is found.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := r.pool.Get().(*Context)
	ctx.Writer = w
	ctx.Request = req
	// Clear previous params and values for reuse
	for k := range ctx.Params {
		delete(ctx.Params, k)
	}
	if ctx.Values != nil {
		for k := range ctx.Values {
			delete(ctx.Values, k)
		}
	}
	defer r.pool.Put(ctx)

	handler, params, middleware := r.findHandlerAndMiddleware(req.Method, req.URL.Path)
	if handler == nil {
		if r.config.NotFoundHandler != nil {
			r.config.NotFoundHandler(ctx)
		} else {
			http.NotFound(w, req) // Default 404 behavior
		}
		return
	}
	ctx.Params = params

	// Build and execute the middleware chain
	wrappedHandler := handler
	for i := len(middleware) - 1; i >= 0; i-- {
		mw := middleware[i]
		next := wrappedHandler
		wrappedHandler = func(ctx *Context) {
			mw(ctx, func() { next(ctx) })
		}
	}

	// Handle panics with custom error handler if set
	defer func() {
		if err := recover(); err != nil {
			fmt.Println("Panic:", err)
			if r.config.ErrorHandler != nil {
				r.config.ErrorHandler(ctx, fmt.Errorf("%v", err))
			} else {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}
	}()

	wrappedHandler(ctx)
}

// ### Server Start Methods

// Start launches the HTTP server on the specified port.
// It logs a startup message and listens for incoming requests.
func (r *Router) Start(port string) {
	fmt.Printf("Nanite server running on port %s\n", port)
	http.ListenAndServe(":"+port, r)
}

// StartTLS launches the HTTPS server on the specified port with the provided certificate and key files.
// It enables TLS encryption for secure communication.
func (r *Router) StartTLS(port, certFile, keyFile string) {
	fmt.Printf("Nanite server running on port %s with TLS\n", port)
	http.ListenAndServeTLS(":"+port, certFile, keyFile, r)
}

// String returns a description of the router, useful for debugging or logging.
func (r *Router) String() string {
	return "Nanite Router: Efficient and Express-like HTTP router"
}

// ### Context Methods

// Set sets a user-defined value in the context (e.g., a database connection).
// It initializes the Values map if it doesn’t exist.
func (c *Context) Set(key string, value interface{}) {
	if c.Values == nil {
		c.Values = make(map[string]interface{})
	}
	c.Values[key] = value
}

// Get retrieves a user-defined value from the context.
// Returns nil if the key doesn’t exist or Values is uninitialized.
func (c *Context) Get(key string) interface{} {
	if c.Values == nil {
		return nil
	}
	return c.Values[key]
}

// Bind parses the request body into the provided interface, typically for JSON data.
// Returns an error if decoding fails.
func (c *Context) Bind(v interface{}) error {
	if err := json.NewDecoder(c.Request.Body).Decode(v); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}
	return nil
}

// Cookie sets a cookie with the given name, value, and optional parameters like MaxAge and Path.
// Options are provided as key-value pairs (e.g., "MaxAge", 3600).
func (c *Context) Cookie(name, value string, options ...interface{}) {
	cookie := &http.Cookie{Name: name, Value: value}
	for i := 0; i < len(options); i += 2 {
		key, ok := options[i].(string)
		if !ok {
			continue
		}
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
	http.SetCookie(c.Writer, cookie)
}

// File retrieves the uploaded file associated with the given form key.
// It parses multipart form data with a 32MB limit if not already parsed.
func (c *Context) File(formKey string) (*multipart.FileHeader, error) {
	if c.Request.MultipartForm == nil {
		if err := c.Request.ParseMultipartForm(32 << 20); err != nil { // 32MB max
			return nil, err
		}
	}
	_, header, err := c.Request.FormFile(formKey)
	if err != nil {
		return nil, err
	}
	return header, nil
}

// JSON sends a JSON response with the specified status code.
// Sets the appropriate Content-Type and handles encoding errors.
func (c *Context) JSON(status int, data interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
		http.Error(c.Writer, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

// String sends a plain text response with the specified status code.
// Sets the Content-Type to "text/plain".
func (c *Context) String(status int, data string) {
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(data))
}

// HTML sends an HTML response with the specified status code.
// Sets the Content-Type to "text/html" with UTF-8 charset.
func (c *Context) HTML(status int, html string) {
	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(html))
}

// FormValue retrieves the value of the specified form field from the request.
// Returns an empty string if the key is not found.
func (c *Context) FormValue(key string) string {
	return c.Request.FormValue(key)
}

// MustParam retrieves a required route parameter, returning an error if it is missing or empty.
// Useful for enforcing required parameters in handlers.
func (c *Context) MustParam(key string) (string, error) {
	if val, ok := c.Params[key]; ok && val != "" {
		return val, nil
	}
	return "", fmt.Errorf("required parameter %s is missing or empty", key)
}

// SetHeader sets a custom HTTP response header with the specified key and value.
func (c *Context) SetHeader(key, value string) {
	c.Writer.Header().Set(key, value)
}

// Redirect redirects the client to the specified URL with the given status code (e.g., 301, 302).
// Validates that the status code is in the 3xx range.
func (c *Context) Redirect(status int, url string) {
	if status < 300 || status > 399 {
		c.String(http.StatusBadRequest, "Redirect status must be in the 3xx range")
		return
	}
	c.Writer.Header().Set("Location", url)
	c.Writer.WriteHeader(status)
}

// Query retrieves the value of the specified query parameter from the request URL.
// Returns an empty string if the parameter is not found.
func (c *Context) Query(key string) string {
	return c.Request.URL.Query().Get(key)
}

// Status sets the HTTP status code for the response without writing a body.
// Useful for minimal responses like 204 No Content.
func (c *Context) Status(status int) {
	c.Writer.WriteHeader(status)
}

// ### WebSocket Support

// wrapWebSocketHandler wraps a WebSocketHandler into a HandlerFunc that upgrades the connection.
// It uses the router's configured Upgrader for consistency.
func (r *Router) wrapWebSocketHandler(handler WebSocketHandler) HandlerFunc {
	return func(ctx *Context) {
		// Use the configured upgrader from the router's config
		upgrader := r.config.Upgrader
		conn, err := upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
		if err != nil {
			http.Error(ctx.Writer, "Failed to upgrade to WebSocket", http.StatusBadRequest)
			return
		}
		handler(conn, ctx)
	}
}
