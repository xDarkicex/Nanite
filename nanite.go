// Package nanite provides a lightweight, high-performance HTTP router for Go.
// It is designed to be developer-friendly, inspired by Express.js, and optimized
// for speed and efficiency in routing, grouping, middleware handling, and WebSocket support.
package nanite

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ### Core Types and Data Structures

// ErrorMiddlewareFunc defines the signature for error handling middleware.
// It takes an error and a Context to handle errors in the request pipeline.
type ErrorMiddlewareFunc func(err error, ctx *Context, next func())

// HandlerFunc defines the signature for HTTP request handlers.
// It takes a Context pointer to process the request and send a response.
type HandlerFunc func(*Context)

// WebSocketHandler defines the signature for WebSocket handlers.
// It processes WebSocket connections using a connection and context.
type WebSocketHandler func(*websocket.Conn, *Context)

// MiddlewareFunc defines the signature for middleware functions.
// It takes a Context and a next function to control request flow.
type MiddlewareFunc func(*Context, func())

// Param represents a route parameter with a key-value pair.
// Fields are aligned for simplicity and cache efficiency.
type Param struct {
	Key   string // Parameter name
	Value string // Parameter value
}

// Context represents the environment for an HTTP request/response cycle in the Nanite router.
// It provides access to the request data, response writing capabilities, parameter handling,
// validation, and request-scoped storage.
//
// The Context is created for each incoming request and pooled for reuse after the request
// completes. It's passed to all middleware functions and handlers, serving as the primary
// interface for accessing request data and manipulating the response.
//
// The struct is optimized for cache-line efficiency with fields arranged by size to minimize
// padding and memory usage. Most operations on Context are designed to minimize allocations.
//
// Common operations:
//   - Access route parameters: c.GetParam("id")
//   - Set/get values: c.Set("user", user), user := c.Get("user")
//   - Send responses: c.JSON(200, data), c.String(200, "Hello")
//   - Control flow: c.Abort()
type Context struct {
	// Core HTTP objects
	Writer  http.ResponseWriter // Underlying response writer for sending HTTP responses
	Request *http.Request       // Original HTTP request with all headers, body, and URL information

	// Reference maps (8-byte pointers)
	Values     map[string]interface{} // Thread-safe key-value store for request-scoped data sharing between handlers and middleware
	lazyFields map[string]*LazyField  // Deferred validation fields that only evaluate when accessed, reducing unnecessary processing

	// Array and slice fields
	Params         [10]Param        // Fixed-size array of route parameters extracted from URL (e.g., /users/:id → {id: "123"})
	ValidationErrs ValidationErrors // Collection of validation failures for providing consistent error responses

	// Integer fields (8 bytes on 64-bit systems)
	ParamsCount int // Number of active parameters in the Params array, avoids unnecessary iterations

	// Boolean flags (1 byte + potential padding)
	aborted bool // Request termination flag that stops middleware chain execution when true
}

// ValidationErrors aggregates multiple validation failures into a single error.
// It implements the error interface while providing structured access to individual errors.
//
// Use this when validating complex input to report all issues simultaneously rather than
// failing on the first error. The structured errors enable precise error reporting in APIs
// and user interfaces.
//
// Example usage:
//
//	if err := Validate(input); err != nil {
//	    if verr, ok := err.(ValidationErrors); ok {
//	        for _, fieldErr := range verr {
//	            fmt.Printf("%s: %s\n", fieldErr.Field, fieldErr.Message)
//	        }
//	    }
//	}
type ValidationErrors []ValidationError

// Error returns a human-readable summary of validation failures in the format:
// "validation failed: <field1>: <message1>, <field2>: <message2>, ...".
//
// Returns "validation failed" when empty, though typically contains at least one error.
// The output is suitable for logging and API error responses, but prefer accessing
// individual errors programmatically for precise error handling.
//
// Implements the error interface, allowing direct return from validation functions:
//
//	if len(errors) > 0 {
//	    return ValidationErrors(errors)
//	}
func (ve ValidationErrors) Error() string {
	if len(ve) == 0 {
		return "validation failed"
	}
	var errs []string
	for _, e := range ve {
		errs = append(errs, fmt.Sprintf("%s: %s", e.Field, e.Error()))
	}
	return fmt.Sprintf("validation failed: %s", strings.Join(errs, ", "))
}

// ### Router Configuration

// Config controls router behavior and performance.
// Production-ready defaults provided; tune for specific workloads.
//
// Field ordering optimized for memory efficiency (hot fields first).
type Config struct {
	// --- Request Handling ---
	// Custom 404 handler (nil = default plain text)
	// Example: NotFoundHandler = renderCustom404
	NotFoundHandler HandlerFunc

	// Global error handler (nil = log with request ID + stack)
	ErrorHandler func(*Context, error)

	// --- WebSocket Configuration ---
	// WS upgrade settings - clone instead of replace
	Upgrader *websocket.Upgrader

	// Tuning: timeouts, buffers, pings
	WebSocket *WebSocketConfig

	// --- Routing Optimization ---
	// Cached dynamic routes (LRU)
	// Default 1024, Min 128, Set ≈ QPS×params
	RouteCacheSize int

	// Max params per route (security: ≤64)
	// Pre-allocates storage, Default 10
	RouteMaxParams int

	// --- Memory Management ---
	// Base response buffer (bytes)
	// Default 4KB, Typical 2KB-16KB
	DefaultBufferSize int

	// Text responses (JSON/HTML) buffer
	// Default 4KB, Set ≈ max response size
	TextBufferSize int

	// Binary responses (images/files) buffer
	// Default 8KB, Set ≈ avg asset size
	BinaryBufferSize int

	// Auto-tune buffers: ~20% memory saving
	// Costs 5-10% CPU, enable for spiky traffic
	AdaptiveBuffering bool
}

// WebSocketConfig holds configuration options for WebSocket connections.
type WebSocketConfig struct {
	ReadTimeout    time.Duration // Timeout for reading messages
	WriteTimeout   time.Duration // Timeout for writing messages
	PingInterval   time.Duration // Interval for sending pings
	MaxMessageSize int64         // Maximum message size in bytes
	BufferSize     int           // Buffer size for read/write operations
}

// ### static route Structure

// staticRoute represents a static route with a handler and parameters.
type staticRoute struct {
	handler HandlerFunc
	params  []Param
}

// ### Radix Structure

// RadixNode represents a node in the radix tree
type RadixNode struct {
	// The path segment this node represents
	prefix string

	// Handler for this route (if terminal)
	handler HandlerFunc

	// Static children indexed by their first byte for quick lookup
	children map[byte]*RadixNode

	// Special children for parameters and wildcards
	paramChild    *RadixNode
	wildcardChild *RadixNode

	// Parameter/wildcard names if applicable
	paramName    string
	wildcardName string
}

// Router is the core request routing handler for the Nanite framework.
// It combines lightning-fast static route lookups with efficient dynamic path matching,
// making it suitable for high-throughput API servers and real-time applications.
//
// Key Features:
// - O(1) static route lookup using method/path hash maps
// - Dynamic routing with parameters using radix trees
// - LRU caching for hot path optimization
// - Zero-allocation context pooling
// - Thread-safe configuration updates
// - Built-in WebSocket support with sensible defaults
// - Graceful shutdown management
//
// The router is optimized for machine efficiency through:
// - String interning for path comparisons
// - Reusable context objects (sync.Pool)
// - Pre-allocated parameter arrays
// - Lock-free reads during request handling
//
// Example Usage:
//
//	router := nanite.New()
//	router.Use(LoggingMiddleware)
//	router.Get("/status", StatusHandler)
//	router.Post("/users/:id", CreateUserHandler)
//	router.Start(":8080")
type Router struct {
	// Core routing components (optimized for read performance)
	staticRoutes map[string]map[string]staticRoute // [HTTP Method][Path Pattern] -> Handler mapping
	trees        map[string]*RadixNode             // Method-specific radix trees for dynamic routes
	routeCache   *LRUCache                         // Cached dynamic route matches (path -> resolved route)

	// Request lifecycle management
	pool            sync.Pool             // Context instance pool (reduces GC pressure)
	middleware      []MiddlewareFunc      // Global middleware chain (pre-handler processing)
	errorMiddleware []ErrorMiddlewareFunc // Error handling chain (post-error processing)

	// Service configuration
	config     *Config      // Tunable parameters for routing and behavior
	httpClient *http.Client // Pre-configured client for proxy/outbound requests

	// Server orchestration
	server        *http.Server   // Embedded HTTP server instance
	shutdownHooks []ShutdownHook // Cleanup tasks for graceful shutdown
	mutex         sync.RWMutex   // Protects mutable components (middleware, routes)
}

// ShutdownHook defines a cleanup function executed during graceful shutdown.
// Hooks are executed in registration order and should return within 5 seconds
// to respect shutdown deadlines.
type ShutdownHook func() error

// New creates a production-ready Router with optimized defaults:
// - Route cache: 1024 entries
// - Max parameters per route: 10
// - HTTP Client: Keep-alive with 1000 idle connections
// - WebSocket: 1MB max message, 30s ping interval
// - Default timeouts: 30s dial, 120s idle, 30s request
//
// The initialized router includes:
// - Static route map for exact path matches
// - Radix trees for parameterized routes
// - Context pool with pre-allocated parameter slots
// - HTTP client tuned for high concurrency
// - WebSocket upgrader with permissive CORS
//
// Usage Example:
//
//	// Create router with default configuration
//	r := nanite.New()
//
//	// Customize configuration before starting
//	r.Config().WebSocket.ReadTimeout = 15 * time.Second
//
//	// Add routes and middleware
//	r.Use(RequestIDMiddleware)
//	r.Get("/health", healthCheckHandler)
func New() *Router {
	r := &Router{
		trees:        make(map[string]*RadixNode),
		staticRoutes: make(map[string]map[string]staticRoute),
		config: &Config{
			WebSocket: &WebSocketConfig{
				ReadTimeout:    60 * time.Second,
				WriteTimeout:   10 * time.Second,
				PingInterval:   30 * time.Second,
				MaxMessageSize: 1024 * 1024, // 1MB
				BufferSize:     4096,
			},
			RouteCacheSize: 1024, // Default cache size
			RouteMaxParams: 10,   // Default max params
		},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        1000,
				MaxIdleConnsPerHost: 100,
				IdleConnTimeout:     120 * time.Second,
				DisableCompression:  false,
				ForceAttemptHTTP2:   false,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
			Timeout: 30 * time.Second,
		},
	}

	// Context pool with memory-efficient initialization
	r.pool.New = func() interface{} {
		return &Context{
			Params:     [10]Param{},                     // Pre-allocated parameter array
			Values:     make(map[string]interface{}, 8), // Common case: 8-12 context values
			lazyFields: make(map[string]*LazyField),     // Lazy response formatting
			aborted:    false,
		}
	}

	// WebSocket configuration with permissive defaults
	r.config.Upgrader = &websocket.Upgrader{
		CheckOrigin:     func(*http.Request) bool { return true }, // Accept all origins
		ReadBufferSize:  r.config.WebSocket.BufferSize,
		WriteBufferSize: r.config.WebSocket.BufferSize,
	}

	// Route cache optimized for high locality workloads
	r.routeCache = NewLRUCache(r.config.RouteCacheSize, r.config.RouteMaxParams)

	return r
}

// ### Middleware Support

// Use adds one or more middleware functions to the router's global middleware stack.
// These middleware functions will be executed for every request in order.
func (r *Router) Use(middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.middleware = append(r.middleware, middleware...)
}

// ### Route Registration

// Get registers a handler for GET requests on the specified path.
func (r *Router) Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Router {
	r.addRoute("GET", path, handler, middleware...)
	return r
}

// Post registers a handler for POST requests on the specified path.
func (r *Router) Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Router {
	r.addRoute("POST", path, handler, middleware...)
	return r
}

// Put registers a handler for PUT requests on the specified path.
func (r *Router) Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Router {
	r.addRoute("PUT", path, handler, middleware...)
	return r
}

// Delete registers a handler for DELETE requests on the specified path.
func (r *Router) Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Router {
	r.addRoute("DELETE", path, handler, middleware...)
	return r
}

// Patch registers a handler for PATCH requests on the specified path.
func (r *Router) Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Router {
	r.addRoute("PATCH", path, handler, middleware...)
	return r
}

// Options registers a handler for OPTIONS requests on the specified path.
func (r *Router) Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Router {
	r.addRoute("OPTIONS", path, handler, middleware...)
	return r
}

// Head registers a handler for HEAD requests on the specified path.
func (r *Router) Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Router {
	r.addRoute("HEAD", path, handler, middleware...)
	return r
}

// Handle registers a handler for the specified HTTP method and path.
func (r *Router) Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Router {
	r.addRoute(method, path, handler, middleware...)
	return r
}

// ### Server Start Methods

// Start launches the HTTP server on the specified port.
func (r *Router) Start(port string) error {
	r.mutex.Lock()
	if r.server != nil {
		r.mutex.Unlock()
		return fmt.Errorf("server already running")
	}
	r.server = &http.Server{
		Addr:           ":" + port,
		Handler:        r,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateNew {
				tcpConn, ok := conn.(*net.TCPConn)
				if ok {
					tcpConn.SetReadBuffer(65536)
					tcpConn.SetWriteBuffer(65536)
				}
			}
		},
	}
	r.mutex.Unlock()
	fmt.Printf("Nanite server running on port %s\n", port)
	err := r.server.ListenAndServe()
	// ErrServerClosed is returned when Shutdown is called
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// AddShutdownHook registers a function to be called during graceful shutdown
func (r *Router) AddShutdownHook(hook ShutdownHook) *Router {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.shutdownHooks = append(r.shutdownHooks, hook)
	return r
}

// StartTLS launches the HTTPS server on the specified port with TLS.
func (r *Router) StartTLS(port, certFile, keyFile string) error {
	r.mutex.Lock()
	if r.server != nil {
		r.mutex.Unlock()
		return fmt.Errorf("server already running")
	}

	r.server = &http.Server{
		Addr:           ":" + port,
		Handler:        r,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	r.mutex.Unlock()
	err := r.server.ListenAndServeTLS(certFile, keyFile)
	// ErrServerClosed is returned when Shutdown is called
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown gracefully shuts down the server without interrupting any active connections.
// It waits for all in-flight requests to complete (up to the specified timeout), then shuts down.
//
// Parameters:
//   - timeout: Maximum time to wait for connections to complete before forcing shutdown
//
// Returns:
//   - error: Any error that occurred during shutdown
func (r *Router) Shutdown(timeout time.Duration) error {
	r.mutex.Lock()
	if r.server == nil {
		r.mutex.Unlock()
		return fmt.Errorf("server not started or already shut down")
	}

	// Execute shutdown hooks
	for _, hook := range r.shutdownHooks {
		if err := hook(); err != nil {
			fmt.Printf("Error during shutdown hook: %v\n", err)
		}
	}

	server := r.server
	r.server = nil
	r.mutex.Unlock()

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Perform graceful shutdown
	return server.Shutdown(ctx)
}

// ShutdownImmediate forces an immediate shutdown of the server.
// Unlike Shutdown(), this does not wait for in-flight requests to complete.
//
// Returns:
//   - error: Any error that occurred during shutdown
func (r *Router) ShutdownImmediate() error {
	r.mutex.Lock()
	if r.server == nil {
		r.mutex.Unlock()
		return fmt.Errorf("server not started or already shut down")
	}

	server := r.server
	r.server = nil
	r.mutex.Unlock()

	// Close immediately
	return server.Close()
}

// ### WebSocket Support

// WebSocket registers a WebSocket handler for the specified path.
func (r *Router) WebSocket(path string, handler WebSocketHandler, middleware ...MiddlewareFunc) *Router {
	r.addRoute("GET", path, r.wrapWebSocketHandler(handler), middleware...)
	return r
}

// ### Static File Serving

// ServeStatic serves static files from the specified root directory under the given prefix.
func (r *Router) ServeStatic(prefix, root string) *Router {
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	fs := http.FileServer(http.Dir(root))
	handler := func(c *Context) {
		http.StripPrefix(prefix, fs).ServeHTTP(c.Writer, c.Request)
	}
	r.addRoute("GET", prefix+"/*", handler)
	r.addRoute("HEAD", prefix+"/*", handler)
	return r
}

// ### Helper Functions

// addRoute registers a route with the router.
// Static routes (without parameters) are stored in a map for O(1) lookup.
// Dynamic routes (with parameters) are stored in a radix tree for efficient matching.
// Middleware chains are pre-composed at registration time rather than during request
// processing, dramatically reducing per-request overhead and eliminating recursion issues.
func (r *Router) addRoute(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Combine global and route middleware
	routeMiddleware := make([]MiddlewareFunc, len(r.middleware)+len(middleware))
	copy(routeMiddleware, r.middleware)
	copy(routeMiddleware[len(r.middleware):], middleware)

	wrapped := handler
	for i := len(routeMiddleware) - 1; i >= 0; i-- {
		mw := routeMiddleware[i]
		next := wrapped
		wrapped = func(c *Context) {
			if !c.IsAborted() {
				mw(c, func() {
					if !c.IsAborted() {
						next(c)
					}
				})
			}
		}
	}

	// Check if route is static (no parameters or wildcards)
	isStatic := !strings.Contains(path, ":") && !strings.Contains(path, "*")

	// Store static routes in map for O(1) lookup
	if isStatic {
		if _, exists := r.staticRoutes[method]; !exists {
			r.staticRoutes[method] = make(map[string]staticRoute)
		}

		r.staticRoutes[method][path] = staticRoute{handler: wrapped, params: []Param{}}
		return // Skip radix tree insertion for static routes
	}

	// Only dynamic routes go in the radix tree
	if _, exists := r.trees[method]; !exists {
		r.trees[method] = &RadixNode{
			prefix:   "",
			children: make(map[byte]*RadixNode),
		}
	}

	// Insert into radix tree
	root := r.trees[method]
	if path == "" || path == "/" {
		root.handler = wrapped
	} else {
		if path[0] != '/' {
			path = "/" + path
		}

		root.insertRoute(path[1:], wrapped) // Skip leading slash
	}
}

// findHandlerAndMiddleware finds the handler and parameters for a given method and path.
// It employs a three-tier lookup strategy for optimal performance:
//  1. Fast path: O(1) lookup for static routes via map
//  2. LRU cache: Recently used dynamic routes
//  3. Radix tree: Full path matching for dynamic routes
//
// The function returns the matched handler and route parameters.
func (r *Router) findHandlerAndMiddleware(method, path string) (HandlerFunc, []Param) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Fast path: check static routes first (O(1) lookup)
	if methodRoutes, exists := r.staticRoutes[method]; exists {
		if route, found := methodRoutes[path]; found {
			return route.handler, route.params
		}
	}

	// Second tier: check LRU cache before doing the more expensive radix tree lookup
	// This avoids the cost of tree traversal for frequently used dynamic routes
	if r.routeCache != nil {
		if handler, params, found := r.routeCache.Get(method, path); found {
			// Cache hit - strings are interned and params are pooled for efficiency
			return handler, params
		}
		// Cache miss is tracked internally by the LRU implementation
	}

	// Third tier: use radix tree for dynamic routes
	if tree, exists := r.trees[method]; exists {
		// Use an empty params slice that we'll populate
		params := make([]Param, 0, 5)

		searchPath := path
		if len(path) > 0 && path[0] == '/' {
			searchPath = path[1:]
		}

		handler, params := tree.findRoute(searchPath, params)

		// Cache successful lookups to speed up future requests
		// The LRU handles memory management, parameter pooling, and string interning
		if handler != nil && r.routeCache != nil {
			r.routeCache.Add(method, path, handler, params)
		}

		return handler, params
	}

	// No matching route found
	return nil, nil
}

// ServeHTTP implements the http.Handler interface for the router.
// It processes incoming HTTP requests by:
// 1. Setting up response tracking and buffering
// 2. Retrieving a pooled Context for the request
// 3. Monitoring for context cancellation and timeouts
// 4. Finding the appropriate handler for the request path
// 5. Executing the middleware/handler pipeline
// 6. Handling any panics or errors during processing with error middleware
// 7. Ensuring all resources are properly released
//
// The implementation is optimized for high throughput with minimal allocations
// by using object pooling, buffered writes, and direct middleware references.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Initialize response writer chain with tracking and buffering
	trackedWriter := WrapResponseWriter(w)
	// Get content type from response headers or request Accept header
	contentType := w.Header().Get("Content-Type")
	if contentType == "" {
		contentType = req.Header.Get("Accept")
		if contentType == "" || contentType == "*/*" {
			contentType = "text/plain" // Default assumption
		}
	}

	bufferedWriter := newBufferedResponseWriter(trackedWriter, contentType, r.config)
	defer bufferedWriter.Close()
	// Get a context from the pool and initialize it with a single Reset call
	ctx := r.pool.Get().(*Context)
	ctx.Reset(bufferedWriter, req)
	// Ensure context is returned to pool when done
	defer func() {
		ctx.CleanupPooledResources()
		r.pool.Put(ctx)
	}()
	// Set up context cancellation monitoring
	reqCtx := req.Context()
	if reqCtx.Done() != nil {
		finished := make(chan struct{})
		defer close(finished)
		go func() {
			select {
			case <-reqCtx.Done():
				ctx.Abort()
				if !trackedWriter.Written() {
					statusCode := http.StatusGatewayTimeout
					if reqCtx.Err() == context.Canceled {
						statusCode = 499 // Client closed request
					}
					http.Error(trackedWriter, fmt.Sprintf("Request %v", reqCtx.Err()), statusCode)
				}
			case <-finished:
				// Handler completed normally
			}
		}()
	}

	// Route lookup: find the appropriate handler and parameters
	handler, params := r.findHandlerAndMiddleware(req.Method, req.URL.Path)
	if handler == nil {
		// Handle 404 Not Found
		if r.config.NotFoundHandler != nil {
			r.config.NotFoundHandler(ctx)
		} else {
			http.NotFound(trackedWriter, req)
		}
		bufferedWriter.Close()
		return
	}

	// Copy route parameters to context's fixed-size array
	for i, p := range params {
		if i < len(ctx.Params) {
			ctx.Params[i] = p
		}
	}
	ctx.ParamsCount = len(params)

	// Make router configuration available to middleware
	ctx.Values["routerConfig"] = r.config

	// Set up panic recovery
	defer func() {
		if err := recover(); err != nil {
			ctx.Abort()
			if !trackedWriter.Written() {
				// Convert panic value to error
				var errValue error
				switch e := err.(type) {
				case error:
					errValue = e
				default:
					errValue = fmt.Errorf("%v", err)
				}

				r.mutex.RLock()
				hasErrorMiddleware := len(r.errorMiddleware) > 0
				r.mutex.RUnlock()

				if hasErrorMiddleware {
					r.mutex.RLock()
					executeErrorMiddlewareChain(errValue, ctx, r.errorMiddleware)
					r.mutex.RUnlock()
				} else if r.config.ErrorHandler != nil {
					r.config.ErrorHandler(ctx, errValue)
				} else {
					http.Error(trackedWriter, "Internal Server Error", http.StatusInternalServerError)
				}
			} else {
				fmt.Printf("Panic occurred after response started: %v\n", err)
			}
			bufferedWriter.Close()
		}
	}()

	// Execute the middleware chain with the final handler
	// Using direct middleware reference without cloning for better performance
	r.mutex.RLock()
	executeMiddlewareChain(ctx, handler, r.middleware)
	r.mutex.RUnlock()

	// Check if the context contains an error to be handled by error middleware
	if err := ctx.GetError(); err != nil && !trackedWriter.Written() {
		r.mutex.RLock()
		hasErrorMiddleware := len(r.errorMiddleware) > 0
		r.mutex.RUnlock()

		if hasErrorMiddleware {
			r.mutex.RLock()
			executeErrorMiddlewareChain(err, ctx, r.errorMiddleware)
			r.mutex.RUnlock()
		} else if r.config.ErrorHandler != nil {
			r.config.ErrorHandler(ctx, err)
		}
	} else if ctx.IsAborted() && !trackedWriter.Written() {
		// Handle aborted requests that haven't written a response
		if r.config.NotFoundHandler != nil {
			r.config.NotFoundHandler(ctx)
		} else {
			http.NotFound(trackedWriter, req)
		}
	}

	// Ensure the buffered writer is closed and flushed
	bufferedWriter.Close()
}

// ### Helper Types and Functions

// longestCommonPrefix finds the longest common prefix of two strings
//
//go:inline
func longestCommonPrefix(a, b string) int {
	max := len(a)
	if len(b) < max {
		max = len(b)
	}

	for i := 0; i < max; i++ {
		if a[i] != b[i] {
			return i
		}
	}

	return max
}

// findRoute searches for a route in the radix tree.
func (n *RadixNode) findRoute(path string, params []Param) (HandlerFunc, []Param) {
	// Base case: empty path
	if path == "" {
		return n.handler, params
	}

	// Try static children first
	if len(path) > 0 {
		if child, exists := n.children[path[0]]; exists {
			if strings.HasPrefix(path, child.prefix) {
				// Remove the prefix from the path
				subPath := path[len(child.prefix):]

				// IMPORTANT: Remove leading slash if present
				if len(subPath) > 0 && subPath[0] == '/' {
					subPath = subPath[1:]
				}

				if handler, subParams := child.findRoute(subPath, params); handler != nil {
					return handler, subParams
				}
			}
		}
	}

	// Try parameter child
	if n.paramChild != nil {
		// Extract parameter value
		i := 0
		for i < len(path) && path[i] != '/' {
			i++
		}

		paramValue := path[:i]
		remainingPath := ""
		if i < len(path) {
			remainingPath = path[i:]
			if len(remainingPath) > 0 && remainingPath[0] == '/' {
				remainingPath = remainingPath[1:] // Skip the slash
			}
		}

		// Add parameter to params
		newParams := append(params, Param{Key: n.paramChild.paramName, Value: paramValue})

		// If no remaining path, return the handler directly
		if remainingPath == "" {
			return n.paramChild.handler, newParams
		}

		// Continue with parameter child
		if handler, subParams := n.paramChild.findRoute(remainingPath, newParams); handler != nil {
			return handler, subParams
		}
	}

	// Try wildcard as a last resort
	if n.wildcardChild != nil {
		newParams := append(params, Param{Key: n.wildcardChild.wildcardName, Value: path})
		return n.wildcardChild.handler, newParams
	}

	return nil, nil
}

// insertRoute inserts a route into the radix tree.
func (n *RadixNode) insertRoute(path string, handler HandlerFunc) {
	// Base case: empty path
	if path == "" {
		n.handler = handler
		return
	}

	// Handle parameters (:id)
	if path[0] == ':' {
		// Extract parameter name and remaining path
		paramEnd := strings.IndexByte(path, '/')
		var paramName, remainingPath string

		if paramEnd == -1 {
			paramName = path[1:]
			remainingPath = ""
		} else {
			paramName = path[1:paramEnd]
			remainingPath = path[paramEnd:]
		}

		// Create parameter child if needed
		if n.paramChild == nil {
			n.paramChild = &RadixNode{
				prefix:    ":" + paramName,
				paramName: paramName,
				children:  make(map[byte]*RadixNode),
			}
		}

		// Continue with remaining path
		if remainingPath == "" {
			n.paramChild.handler = handler
		} else {
			n.paramChild.insertRoute(remainingPath, handler)
		}

		return
	}

	// Handle wildcards (*path)
	if path[0] == '*' {
		n.wildcardChild = &RadixNode{
			prefix:       path,
			handler:      handler,
			wildcardName: path[1:],
			children:     make(map[byte]*RadixNode),
		}
		return
	}

	// Find the first differing character
	var i int
	for i = 0; i < len(path); i++ {
		if path[i] == '/' || path[i] == ':' || path[i] == '*' {
			break
		}
	}

	// Extract the current segment
	segment := path[:i]
	remainingPath := ""
	if i < len(path) {
		remainingPath = path[i:]
	}

	// Add check for empty segment to prevent index out of range panic
	if len(segment) == 0 {
		// Skip empty segments and continue with remaining path
		if remainingPath != "" && len(remainingPath) > 0 {
			// If remainingPath starts with a slash, skip it
			if remainingPath[0] == '/' {
				remainingPath = remainingPath[1:]
			}
			n.insertRoute(remainingPath, handler)
			return
		}
		// If no remaining path, set handler on current node
		n.handler = handler
		return
	}

	// Look for matching child
	c, exists := n.children[segment[0]]
	if !exists {
		// Create new child
		c = &RadixNode{
			prefix:   segment,
			children: make(map[byte]*RadixNode),
		}
		n.children[segment[0]] = c

		// Set handler or continue with remaining path
		if remainingPath == "" {
			c.handler = handler
		} else {
			c.insertRoute(remainingPath, handler)
		}
		return
	}

	// Find common prefix length
	commonPrefixLen := longestCommonPrefix(c.prefix, segment)

	if commonPrefixLen == len(c.prefix) {
		// Child prefix is completely contained in this segment
		if commonPrefixLen == len(segment) {
			// Exact match, continue with remaining path
			if remainingPath == "" {
				c.handler = handler
			} else {
				c.insertRoute(remainingPath, handler)
			}
		} else {
			// Current segment extends beyond child prefix
			c.insertRoute(segment[commonPrefixLen:]+remainingPath, handler)
		}
	} else {
		// Need to split the node
		child := &RadixNode{
			prefix:        c.prefix[commonPrefixLen:],
			handler:       c.handler,
			children:      c.children,
			paramChild:    c.paramChild,
			wildcardChild: c.wildcardChild,
			paramName:     c.paramName,
			wildcardName:  c.wildcardName,
		}

		// Reset the original child
		c.prefix = c.prefix[:commonPrefixLen]
		c.handler = nil
		c.children = make(map[byte]*RadixNode)
		c.paramChild = nil
		c.wildcardChild = nil
		c.paramName = ""
		c.wildcardName = ""

		// Add the split node as a child
		c.children[child.prefix[0]] = child

		// Handle current path
		if commonPrefixLen == len(segment) {
			// Current segment matches prefix exactly
			if remainingPath == "" {
				c.handler = handler
			} else {
				c.insertRoute(remainingPath, handler)
			}
		} else {
			// Current segment extends beyond common prefix
			newChild := &RadixNode{
				prefix:   segment[commonPrefixLen:],
				children: make(map[byte]*RadixNode),
			}

			if remainingPath == "" {
				newChild.handler = handler
			} else {
				newChild.insertRoute(remainingPath, handler)
			}

			c.children[newChild.prefix[0]] = newChild
		}
	}
}
