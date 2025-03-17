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

// Context holds the state of an HTTP request and response.
// It is optimized with a fixed-size array for params.
type Context struct {
	Writer         http.ResponseWriter    // Response writer for sending data
	Request        *http.Request          // Incoming HTTP request
	Params         [5]Param               // Fixed-size array for route parameters
	ParamsCount    int                    // Number of parameters used
	Values         map[string]interface{} // General-purpose value storage
	ValidationErrs ValidationErrors       // Validation errors, if any
	lazyFields     map[string]*LazyField  // Lazy validation fields
	aborted        bool                   // Flag indicating if request is aborted
}

// ValidationErrors is a slice of ValidationError for multiple validation failures.
type ValidationErrors []ValidationError

// Error returns a string representation of all validation errors.
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

// Config holds configuration options for the router.
type Config struct {
	NotFoundHandler   HandlerFunc           // Handler for 404 responses
	ErrorHandler      func(*Context, error) // Custom error handler
	Upgrader          *websocket.Upgrader   // WebSocket upgrader configuration
	WebSocket         *WebSocketConfig      // WebSocket-specific settings
	RouteCacheSize    int                   // Size of the route cache
	RouteMaxParams    int                   // Maximum number of parameters per route
	DefaultBufferSize int                   // Default buffer size for responses
	TextBufferSize    int                   // Buffer size for text-based content types
	BinaryBufferSize  int                   // Buffer size for binary content types
	AdaptiveBuffering bool                  // Enable/disable adaptive buffering
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

// ### Router Structure

// Router is the main router type that manages HTTP and WebSocket requests.
type Router struct {
	trees        map[string]*RadixNode             // Routing trees by HTTP method
	pool         sync.Pool                         // Pool for reusing Context instances
	mutex        sync.RWMutex                      // Mutex for thread-safe middleware updates
	middleware   []MiddlewareFunc                  // Global middleware stack
	config       *Config                           // Router configuration
	httpClient   *http.Client                      // HTTP client for proxying or external requests
	staticRoutes map[string]map[string]staticRoute // method -> exact path -> handler
	routeCache   *LRUCache                         // Route cache
}

// ### Router Initialization

// New creates a new Router instance with default configurations.
// It initializes the routing trees, context pool, and WebSocket settings.
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
	// Initialize context pool with pre-allocated structures
	r.pool.New = func() interface{} {
		return &Context{
			Params:     [5]Param{},
			Values:     make(map[string]interface{}, 8),
			lazyFields: make(map[string]*LazyField),
			aborted:    false,
		}
	}

	// Set up WebSocket upgrader with default settings
	r.config.Upgrader = &websocket.Upgrader{
		CheckOrigin:     func(*http.Request) bool { return true },
		ReadBufferSize:  r.config.WebSocket.BufferSize,
		WriteBufferSize: r.config.WebSocket.BufferSize,
	}
	// Initialize the route cache
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
func (r *Router) Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("GET", path, handler, middleware...)
}

// Post registers a handler for POST requests on the specified path.
func (r *Router) Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("POST", path, handler, middleware...)
}

// Put registers a handler for PUT requests on the specified path.
func (r *Router) Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("PUT", path, handler, middleware...)
}

// Delete registers a handler for DELETE requests on the specified path.
func (r *Router) Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("DELETE", path, handler, middleware...)
}

// Patch registers a handler for PATCH requests on the specified path.
func (r *Router) Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("PATCH", path, handler, middleware...)
}

// Options registers a handler for OPTIONS requests on the specified path.
func (r *Router) Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("OPTIONS", path, handler, middleware...)
}

// Head registers a handler for HEAD requests on the specified path.
func (r *Router) Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("HEAD", path, handler, middleware...)
}

// Handle registers a handler for the specified HTTP method and path.
func (r *Router) Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute(method, path, handler, middleware...)
}

// ### Server Start Methods

// Start launches the HTTP server on the specified port.
func (r *Router) Start(port string) error {
	server := &http.Server{
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
	fmt.Printf("Nanite server running on port %s\n", port)
	return server.ListenAndServe()
}

// StartTLS launches the HTTPS server on the specified port with TLS.
func (r *Router) StartTLS(port, certFile, keyFile string) error {
	server := &http.Server{
		Addr:           ":" + port,
		Handler:        r,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	fmt.Printf("Nanite server running on port %s with TLS\n", port)
	return server.ListenAndServeTLS(certFile, keyFile)
}

// ### WebSocket Support

// WebSocket registers a WebSocket handler for the specified path.
func (r *Router) WebSocket(path string, handler WebSocketHandler, middleware ...MiddlewareFunc) {
	r.addRoute("GET", path, r.wrapWebSocketHandler(handler), middleware...)
}

// ### Static File Serving

// ServeStatic serves static files from the specified root directory under the given prefix.
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

// ### Helper Functions

// addRoute adds a route to the router's tree for the given method and path.
// It optimizes static routes with a fast path lookup and builds a RadixTree for dynamic routes.
func (r *Router) addRoute(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Pre-build middleware chain (keep this unchanged)
	allMiddleware := append(r.middleware, middleware...)
	wrapped := handler
	for i := len(allMiddleware) - 1; i >= 0; i-- {
		mw := allMiddleware[i]
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

	// Keep static routes optimization
	isStatic := !strings.Contains(path, ":") && !strings.Contains(path, "*")
	if isStatic {
		if _, exists := r.staticRoutes[method]; !exists {
			r.staticRoutes[method] = make(map[string]staticRoute)
		}
		r.staticRoutes[method][path] = staticRoute{handler: wrapped, params: []Param{}}
	}

	// Initialize or use existing method tree
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
		// Normalize path
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
// 6. Handling any panics or errors during processing
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

	// Set up panic recovery
	defer func() {
		if err := recover(); err != nil {
			ctx.Abort()
			if !trackedWriter.Written() {
				if r.config.ErrorHandler != nil {
					r.config.ErrorHandler(ctx, fmt.Errorf("%v", err))
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

	// Handle aborted requests that haven't written a response
	if ctx.IsAborted() && !trackedWriter.Written() {
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
