// Package nanite provides a lightweight, high-performance HTTP router for Go.
// It is designed to be developer-friendly, inspired by Express.js, and optimized
// for speed and efficiency in routing, grouping, middleware handling, and WebSocket support.
package nanite

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"sort"
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
	NotFoundHandler HandlerFunc           // Handler for 404 responses
	ErrorHandler    func(*Context, error) // Custom error handler
	Upgrader        *websocket.Upgrader   // WebSocket upgrader configuration
	WebSocket       *WebSocketConfig      // WebSocket-specific settings
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

// ### Router Structure

// Router is the main router type that manages HTTP and WebSocket requests.
type Router struct {
	trees        map[string]*node                  // Routing trees by HTTP method
	pool         sync.Pool                         // Pool for reusing Context instances
	mutex        sync.RWMutex                      // Mutex for thread-safe middleware updates
	middleware   []MiddlewareFunc                  // Global middleware stack
	config       *Config                           // Router configuration
	httpClient   *http.Client                      // HTTP client for proxying or external requests
	staticRoutes map[string]map[string]staticRoute // method -> exact path -> handler
}

// ### Router Initialization

// New creates a new Router instance with default configurations.
// It initializes the routing trees, context pool, and WebSocket settings.
func New() *Router {
	r := &Router{
		trees:        make(map[string]*node),
		staticRoutes: make(map[string]map[string]staticRoute),
		config: &Config{
			WebSocket: &WebSocketConfig{
				ReadTimeout:    60 * time.Second,
				WriteTimeout:   10 * time.Second,
				PingInterval:   30 * time.Second,
				MaxMessageSize: 1024 * 1024, // 1MB
				BufferSize:     4096,
			},
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
		WriteTimeout:   5 * time.Second,
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

// parsePath splits a path into segments for routing.
// depricated
func parsePath(path string) []string {
	if path == "/" || path == "" {
		return []string{}
	}

	// Pre-allocate with larger capacity for common case
	var partsArray [12]string
	count := 0

	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			if i > start {
				if count < len(partsArray) {
					partsArray[count] = path[start:i]
					count++
				} else {
					// Rare case: more than 12 segments
					result := make([]string, count, count+8)
					copy(result, partsArray[:count])
					result = append(result, path[start:i])

					// Handle remaining parts
					for j := i + 1; j < len(path); j++ {
						if path[j] == '/' {
							if j > i+1 {
								result = append(result, path[i+1:j])
							}
							i = j
						}
					}

					// Add final part if exists
					if i+1 < len(path) {
						result = append(result, path[i+1:])
					}

					return result
				}
			}
			start = i + 1
		}
	}

	// Add final part if exists
	if start < len(path) {
		partsArray[count] = path[start:]
		count++
	}

	return partsArray[:count]
}

// addRoute adds a route to the router's tree for the given method and path.
// It optimizes static routes with a fast path lookup and builds a trie for dynamic routes.
func (r *Router) addRoute(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Pre-build the middleware chain once for both static and dynamic routes
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

	// Fast path: Check if this is a static route (no params or wildcards)
	isStatic := true
	for i := 0; i < len(path); i++ {
		if path[i] == ':' || path[i] == '*' {
			isStatic = false
			break
		}
	}

	// Initialize static routes map if needed
	if _, exists := r.staticRoutes[method]; !exists {
		r.staticRoutes[method] = make(map[string]staticRoute)
	}

	// Store in fast path map if static
	if isStatic {
		r.staticRoutes[method][path] = staticRoute{
			handler: wrapped,
			params:  []Param{},
		}
	}

	// Initialize method tree if needed (only once)
	if _, exists := r.trees[method]; !exists {
		r.trees[method] = &node{children: []childNode{}}
	}

	// Always add to the trie for consistent behavior
	cur := r.trees[method]
	parser := NewPathParser(path)

	for i := 0; i < parser.Count(); i++ {
		var key string

		if parser.IsParam(i) {
			key = ":"
			cur.paramName = parser.ParamName(i)
		} else if parser.IsWildcard(i) {
			cur.wildcard = true
			cur.paramName = parser.ParamName(i)
			if cur.paramName == "" {
				cur.paramName = "*"
			}
			break // Wildcard ends the path
		} else {
			key = parser.Part(i)
		}

		// Binary search for child node position
		idx := sort.Search(len(cur.children), func(j int) bool {
			return cur.children[j].key >= key
		})

		if idx < len(cur.children) && cur.children[idx].key == key {
			// Existing node found
			cur = cur.children[idx].node
		} else {
			// Create new node
			newNode := &node{
				path:     parser.Part(i),
				children: []childNode{},
			}

			if parser.IsParam(i) {
				newNode.paramName = parser.ParamName(i)
			}

			// Insert at sorted position
			cur.children = slices.Insert(cur.children, idx, childNode{key: key, node: newNode})
			cur = newNode
		}
	}

	// Set handler for the final node
	cur.handler = wrapped
}

// findHandlerAndMiddleware finds the handler and parameters for a given method and path.
// It uses a fast path for static routes and falls back to trie traversal for dynamic routes.
func (r *Router) findHandlerAndMiddleware(method, path string) (HandlerFunc, []Param) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Fast path: check static routes first (O(1) lookup)
	if methodRoutes, exists := r.staticRoutes[method]; exists {
		if route, found := methodRoutes[path]; found {
			return route.handler, route.params
		}
	}

	// Slow path: use trie traversal for dynamic routes
	if tree, exists := r.trees[method]; exists {
		cur := tree

		// Use a fixed-size array for params to avoid allocations in common case
		var paramsArray [5]Param
		paramsCount := 0

		parser := NewPathParser(path)

		for i := 0; i < parser.Count(); i++ {
			part := parser.Part(i)

			// Fast path for wildcard nodes
			if cur.wildcard {
				// Capture remaining path as wildcard parameter
				if cur.paramName != "" {
					// Calculate remaining path without allocating new strings
					var remainingPath string
					if i < parser.Count() {
						// Get the start of the current part
						startIdx := parser.parts[i].Start
						// Use the original path from this point
						remainingPath = path[startIdx:]
					}

					// Add param to fixed-size array if possible
					if paramsCount < len(paramsArray) {
						paramsArray[paramsCount] = Param{Key: cur.paramName, Value: remainingPath}
						paramsCount++
					} else {
						// Rare case: more than 5 params
						params := make([]Param, paramsCount, paramsCount+1)
						copy(params, paramsArray[:paramsCount])
						params = append(params, Param{Key: cur.paramName, Value: remainingPath})

						if cur.handler != nil {
							return cur.handler, params
						}
						return nil, nil
					}
				}

				if cur.handler != nil {
					return cur.handler, paramsArray[:paramsCount]
				}

				return nil, nil
			}

			// Binary search for exact match (O(log n) lookup)
			idx := sort.Search(len(cur.children), func(j int) bool {
				return cur.children[j].key >= part
			})

			if idx < len(cur.children) && cur.children[idx].key == part {
				cur = cur.children[idx].node
			} else {
				// Binary search for parameter match
				idx = sort.Search(len(cur.children), func(j int) bool {
					return cur.children[j].key >= ":"
				})

				if idx < len(cur.children) && cur.children[idx].key == ":" {
					cur = cur.children[idx].node
					if cur.paramName != "" {
						// Add param to fixed-size array if possible
						if paramsCount < len(paramsArray) {
							paramsArray[paramsCount] = Param{Key: cur.paramName, Value: part}
							paramsCount++
						} else {
							// Rare case: more than 5 params
							params := make([]Param, paramsCount, paramsCount+1)
							copy(params, paramsArray[:paramsCount])
							params = append(params, Param{Key: cur.paramName, Value: part})

							// Continue traversal with dynamic params slice
							for i++; i < parser.Count(); i++ {
								// Similar traversal logic but with dynamic params slice
								// This branch is rare, so the slight code duplication is acceptable for performance
								// ...
							}

							if cur.handler != nil {
								return cur.handler, params
							}
							return nil, nil
						}
					}
				} else {
					return nil, nil
				}
			}
		}

		if cur.handler != nil {
			return cur.handler, paramsArray[:paramsCount]
		}
	}

	return nil, nil
}

// ServeHTTP implements the http.Handler interface for the router.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Wrap the response writer to track if headers have been sent
	trackedWriter := WrapResponseWriter(w)
	bufferedWriter := newBufferedResponseWriter(trackedWriter, 4096)
	defer bufferedWriter.Close()

	// Get a context from the pool
	ctx := r.pool.Get().(*Context)
	ctx.Writer = bufferedWriter
	ctx.Request = req
	ctx.ParamsCount = 0 // Reset params count
	ctx.ClearValues()
	ctx.ClearLazyFields()
	ctx.ValidationErrs = nil
	ctx.aborted = false

	// Ensure context is returned to pool when done
	defer func() {
		ctx.CleanupPooledResources()
		r.pool.Put(ctx)
	}()

	// Use the request's context for detecting cancellation and timeouts
	reqCtx := req.Context()

	// Set up a goroutine to monitor for cancellation if the context can be canceled
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

	// Find the appropriate handler
	handler, params := r.findHandlerAndMiddleware(req.Method, req.URL.Path)
	if handler == nil {
		if r.config.NotFoundHandler != nil {
			r.config.NotFoundHandler(ctx)
		} else {
			http.NotFound(trackedWriter, req)
		}
		bufferedWriter.Close()
		return
	}

	// Set parameters to context
	for i, p := range params {
		if i < len(ctx.Params) {
			ctx.Params[i] = p
		}
	}
	ctx.ParamsCount = len(params)

	// Capture panics from handlers
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
	// Execute the handler with middleware
	r.mutex.RLock()
	allMiddleware := slices.Clone(r.middleware)
	r.mutex.RUnlock()

	executeMiddlewareChain(ctx, handler, allMiddleware)

	if ctx.IsAborted() && !trackedWriter.Written() {
		if r.config.NotFoundHandler != nil {
			r.config.NotFoundHandler(ctx)
		} else {
			http.NotFound(trackedWriter, req)
		}
		bufferedWriter.Close()
	}
	bufferedWriter.Close()
}

// ### Helper Types and Functions

// childNode represents a child node in the routing tree.
type childNode struct {
	key  string
	node *node
}

// node represents a node in the routing tree.
type node struct {
	path      string
	paramName string
	wildcard  bool
	handler   HandlerFunc
	children  []childNode
}

// insertChild inserts a child node into the sorted list of children.
func insertChild(children []childNode, key string, node *node) []childNode {
	idx := sort.Search(len(children), func(i int) bool { return children[i].key >= key })
	if idx < len(children) && children[idx].key == key {
		children[idx].node = node
	} else {
		newChild := childNode{key: key, node: node}
		children = slices.Insert(children, idx, newChild)
	}
	return children
}
