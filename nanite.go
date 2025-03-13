package nanite

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Core Types (unchanged for brevity)
type HandlerFunc func(*Context)
type WebSocketHandler func(*websocket.Conn, *Context)
type MiddlewareFunc func(*Context, func())

type Context struct {
	Writer         http.ResponseWriter
	Request        *http.Request
	Params         []Param
	Values         map[string]interface{}
	ValidationErrs ValidationErrors
	aborted        bool
}

type Param struct {
	Key   string
	Value string
}

type Router struct {
	trees      map[string]*node
	pool       sync.Pool
	mutex      sync.RWMutex
	middleware []MiddlewareFunc
	config     *Config
	httpClient *http.Client
}

// Add configuration options for WebSocket
type WebSocketConfig struct {
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	PingInterval   time.Duration
	MaxMessageSize int64
	BufferSize     int // Buffer sizes for read/write
}

type Config struct {
	NotFoundHandler HandlerFunc
	ErrorHandler    func(*Context, error)
	Upgrader        *websocket.Upgrader
	WebSocket       *WebSocketConfig
}

type childNode struct {
	key  string
	node *node
}

type node struct {
	path       string
	wildcard   bool
	handler    HandlerFunc
	children   []childNode
	middleware []MiddlewareFunc
}

// Validation Types (unchanged for brevity)
type ValidationError struct {
	Field string `json:"field"`
	Error string `json:"error"`
}

type ValidationErrors []ValidationError

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

type ValidatorFunc func(string) error
type ValidationChain struct {
	field string
	rules []ValidatorFunc
}

func NewValidationChain(field string) *ValidationChain {
	return &ValidationChain{field: field}
}

func (vc *ValidationChain) Required() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if value == "" {
			return fmt.Errorf("field is required")
		}
		return nil
	})
	return vc
}

func (vc *ValidationChain) IsEmail() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if !strings.Contains(value, "@") {
			return fmt.Errorf("invalid email format")
		}
		return nil
	})
	return vc
}

func (vc *ValidationChain) IsInt() *ValidationChain {
	vc.rules = append(vc.rules, func(value string) error {
		if _, err := strconv.Atoi(value); err != nil {
			return fmt.Errorf("must be an integer")
		}
		return nil
	})
	return vc
}

// Router Initialization
func New() *Router {
	r := &Router{
		trees: make(map[string]*node),
		config: &Config{
			WebSocket: &WebSocketConfig{
				ReadTimeout:    60 * time.Second,
				WriteTimeout:   10 * time.Second,
				PingInterval:   30 * time.Second,
				MaxMessageSize: 1024 * 1024, // 1MB
				BufferSize:     1024,
			},
		},
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 20,                // Increase from 10
				IdleConnTimeout:     120 * time.Second, // Increase from 90
				DisableCompression:  false,             // Add for most use cases
				ForceAttemptHTTP2:   false,             // Add to enable HTTP/2
			},
			Timeout: 30 * time.Second, // Add default timeout
		},
	}
	r.pool.New = func() interface{} {
		return &Context{
			Params: make([]Param, 0, 5),
			Values: make(map[string]interface{}, 8),
		}
	}
	r.config.Upgrader = &websocket.Upgrader{
		CheckOrigin:     func(*http.Request) bool { return true },
		ReadBufferSize:  r.config.WebSocket.BufferSize,
		WriteBufferSize: r.config.WebSocket.BufferSize,
	}
	return r
}

// Middleware Support
func (r *Router) Use(middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.middleware = append(r.middleware, middleware...)
}

func (c *Context) Abort() {
	c.aborted = true
}

func (c *Context) IsAborted() bool {
	return c.aborted
}

func (c *Context) HTTPClient() *http.Client {
	if client, ok := c.Values["httpClient"].(*http.Client); ok {
		return client
	}
	if router, ok := c.Values["router"].(*Router); ok {
		return router.httpClient
	}
	return http.DefaultClient
}

// Pool for reusing request body buffers to reduce allocations
var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func ValidationMiddleware(chains ...*ValidationChain) MiddlewareFunc {
	return func(ctx *Context, next func()) {
		if ctx.IsAborted() {
			return
		}

		var errs ValidationErrors

		// Only process validation for POST or PUT requests with chains
		if len(chains) > 0 && (ctx.Request.Method == "POST" || ctx.Request.Method == "PUT") {
			contentType := ctx.Request.Header.Get("Content-Type")

			// Handle JSON content
			if strings.HasPrefix(contentType, "application/json") {
				// Get a buffer from the pool and ensure it's empty
				buffer := bufferPool.Get().(*bytes.Buffer)
				buffer.Reset()
				defer bufferPool.Put(buffer) // Return buffer to the pool when done

				// Copy request body to buffer
				if _, err := io.Copy(buffer, ctx.Request.Body); err != nil {
					errs = append(errs, ValidationError{Field: "", Error: "failed to read request body"})
				} else {
					// Create a new reader from buffer bytes and replace the request body
					bodyBytes := buffer.Bytes()
					ctx.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

					// Parse JSON only if we successfully read the body
					var body map[string]interface{}
					if err := json.Unmarshal(bodyBytes, &body); err == nil {
						ctx.Values["body"] = body
					} else {
						errs = append(errs, ValidationError{Field: "", Error: "invalid JSON"})
					}
				}
			}
		}

		// Process validation chains
		for _, chain := range chains {
			value := ""

			// Check query parameters first
			if val := ctx.Request.URL.Query().Get(chain.field); val != "" {
				value = val
			} else if val, ok := ctx.GetParam(chain.field); ok {
				// Then check URL parameters
				value = val
			} else if body, ok := ctx.Values["body"].(map[string]interface{}); ok {
				// Finally check JSON body fields
				if val, ok := body[chain.field].(string); ok {
					value = val
				}
			}

			// Apply validation rules
			for _, rule := range chain.rules {
				if err := rule(value); err != nil {
					errs = append(errs, ValidationError{Field: chain.field, Error: err.Error()})
					break // Stop on first validation error for this field
				}
			}
		}

		// Store validation errors in context if any
		if len(errs) > 0 {
			ctx.ValidationErrs = errs
		}

		// Continue with the next middleware or handler
		next()
	}
}

// Route Registration
func (r *Router) Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("GET", path, handler, middleware...)
}

func (r *Router) Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("POST", path, handler, middleware...)
}

func (r *Router) Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("PUT", path, handler, middleware...)
}

func (r *Router) Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("DELETE", path, handler, middleware...)
}

func (r *Router) Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("PATCH", path, handler, middleware...)
}

func (r *Router) Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("OPTIONS", path, handler, middleware...)
}

func (r *Router) Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute("HEAD", path, handler, middleware...)
}

func (r *Router) Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.addRoute(method, path, handler, middleware...)
}

func (r *Router) WebSocket(path string, handler WebSocketHandler, middleware ...MiddlewareFunc) {
	r.addRoute("GET", path, r.wrapWebSocketHandler(handler), middleware...)
}

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

func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *Router {
	sub := New()
	sub.middleware = append(sub.middleware, middleware...)
	r.Mount(prefix, sub)
	return sub
}

func parsePath(path string) []string {
	if path == "/" {
		return []string{}
	}

	path = strings.Trim(path, "/")
	if path == "" {
		return []string{}
	}

	parts := make([]string, 0, 10) // Most paths have < 10 segments
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			parts = append(parts, path[start:i])
			start = i + 1
		}
	}
	parts = append(parts, path[start:])
	return parts
}

func (r *Router) Mount(prefix string, subRouter *Router) {
	prefix = strings.Trim(prefix, "/")
	parts := parsePath(prefix)
	for method, tree := range subRouter.trees {
		if _, exists := r.trees[method]; !exists {
			r.trees[method] = &node{children: []childNode{}}
		}
		cur := r.trees[method]
		for _, part := range parts {
			idx := sort.Search(len(cur.children), func(i int) bool { return cur.children[i].key >= part })
			if idx < len(cur.children) && cur.children[idx].key == part {
				cur = cur.children[idx].node
			} else {
				newNode := &node{path: part, children: []childNode{}}
				cur.children = insertChild(cur.children, part, newNode)
				cur = newNode
			}
		}
		cur.middleware = subRouter.middleware
		for _, child := range tree.children {
			cur.children = insertChild(cur.children, child.key, child.node)
		}
	}
}

func insertChild(children []childNode, key string, node *node) []childNode {
	idx := sort.Search(len(children), func(i int) bool { return children[i].key >= key })
	if idx < len(children) && children[idx].key == key {
		children[idx].node = node
	} else {
		newChild := childNode{key: key, node: node}
		children = append(children, childNode{})
		copy(children[idx+1:], children[idx:])
		children[idx] = newChild
	}
	return children
}

// Optimized addRoute: Pre-build middleware chain
func (r *Router) addRoute(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if _, exists := r.trees[method]; !exists {
		r.trees[method] = &node{children: []childNode{}}
	}
	cur := r.trees[method]
	parts := parsePath(path)
	for _, part := range parts {
		var key string
		if strings.HasPrefix(part, ":") {
			key = ":"
		} else if part == "*" {
			cur.wildcard = true
			break
		} else {
			key = part
		}
		idx := sort.Search(len(cur.children), func(i int) bool { return cur.children[i].key >= key })
		if idx < len(cur.children) && cur.children[idx].key == key {
			cur = cur.children[idx].node
		} else {
			newNode := &node{path: part, children: []childNode{}}
			cur.children = insertChild(cur.children, key, newNode)
			cur = newNode
		}
	}
	// Combine global and route-specific middleware and pre-build the chain
	allMiddleware := append(r.middleware, middleware...)
	wrapped := handler
	for i := len(allMiddleware) - 1; i >= 0; i-- {
		mw := allMiddleware[i]
		next := wrapped
		wrapped = func(c *Context) {
			if !c.IsAborted() {
				mw(c, func() { next(c) })
			}
		}
	}
	cur.handler = wrapped
}

// Optimized findHandlerAndMiddleware: Pre-allocate middleware slice
func (r *Router) findHandlerAndMiddleware(method, path string) (HandlerFunc, []Param) {
	r.mutex.RLock() // Use read lock only
	defer r.mutex.RUnlock()
	if tree, exists := r.trees[method]; exists {
		cur := tree
		var params []Param
		start := 0
		if len(path) > 0 && path[0] == '/' {
			start = 1
		}
		for i := start; i <= len(path); i++ {
			if i == len(path) || path[i] == '/' {
				segment := path[start:i]
				idx := sort.Search(len(cur.children), func(j int) bool { return cur.children[j].key >= segment })
				if idx < len(cur.children) && cur.children[idx].key == segment {
					cur = cur.children[idx].node
				} else {
					idx = sort.Search(len(cur.children), func(j int) bool { return cur.children[j].key >= ":" })
					if idx < len(cur.children) && cur.children[idx].key == ":" {
						cur = cur.children[idx].node
						params = append(params, Param{Key: cur.path[1:], Value: segment})
					} else if cur.wildcard {
						break
					} else {
						return nil, nil
					}
				}
				start = i + 1
			}
		}
		if cur.handler != nil {
			return cur.handler, params
		}
	}
	return nil, nil
}

// Improved ServeHTTP with proper timeout and cancellation support
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// Wrap the response writer to track if headers have been sent
	trackedWriter := WrapResponseWriter(w)

	// Get a context from the pool
	ctx := r.pool.Get().(*Context)
	ctx.Writer = trackedWriter
	ctx.Request = req
	ctx.Params = ctx.Params[:0] // Reuse slice capacity but clear contents

	// Replace the Values map for a clean state
	ctx.Values = make(map[string]interface{})
	ctx.Values["router"] = r // Store router reference for access to httpClient

	ctx.ValidationErrs = nil
	ctx.aborted = false

	// Ensure context is returned to pool when done
	defer r.pool.Put(ctx)

	// Use the request's context for detecting cancellation and timeouts
	reqCtx := req.Context()

	// Set up a goroutine to monitor for cancellation if the context can be canceled
	if reqCtx.Done() != nil {
		// We need a way to signal when we're completely done handling this request
		finished := make(chan struct{})
		defer close(finished)

		go func() {
			select {
			case <-reqCtx.Done():
				// Request was canceled or timed out
				ctx.Abort()

				// Only send error response if we haven't already sent headers
				if !trackedWriter.Written() {
					// Determine the appropriate status code based on the error
					statusCode := http.StatusGatewayTimeout // Default to 504 for timeouts

					if reqCtx.Err() == context.Canceled {
						statusCode = 499 // Nginx's code for client closed request
					}

					http.Error(trackedWriter, fmt.Sprintf("Request %v", reqCtx.Err()), statusCode)
				}
			case <-finished:
				// Handler completed normally, do nothing
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
		return
	}

	// Set parameters to context
	ctx.Params = params

	// Capture panics from handlers and provide proper error handling
	defer func() {
		if err := recover(); err != nil {
			// Abort the context to prevent further processing
			ctx.Abort()

			// Check if response was already started
			if !trackedWriter.Written() {
				if r.config.ErrorHandler != nil {
					r.config.ErrorHandler(ctx, fmt.Errorf("%v", err))
				} else {
					http.Error(trackedWriter, "Internal Server Error", http.StatusInternalServerError)
				}
			} else {
				// If headers were already sent, we can only log the error
				fmt.Printf("Panic occurred after response was started: %v\n", err)
			}
		}
	}()

	// Execute the handler (middleware chain is already pre-built in addRoute)
	handler(ctx)
}

// TrackedResponseWriter wraps http.ResponseWriter to track if headers have been sent
type TrackedResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
	bytesWritten  int64
}

// WrapResponseWriter creates a new TrackedResponseWriter
func WrapResponseWriter(w http.ResponseWriter) *TrackedResponseWriter {
	return &TrackedResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK, // Default status code
	}
}

// WriteHeader records that headers have been written
func (w *TrackedResponseWriter) WriteHeader(statusCode int) {
	if !w.headerWritten {
		w.statusCode = statusCode
		w.ResponseWriter.WriteHeader(statusCode)
		w.headerWritten = true
	}
}

// Write records that data (and implicitly headers) have been written
func (w *TrackedResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK) // Implicit 200 OK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// Status returns the HTTP status code that was set
func (w *TrackedResponseWriter) Status() int {
	return w.statusCode
}

// Written returns whether headers have been sent
func (w *TrackedResponseWriter) Written() bool {
	return w.headerWritten
}

// BytesWritten returns the number of bytes written
func (w *TrackedResponseWriter) BytesWritten() int64 {
	return w.bytesWritten
}

// Unwrap returns the original ResponseWriter
func (w *TrackedResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Flush implements http.Flusher interface if the underlying writer supports it
func (w *TrackedResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker interface if the underlying writer supports it
func (w *TrackedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// Push implements http.Pusher interface if the underlying writer supports it (for HTTP/2)
func (w *TrackedResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return fmt.Errorf("underlying ResponseWriter does not implement http.Pusher")
}

// Optimized Server Start Methods: Add timeouts
func (r *Router) Start(port string) error {
	server := &http.Server{
		Addr:           ":" + port,
		Handler:        r,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}
	fmt.Printf("Nanite server running on port %s\n", port)
	return server.ListenAndServe()
}

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

// Context Methods (unchanged for brevity)
func (c *Context) Set(key string, value interface{}) {
	if c.Values == nil {
		c.Values = make(map[string]interface{})
	}
	c.Values[key] = value
}

func (c *Context) Get(key string) interface{} {
	if c.Values != nil {
		return c.Values[key]
	}
	return nil
}

func (c *Context) Bind(v interface{}) error {
	if err := json.NewDecoder(c.Request.Body).Decode(v); err != nil {
		return fmt.Errorf("failed to decode JSON: %w", err)
	}
	return nil
}

func (c *Context) FormValue(key string) string {
	return c.Request.FormValue(key)
}

func (c *Context) Query(key string) string {
	return c.Request.URL.Query().Get(key)
}

func (c *Context) GetParam(key string) (string, bool) {
	// Unrolled loop for small slices can be faster
	params := c.Params
	n := len(params)

	if n > 0 && params[0].Key == key {
		return params[0].Value, true
	}
	if n > 1 && params[1].Key == key {
		return params[1].Value, true
	}
	if n > 2 && params[2].Key == key {
		return params[2].Value, true
	}

	// Fall back to regular loop for more params
	for i := 3; i < n; i++ {
		if params[i].Key == key {
			return params[i].Value, true
		}
	}

	return "", false
}

func (c *Context) MustParam(key string) (string, error) {
	if val, ok := c.GetParam(key); ok && val != "" {
		return val, nil
	}
	return "", fmt.Errorf("required parameter %s missing or empty", key)
}

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

func (c *Context) JSON(status int, data interface{}) {
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(status)
	if err := json.NewEncoder(c.Writer).Encode(data); err != nil {
		http.Error(c.Writer, "Failed to encode JSON", http.StatusInternalServerError)
	}
}

func (c *Context) String(status int, data string) {
	c.Writer.Header().Set("Content-Type", "text/plain")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(data))
}

func (c *Context) HTML(status int, html string) {
	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Writer.WriteHeader(status)
	c.Writer.Write([]byte(html))
}

func (c *Context) SetHeader(key, value string) {
	c.Writer.Header().Set(key, value)
}

func (c *Context) Status(status int) {
	c.Writer.WriteHeader(status)
}

func (c *Context) Redirect(status int, url string) {
	if status < 300 || status > 399 {
		c.String(http.StatusBadRequest, "redirect status must be 3xx")
		return
	}
	c.Writer.Header().Set("Location", url)
	c.Writer.WriteHeader(status)
}

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

func (c *Context) CheckValidation() bool {
	if len(c.ValidationErrs) > 0 {
		c.JSON(http.StatusBadRequest, map[string]interface{}{"errors": c.ValidationErrs})
		return false
	}
	return true
}

// Improved WebSocket handler wrapper with proper lifecycle management
func (r *Router) wrapWebSocketHandler(handler WebSocketHandler) HandlerFunc {
	return func(ctx *Context) {
		// Upgrade the connection
		conn, err := r.config.Upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
		if err != nil {
			http.Error(ctx.Writer, "Failed to upgrade to WebSocket", http.StatusBadRequest)
			return
		}

		// Set connection parameters
		conn.SetReadLimit(r.config.WebSocket.MaxMessageSize)

		// Create a cancelable context for the WebSocket connection
		wsCtx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Create a WaitGroup to ensure all goroutines are done before returning
		var wg sync.WaitGroup

		// Create a cleanup function to handle proper connection teardown
		cleanup := func() {
			cancel()     // Cancel context to signal all goroutines to exit
			conn.Close() // Ensure connection is closed
			wg.Wait()    // Wait for all goroutines to exit
		}
		defer cleanup()

		// Set up ping/pong handlers to detect dead connections
		conn.SetPongHandler(func(string) error {
			// Reset read deadline when we get a pong response
			conn.SetReadDeadline(time.Now().Add(r.config.WebSocket.ReadTimeout))
			return nil
		})

		// Start a goroutine to periodically send pings
		wg.Add(1)
		go func() {
			defer wg.Done()
			pingTicker := time.NewTicker(r.config.WebSocket.PingInterval)
			defer pingTicker.Stop()

			for {
				select {
				case <-pingTicker.C:
					// Set write deadline for the ping
					conn.SetWriteDeadline(time.Now().Add(r.config.WebSocket.WriteTimeout))
					if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
						// Connection is probably dead, exit the goroutine
						return
					}
				case <-wsCtx.Done():
					// Context canceled, exit the goroutine
					return
				}
			}
		}()

		// Handle close signals for graceful shutdown
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Listen for server shutdown or client closure
			select {
			case <-ctx.Request.Context().Done():
				// Request context canceled (server shutting down)
				conn.WriteControl(
					websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseGoingAway, "Server shutting down"),
					time.Now().Add(time.Second),
				)
				return
			case <-wsCtx.Done():
				// Connection context canceled (normal closure)
				return
			}
		}()

		// Set initial read deadline
		conn.SetReadDeadline(time.Now().Add(r.config.WebSocket.ReadTimeout))

		// Call the actual handler with the managed connection
		handler(conn, ctx)

		// After handler returns, ensure proper closure
		conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(time.Second),
		)
	}
}

func LoggingMiddleware() MiddlewareFunc {
	return func(c *Context, next func()) {
		start := time.Now()
		next()
		elapsed := time.Since(start)

		fmt.Printf("[%s] %s %s - %v\n",
			time.Now().Format("2006-01-02 15:04:05"),
			c.Request.Method,
			c.Request.URL.Path,
			elapsed,
		)
	}
}
