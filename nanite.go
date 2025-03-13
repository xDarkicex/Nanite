package nanite

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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

type Config struct {
	NotFoundHandler HandlerFunc
	ErrorHandler    func(*Context, error)
	Upgrader        *websocket.Upgrader
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
		trees:  make(map[string]*node),
		config: &Config{},
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
		CheckOrigin: func(*http.Request) bool { return true },
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

// Optimized ServeHTTP: Replace Values map instead of clearing
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := r.pool.Get().(*Context)
	ctx.Writer = w
	ctx.Request = req
	ctx.Params = nil
	ctx.Values = make(map[string]interface{}) // Replace instead of clearing
	ctx.ValidationErrs = nil
	ctx.aborted = false

	defer r.pool.Put(ctx)
	handler, params := r.findHandlerAndMiddleware(req.Method, req.URL.Path)
	if handler == nil {
		if r.config.NotFoundHandler != nil {
			r.config.NotFoundHandler(ctx)
		} else {
			http.NotFound(w, req)
		}
		return
	}
	ctx.Params = params

	// Middleware chain is pre-built in addRoute, so just call the handler
	defer func() {
		if err := recover(); err != nil {
			if r.config.ErrorHandler != nil {
				r.config.ErrorHandler(ctx, fmt.Errorf("%v", err))
			} else {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}
	}()
	handler(ctx)
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
	for _, p := range c.Params {
		if p.Key == key {
			return p.Value, true
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
