// Package nanite provides a lightweight, high-performance HTTP router for Go.
package nanite

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

// Group represents a route group with shared path prefix and middleware.
// It allows organizing routes into logical sections and applying
// common middleware to multiple routes efficiently.
type Group struct {
	router     *Router          // Reference to the parent router
	prefix     string           // Path prefix for all routes in this group
	middleware []MiddlewareFunc // Middleware applied to all routes in this group
}

// Group creates a new route group with the given path prefix and optional middleware.
// All routes registered on this group will have the prefix prepended to their paths
// and the middleware applied before their handlers.
//
// Parameters:
//   - prefix: The path prefix for all routes in this group
//   - middleware: Optional middleware functions to apply to all routes in this group
//
// Returns:
//   - *Group: A new route group instance
func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *Group {
	return &Group{
		router:     r,
		prefix:     prefix,
		middleware: middleware,
	}
}

// Get registers a handler for GET requests on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - path: The route path, relative to the group's prefix
//   - handler: The handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Get(fullPath, handler, allMiddleware...)
}

// Post registers a handler for POST requests on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - path: The route path, relative to the group's prefix
//   - handler: The handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Post(fullPath, handler, allMiddleware...)
}

// Put registers a handler for PUT requests on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - path: The route path, relative to the group's prefix
//   - handler: The handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Put(fullPath, handler, allMiddleware...)
}

// Delete registers a handler for DELETE requests on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - path: The route path, relative to the group's prefix
//   - handler: The handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Delete(fullPath, handler, allMiddleware...)
}

// Patch registers a handler for PATCH requests on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - path: The route path, relative to the group's prefix
//   - handler: The handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Patch(fullPath, handler, allMiddleware...)
}

// Options registers a handler for OPTIONS requests on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - path: The route path, relative to the group's prefix
//   - handler: The handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Options(fullPath, handler, allMiddleware...)
}

// Head registers a handler for HEAD requests on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - path: The route path, relative to the group's prefix
//   - handler: The handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Head(fullPath, handler, allMiddleware...)
}

// Handle registers a handler for the specified HTTP method on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - method: The HTTP method (GET, POST, PUT, etc.)
//   - path: The route path, relative to the group's prefix
//   - handler: The handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Handle(method, fullPath, handler, allMiddleware...)
}

// WebSocket registers a WebSocket handler on the group's path prefix.
// The path is normalized and combined with the group's prefix.
//
// Parameters:
//   - path: The route path, relative to the group's prefix
//   - handler: The WebSocket handler function to execute for matching requests
//   - middleware: Optional route-specific middleware functions
func (g *Group) WebSocket(path string, handler WebSocketHandler, middleware ...MiddlewareFunc) {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.WebSocket(fullPath, handler, allMiddleware...)
}

// Group creates a sub-group with an additional prefix and optional middleware.
// The new group inherits all middleware from the parent group.
//
// Parameters:
//   - prefix: The additional path prefix for the sub-group
//   - middleware: Optional middleware functions specific to the sub-group
//
// Returns:
//   - *Group: A new route group instance
func (g *Group) Group(prefix string, middleware ...MiddlewareFunc) *Group {
	fullPrefix := normalizePath(g.prefix + prefix)
	allMiddleware := append(g.middleware, middleware...)
	return &Group{
		router:     g.router,
		prefix:     fullPrefix,
		middleware: allMiddleware,
	}
}

// Use adds middleware to the group.
// These middleware functions will be applied to all routes in this group.
//
// Parameters:
//   - middleware: The middleware functions to add
func (g *Group) Use(middleware ...MiddlewareFunc) {
	g.middleware = append(g.middleware, middleware...)
}

// normalizePath ensures paths start with a slash and don't end with one.
// This optimized version avoids unnecessary allocations for common cases.
//
// Parameters:
//   - path: The path to normalize
//
// Returns:
//   - string: The normalized path
func normalizePath(path string) string {
	// Fast path for empty string
	if path == "" {
		return "/"
	}

	// Fast path for root path
	if path == "/" {
		return "/"
	}

	// Check if we need to add a leading slash
	needsPrefix := path[0] != '/'

	// Check if we need to remove a trailing slash
	length := len(path)
	needsSuffix := length > 1 && path[length-1] == '/'

	// Fast path: if no changes needed, return original
	if !needsPrefix && !needsSuffix {
		return path
	}

	// Calculate the exact size needed for the new string
	newLen := length
	if needsPrefix {
		newLen++
	}
	if needsSuffix {
		newLen--
	}

	// Create a new string with the exact capacity needed
	var b strings.Builder
	b.Grow(newLen)

	// Add leading slash if needed
	if needsPrefix {
		b.WriteByte('/')
	}

	// Write the path, excluding trailing slash if needed
	if needsSuffix {
		b.WriteString(path[:length-1])
	} else {
		b.WriteString(path)
	}

	return b.String()
}

// ### Validation Middleware

func ValidationMiddleware(chains ...*ValidationChain) MiddlewareFunc {
	return func(ctx *Context, next func()) {
		if ctx.IsAborted() {
			return
		}

		// Handle request data parsing for POST, PUT, PATCH, DELETE methods
		if len(chains) > 0 && (ctx.Request.Method == "POST" || ctx.Request.Method == "PUT" ||
			ctx.Request.Method == "PATCH" || ctx.Request.Method == "DELETE") {

			contentType := ctx.Request.Header.Get("Content-Type")

			// Parse form data (application/x-www-form-urlencoded or multipart/form-data)
			if strings.HasPrefix(contentType, "application/x-www-form-urlencoded") ||
				strings.HasPrefix(contentType, "multipart/form-data") {
				if err := ctx.Request.ParseForm(); err != nil {
					ve := getValidationError("", "failed to parse form data")
					if ctx.ValidationErrs == nil {
						ctx.ValidationErrs = make(ValidationErrors, 0, 1)
					}
					ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
					putValidationError(ve)
					ctx.JSON(http.StatusBadRequest, map[string]interface{}{"errors": ctx.ValidationErrs})
					return
				}

				// Store form data in ctx.Values
				formData := getMap()
				for key, values := range ctx.Request.Form {
					if len(values) == 1 {
						formData[key] = values[0]
					} else {
						formData[key] = values
					}
				}
				ctx.Values["formData"] = formData
			}

			// Parse JSON body (application/json)
			if strings.HasPrefix(contentType, "application/json") {
				buffer := bufferPool.Get().(*bytes.Buffer)
				buffer.Reset()
				defer bufferPool.Put(buffer)

				if _, err := io.Copy(buffer, ctx.Request.Body); err != nil {
					ve := getValidationError("", "failed to read request body")
					if ctx.ValidationErrs == nil {
						ctx.ValidationErrs = make(ValidationErrors, 0, 1)
					}
					ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
					putValidationError(ve)
					ctx.JSON(http.StatusBadRequest, map[string]interface{}{"errors": ctx.ValidationErrs})
					return
				}

				bodyBytes := buffer.Bytes()
				// Restore request body for downstream use
				ctx.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

				var body map[string]interface{}
				if err := json.Unmarshal(bodyBytes, &body); err != nil {
					ve := getValidationError("", "invalid JSON")
					if ctx.ValidationErrs == nil {
						ctx.ValidationErrs = make(ValidationErrors, 0, 1)
					}
					ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
					putValidationError(ve)
					ctx.JSON(http.StatusBadRequest, map[string]interface{}{"errors": ctx.ValidationErrs})
					return
				}

				ctx.Values["body"] = body
			}
		}

		// Attach validation rules to LazyFields
		for _, chain := range chains {
			field := ctx.Field(chain.field)                   // Get or create the LazyField
			field.rules = append(field.rules, chain.rules...) // Append validation rules
		}

		// Proceed to the next middleware or handler
		next()
		for _, chain := range chains {
			chain.Release()
		}
	}
}

// ExecuteMiddleware executes the middleware chain for a route
func executeMiddlewareChain(c *Context, handler HandlerFunc, middleware []MiddlewareFunc) {
	// No middleware, just execute the handler
	if len(middleware) == 0 {
		handler(c)
		return
	}

	// Build the middleware chain
	var next func()
	var index int

	next = func() {
		if index < len(middleware) {
			currentMiddleware := middleware[index]
			index++
			currentMiddleware(c, next)
		} else {
			// End of middleware chain, execute the handler
			handler(c)
		}
	}

	// Start the middleware chain
	index = 0
	next()
}

// ### tracked_response_writer

// TrackedResponseWriter wraps http.ResponseWriter to track if headers have been sent.
type TrackedResponseWriter struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
	bytesWritten  int64
}

// WrapResponseWriter creates a new TrackedResponseWriter.
func WrapResponseWriter(w http.ResponseWriter) *TrackedResponseWriter {
	return &TrackedResponseWriter{
		ResponseWriter: w,
		statusCode:     http.StatusOK,
	}
}

// WriteHeader records that headers have been written.
func (w *TrackedResponseWriter) WriteHeader(statusCode int) {
	if !w.headerWritten {
		w.statusCode = statusCode
		w.ResponseWriter.WriteHeader(statusCode)
		w.headerWritten = true
	}
}

// Write records that data (and implicitly headers) have been written.
func (w *TrackedResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytesWritten += int64(n)
	return n, err
}

// Status returns the HTTP status code that was set.
func (w *TrackedResponseWriter) Status() int {
	return w.statusCode
}

// Written returns whether headers have been sent.
func (w *TrackedResponseWriter) Written() bool {
	return w.headerWritten
}

// BytesWritten returns the number of bytes written.
func (w *TrackedResponseWriter) BytesWritten() int64 {
	return w.bytesWritten
}

// Unwrap returns the original ResponseWriter.
func (w *TrackedResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Flush implements http.Flusher interface if the underlying writer supports it.
func (w *TrackedResponseWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

// Hijack implements http.Hijacker interface if the underlying writer supports it.
func (w *TrackedResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hijacker, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hijacker.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not implement http.Hijacker")
}

// Push implements http.Pusher interface if the underlying writer supports it.
func (w *TrackedResponseWriter) Push(target string, opts *http.PushOptions) error {
	if pusher, ok := w.ResponseWriter.(http.Pusher); ok {
		return pusher.Push(target, opts)
	}
	return fmt.Errorf("underlying ResponseWriter does not implement http.Pusher")
}

// ### LRU Implementation

// routeCacheKey is the key used in the LRU cache.
type routeCacheKey struct {
	method string
	path   string
}

// entry represents a single entry in the LRU cache.
type entry struct {
	key     routeCacheKey
	handler HandlerFunc
	params  []Param
	prev    int // Index of the previous entry in the doubly-linked list
	next    int // Index of the next entry in the doubly-linked list
}

// LRUCache is a thread-safe least recently used cache with fixed capacity.
type LRUCache struct {
	capacity  int
	mutex     sync.RWMutex
	entries   []entry               // Array of cache entries
	indices   map[routeCacheKey]int // Map from key to index in entries
	head      int                   // Index of the most recently used entry
	tail      int                   // Index of the least recently used entry
	hits      int64                 // Number of cache hits
	misses    int64                 // Number of cache misses
	maxParams int                   // Configurable max parameters
}

// Define multiple sync.Pools for different parameter slice sizes
var paramSlicePools = [3]sync.Pool{
	{New: func() interface{} { return make([]Param, 0, 4) }},  // Capacity 4
	{New: func() interface{} { return make([]Param, 0, 8) }},  // Capacity 8
	{New: func() interface{} { return make([]Param, 0, 16) }}, // Capacity 16
}

// getParamSlice retrieves a parameter slice from the appropriate pool based on paramCount.
func getParamSlice(paramCount int) []Param {
	if paramCount <= 4 {
		return paramSlicePools[0].Get().([]Param)[:0]
	} else if paramCount <= 8 {
		return paramSlicePools[1].Get().([]Param)[:0]
	} else {
		return paramSlicePools[2].Get().([]Param)[:0]
	}
}

// putParamSlice returns a parameter slice to the appropriate pool based on its capacity.
func putParamSlice(s []Param) {
	cap := cap(s)
	if cap == 4 {
		paramSlicePools[0].Put(s)
	} else if cap == 8 {
		paramSlicePools[1].Put(s)
	} else if cap == 16 {
		paramSlicePools[2].Put(s)
	}
	// Slices with unexpected capacities are discarded (handled by GC)
}

// NewLRUCache creates a new LRU cache with the specified capacity and maxParams.
func NewLRUCache(capacity, maxParams int) *LRUCache {
	// Set defaults if invalid values provided
	if capacity <= 0 {
		capacity = 1024 // Default size
	}
	if maxParams <= 0 {
		maxParams = 10 // Default max parameters
	}

	c := &LRUCache{
		capacity:  capacity,
		maxParams: maxParams,
		entries:   make([]entry, capacity),
		indices:   make(map[routeCacheKey]int, capacity),
		head:      0,
		tail:      capacity - 1,
	}

	// Initialize the circular doubly-linked list
	for i := 0; i < capacity; i++ {
		c.entries[i].next = (i + 1) % capacity
		c.entries[i].prev = (i - 1 + capacity) % capacity
	}

	return c
}

// Add adds a new entry to the cache or updates an existing one.
func (c *LRUCache) Add(method, path string, handler HandlerFunc, params []Param) {
	key := routeCacheKey{method: method, path: path}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Check if the key already exists
	if idx, exists := c.indices[key]; exists {
		// Update existing entry
		entry := &c.entries[idx]
		entry.handler = handler

		// Update params: replace with a new slice from the pool
		if entry.params != nil {
			putParamSlice(entry.params)
		}
		newParams := getParamSlice(len(params))
		newParams = append(newParams, params...)
		entry.params = newParams

		// Move to front (most recently used)
		c.moveToFront(idx)
		return
	}

	// Cache is full or empty, reuse the least recently used entry (tail)
	idx := c.tail
	oldKey := c.entries[idx].key

	// Remove old key from map if it exists
	if oldKey.method != "" || oldKey.path != "" {
		delete(c.indices, oldKey)

		// Return old params slice to pool if it exists
		if c.entries[idx].params != nil {
			putParamSlice(c.entries[idx].params)
		}
	}

	// Update entry with new data
	entry := &c.entries[idx]
	entry.key = key
	entry.handler = handler

	// Get a new param slice from the appropriate pool
	newParams := getParamSlice(len(params))
	newParams = append(newParams, params...)
	entry.params = newParams

	// Update index map and move to front
	c.indices[key] = idx
	c.moveToFront(idx)
}

// Get retrieves an entry from the cache.
func (c *LRUCache) Get(method, path string) (HandlerFunc, []Param, bool) {
	key := routeCacheKey{method: method, path: path}

	c.mutex.RLock()
	idx, exists := c.indices[key]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		c.mutex.RUnlock()
		return nil, nil, false
	}

	// Get entry data under read lock
	entry := &c.entries[idx]
	handler := entry.handler

	// Handle parameters: copy if present, set to nil if not
	var params []Param
	if len(entry.params) > 0 {
		params = getParamSlice(len(entry.params))
		params = append(params, entry.params...)
	} else {
		params = nil
	}
	c.mutex.RUnlock()

	// Promote entry to front (requires write lock)
	c.mutex.Lock()
	c.moveToFront(idx)
	c.mutex.Unlock()

	atomic.AddInt64(&c.hits, 1)
	return handler, params, true
}

// moveToFront moves an entry to the front of the list (most recently used).
func (c *LRUCache) moveToFront(idx int) {
	// Already at front, nothing to do
	if idx == c.head {
		return
	}

	// Remove from current position
	entry := &c.entries[idx]
	prevIdx := entry.prev
	nextIdx := entry.next

	c.entries[prevIdx].next = nextIdx
	c.entries[nextIdx].prev = prevIdx

	// Update tail if we moved the tail
	if idx == c.tail {
		c.tail = prevIdx
	}

	// Insert at front
	oldHead := c.head
	oldHeadPrev := c.entries[oldHead].prev

	entry.next = oldHead
	entry.prev = oldHeadPrev

	c.entries[oldHead].prev = idx
	c.entries[oldHeadPrev].next = idx

	// Update head
	c.head = idx
}

// Clear removes all entries from the cache and returns param slices to pools.
func (c *LRUCache) Clear() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	for i := range c.entries {
		if c.entries[i].params != nil {
			putParamSlice(c.entries[i].params)
			c.entries[i].params = nil
		}
		c.entries[i].key = routeCacheKey{}
		c.entries[i].handler = nil
	}

	// Reset the cache
	c.indices = make(map[routeCacheKey]int, c.capacity)
	c.head = 0
	c.tail = c.capacity - 1

	// Re-initialize the linked list
	for i := 0; i < c.capacity; i++ {
		c.entries[i].next = (i + 1) % c.capacity
		c.entries[i].prev = (i - 1 + c.capacity) % c.capacity
	}

	// Reset statistics
	atomic.StoreInt64(&c.hits, 0)
	atomic.StoreInt64(&c.misses, 0)
}

// Stats returns cache hit/miss statistics
func (c *LRUCache) Stats() (hits, misses int64, ratio float64) {
	hits = atomic.LoadInt64(&c.hits)
	misses = atomic.LoadInt64(&c.misses)

	total := hits + misses
	if total > 0 {
		ratio = float64(hits) / float64(total)
	}
	return
}

// SetRouteCacheOptions configures the route cache with the specified size and maximum parameters
func (r *Router) SetRouteCacheOptions(size, maxParams int) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Store settings in config
	if r.config == nil {
		r.config = &Config{}
	}
	r.config.RouteCacheSize = size
	r.config.RouteMaxParams = maxParams

	// Update or disable the cache based on size
	if size <= 0 {
		r.routeCache = nil // Disable caching
	} else {
		r.routeCache = NewLRUCache(size, maxParams)
	}
}
