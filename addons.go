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

// routeCacheKey uniquely identifies an entry in the LRU cache.
// It combines HTTP method and path to form a composite key.
type routeCacheKey struct {
	method string // HTTP method (GET, POST, etc.)
	path   string // Request path
}

// entry represents a single item in the LRU cache.
// It contains the cached data and pointers for the doubly-linked list.
type entry struct {
	key     routeCacheKey // The cache key (method + path)
	handler HandlerFunc   // The handler function for this route
	params  []Param       // Route parameters
	prev    int           // Index of the previous entry in the doubly-linked list
	next    int           // Index of the next entry in the doubly-linked list
}

// LRUCache implements a thread-safe least recently used cache with fixed capacity.
// It uses an array-based doubly-linked list for O(1) LRU operations and maintains
// hit/miss statistics for performance monitoring.
type LRUCache struct {
	capacity  int                   // Maximum number of entries the cache can hold
	mutex     sync.RWMutex          // Read-write mutex for thread safety
	entries   []entry               // Array of cache entries
	indices   map[routeCacheKey]int // Map from key to index in entries
	head      int                   // Index of the most recently used entry
	tail      int                   // Index of the least recently used entry
	hits      int64                 // Number of cache hits (atomic counter)
	misses    int64                 // Number of cache misses (atomic counter)
	maxParams int                   // Configurable max parameters per entry
}

// nextPowerOfTwo rounds up to the next power of two.
// This improves performance by aligning with hash table implementation details.
// For example: 10 becomes 16, 120 becomes 128, etc.
func nextPowerOfTwo(n int) int {
	if n <= 0 {
		return 1
	}

	n--
	n |= n >> 1
	n |= n >> 2
	n |= n >> 4
	n |= n >> 8
	n |= n >> 16
	n++
	return n
}

// Define multiple sync.Pools for different parameter slice sizes.
// This reduces GC pressure by reusing parameter slices based on their capacity.
var paramSlicePools = [5]sync.Pool{
	{New: func() interface{} { return make([]Param, 0, 4) }},  // Capacity 4
	{New: func() interface{} { return make([]Param, 0, 8) }},  // Capacity 8
	{New: func() interface{} { return make([]Param, 0, 16) }}, // Capacity 16
	{New: func() interface{} { return make([]Param, 0, 32) }}, // Capacity 32
	{New: func() interface{} { return make([]Param, 0, 64) }}, // Capacity 64
}

// getParamSlice retrieves a parameter slice from the appropriate pool based on paramCount.
// This function optimizes memory usage by selecting a pool with an appropriate capacity
// for the requested number of parameters.
func getParamSlice(paramCount int) []Param {
	if paramCount <= 4 {
		return paramSlicePools[0].Get().([]Param)[:0]
	} else if paramCount <= 8 {
		return paramSlicePools[1].Get().([]Param)[:0]
	} else if paramCount <= 16 {
		return paramSlicePools[2].Get().([]Param)[:0]
	} else if paramCount <= 32 {
		return paramSlicePools[3].Get().([]Param)[:0]
	} else {
		return paramSlicePools[4].Get().([]Param)[:0]
	}
}

// putParamSlice returns a parameter slice to the appropriate pool based on its capacity.
// This function recycles parameter slices to reduce garbage collection overhead.
// Slices with capacities that don't match a pool are left for the garbage collector.
func putParamSlice(s []Param) {
	cap := cap(s)
	if cap == 4 {
		paramSlicePools[0].Put(s)
	} else if cap == 8 {
		paramSlicePools[1].Put(s)
	} else if cap == 16 {
		paramSlicePools[2].Put(s)
	} else if cap == 32 {
		paramSlicePools[3].Put(s)
	} else if cap == 64 {
		paramSlicePools[4].Put(s)
	}
	// Slices with unexpected capacities are discarded (handled by GC)
}

// Simple string interning for method and path.
// This reduces memory usage by storing only one copy of each unique string.
var stringInterner = struct {
	sync.RWMutex
	m map[string]string
}{
	m: make(map[string]string, 16), // Preallocate for common HTTP methods
}

// internString returns a single canonical instance of the given string.
// If the string has been seen before, the stored version is returned.
// Otherwise, the input string becomes the canonical version.
// This reduces memory usage when the same strings are frequently used.
func internString(s string) string {
	stringInterner.RLock()
	if interned, ok := stringInterner.m[s]; ok {
		stringInterner.RUnlock()
		return interned
	}
	stringInterner.RUnlock()

	stringInterner.Lock()
	defer stringInterner.Unlock()
	if interned, ok := stringInterner.m[s]; ok {
		return interned
	}

	stringInterner.m[s] = s // Store the string itself as the canonical copy
	return s
}

// NewLRUCache creates a new LRU cache with the specified capacity and maxParams.
// The capacity determines how many entries can be stored before eviction begins.
// The maxParams parameter configures the maximum number of parameters per entry.
// The function applies reasonable defaults and bounds if invalid values are provided.
func NewLRUCache(capacity, maxParams int) *LRUCache {
	// Set defaults if invalid values provided
	if capacity <= 0 {
		capacity = 1024 // Default size
	}

	// Set a reasonable upper limit to prevent unexpected issues
	if capacity > 16384 {
		capacity = 16384
	}

	// Round capacity to next power of two for better performance
	capacity = nextPowerOfTwo(capacity)
	if maxParams <= 0 {
		maxParams = 10 // Default max parameters
	}

	c := &LRUCache{
		capacity:  capacity,
		maxParams: maxParams,
		entries:   make([]entry, capacity),
		indices:   make(map[routeCacheKey]int, capacity*2), // Oversize to avoid rehashing
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
// If the key already exists, the entry is updated and moved to the front of the LRU list.
// If the key doesn't exist, the least recently used entry is replaced with the new entry.
// This method is thread-safe and optimizes memory usage through string interning and slice pooling.
func (c *LRUCache) Add(method, path string, handler HandlerFunc, params []Param) {
	// Intern strings to reduce allocations
	method = internString(method)
	path = internString(path)
	c.mutex.Lock()
	defer c.mutex.Unlock()
	key := routeCacheKey{method: method, path: path}
	// Check if the key already exists
	if idx, exists := c.indices[key]; exists {
		entry := &c.entries[idx]
		entry.handler = handler
		// Reuse params slice if capacity is sufficient
		if cap(entry.params) >= len(params) {
			entry.params = entry.params[:len(params)]
			copy(entry.params, params)
		} else {
			if entry.params != nil {
				putParamSlice(entry.params)
			}
			newParams := getParamSlice(len(params))
			copy(newParams, params)
			entry.params = newParams
		}
		c.moveToFront(idx)
		return
	}

	// New entry: reuse the tail slot
	idx := c.tail
	entry := &c.entries[idx]
	oldKey := entry.key
	if oldKey.method != "" || oldKey.path != "" {
		delete(c.indices, oldKey)
	}

	if entry.params != nil {
		putParamSlice(entry.params)
	}

	// Update the existing key struct instead of creating a new one
	entry.key.method = method
	entry.key.path = path
	entry.handler = handler
	// Allocate and copy params
	newParams := getParamSlice(len(params))
	copy(newParams, params)
	entry.params = newParams
	c.indices[entry.key] = idx
	c.moveToFront(idx)
}

// Get retrieves an entry from the cache.
// It returns the handler function, parameters, and a boolean indicating whether the entry was found.
// If the entry is found, it's moved to the front of the LRU list.
// This method is thread-safe and includes panic recovery for robustness.
func (c *LRUCache) Get(method, path string) (HandlerFunc, []Param, bool) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in Get: %v\n", r)
			return
		}
	}()

	// Intern strings for consistency
	method = internString(method)
	path = internString(path)
	key := routeCacheKey{method: method, path: path}
	c.mutex.RLock()
	idx, exists := c.indices[key]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		c.mutex.RUnlock()
		return nil, nil, false
	}

	entry := &c.entries[idx]
	handler := entry.handler
	var params []Param
	if len(entry.params) > 0 {
		params = getParamSlice(len(entry.params))
		copy(params, entry.params)
	} else {
		params = nil
	}

	c.mutex.RUnlock()
	c.mutex.Lock()
	c.moveToFront(idx)
	c.mutex.Unlock()
	atomic.AddInt64(&c.hits, 1)
	return handler, params, true
}

// moveToFront moves an entry to the front of the list (most recently used).
// This maintains the LRU ordering of the cache entries.
// The method includes bounds checking and panic recovery for robustness.
func (c *LRUCache) moveToFront(idx int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in moveToFront: %v\n", r)
		}
	}()

	// Already at front, nothing to do
	if idx == c.head {
		return
	}

	// Safety check for invalid index
	if idx < 0 || idx >= c.capacity {
		fmt.Printf("Warning: Attempted to move invalid index %d in LRU cache with capacity %d\n", idx, c.capacity)
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
// It resets the cache to its initial state while properly cleaning up resources.
// This method is thread-safe and includes panic recovery for robustness.
func (c *LRUCache) Clear() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovered from panic in Clear: %v\n", r)
		}
	}()

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

	c.indices = make(map[routeCacheKey]int, c.capacity*2)
	c.head = 0
	c.tail = c.capacity - 1
	// Re-initialize the linked list
	for i := 0; i < c.capacity; i++ {
		c.entries[i].next = (i + 1) % c.capacity
		c.entries[i].prev = (i - 1 + c.capacity) % c.capacity
	}

	atomic.StoreInt64(&c.hits, 0)
	atomic.StoreInt64(&c.misses, 0)
}

// Stats returns cache hit/miss statistics.
// It provides the number of cache hits, misses, and the hit ratio.
// These values are useful for monitoring and tuning cache performance.
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

//------------------------------------------------------------------------------
// Buffered Response Writer
//------------------------------------------------------------------------------

// Buffer size constants for different content types
const (
	DefaultBufferSize = 4096 // Default buffer size for most content types
	TextBufferSize    = 2048 // Smaller buffer size for text-based content for faster flushing
	BinaryBufferSize  = 8192 // Larger buffer size for binary content to minimize syscalls
)

// BufferedResponseWriter wraps TrackedResponseWriter with a buffer
type BufferedResponseWriter struct {
	*TrackedResponseWriter
	buffer     *bytes.Buffer
	bufferSize int
	autoFlush  bool
}

// contentTypeMatch checks if content type matches a specific prefix without allocations
func contentTypeMatch(contentType []byte, prefix []byte) bool {
	if len(contentType) < len(prefix) {
		return false
	}

	for i := 0; i < len(prefix); i++ {
		if contentType[i] != prefix[i] {
			return false
		}
	}
	return true
}

// stripContentParams strips content type parameters without allocations
// Example: "text/html; charset=utf-8" → "text/html"
func stripContentParams(contentType []byte) []byte {
	for i := 0; i < len(contentType); i++ {
		if contentType[i] == ';' {
			return contentType[:i]
		}
	}
	return contentType
}

// newBufferedResponseWriter creates a new BufferedResponseWriter with content-aware buffering.
// It optimizes the buffer size based on the content type:
//   - Text-based content (text/*, application/json, etc.): Smaller buffers for faster initial flush
//   - Binary content (image/*, video/*, etc.): Larger buffers to minimize syscalls
//   - Other content types: Default buffer size
//
// If a config is provided with explicit buffer sizes, those will be used instead of the defaults.
//
// Parameters:
//   - w: The TrackedResponseWriter to wrap
//   - contentType: The MIME type of the response content
//   - config: Router configuration containing buffer size settings
//
// Returns:
//   - A new BufferedResponseWriter configured with an appropriate buffer size
func newBufferedResponseWriter(w *TrackedResponseWriter, contentType string, config *Config) *BufferedResponseWriter {
	// Get buffer from pool and ensure it's empty
	buffer := bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()

	// Convert to byte slice once instead of multiple string operations
	contentTypeBytes := []byte(contentType)

	// Strip content type parameters without allocations
	contentTypeBytes = stripContentParams(contentTypeBytes)

	// Define common content type prefixes as byte slices to avoid repeat conversions
	var textPrefix = []byte("text/")
	var jsonPrefix = []byte("application/json")
	var xmlPrefix = []byte("application/xml")
	var jsPrefix = []byte("application/javascript")
	var formPrefix = []byte("application/x-www-form-urlencoded")

	var imagePrefix = []byte("image/")
	var videoPrefix = []byte("video/")
	var audioPrefix = []byte("audio/")
	var octetPrefix = []byte("application/octet-stream")
	var pdfPrefix = []byte("application/pdf")
	var zipPrefix = []byte("application/zip")

	// Determine buffer size from content type without allocations
	var bufferSize int

	// Fast path for empty content type
	if len(contentTypeBytes) == 0 {
		if config != nil && config.DefaultBufferSize > 0 {
			bufferSize = config.DefaultBufferSize
		} else {
			bufferSize = DefaultBufferSize
		}
	} else if contentTypeMatch(contentTypeBytes, textPrefix) ||
		contentTypeMatch(contentTypeBytes, jsonPrefix) ||
		contentTypeMatch(contentTypeBytes, xmlPrefix) ||
		contentTypeMatch(contentTypeBytes, jsPrefix) ||
		contentTypeMatch(contentTypeBytes, formPrefix) {
		// Text content - use smaller buffer for faster flushing
		if config != nil && config.TextBufferSize > 0 {
			bufferSize = config.TextBufferSize
		} else {
			bufferSize = TextBufferSize
		}
	} else if contentTypeMatch(contentTypeBytes, imagePrefix) ||
		contentTypeMatch(contentTypeBytes, videoPrefix) ||
		contentTypeMatch(contentTypeBytes, audioPrefix) ||
		contentTypeMatch(contentTypeBytes, octetPrefix) ||
		contentTypeMatch(contentTypeBytes, pdfPrefix) ||
		contentTypeMatch(contentTypeBytes, zipPrefix) {
		// Binary content - use larger buffer to minimize syscalls
		if config != nil && config.BinaryBufferSize > 0 {
			bufferSize = config.BinaryBufferSize
		} else {
			bufferSize = BinaryBufferSize
		}
	} else {
		// Default for unknown content types
		if config != nil && config.DefaultBufferSize > 0 {
			bufferSize = config.DefaultBufferSize
		} else {
			bufferSize = DefaultBufferSize
		}
	}

	return &BufferedResponseWriter{
		TrackedResponseWriter: w,
		buffer:                buffer,
		bufferSize:            bufferSize,
		autoFlush:             true,
	}
}

// Write buffers the data and uses adaptive flushing based on content type and buffer fullness
func (w *BufferedResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	// Get current content type after headers are written
	contentType := w.Header().Get("Content-Type")
	isTextBased := strings.HasPrefix(contentType, "text/") ||
		strings.HasPrefix(contentType, "application/json") ||
		strings.HasPrefix(contentType, "application/xml")

	// For large writes that exceed buffer, write directly to avoid double copying
	if len(b) > w.bufferSize*2 {
		// Flush any existing buffered data first
		if w.buffer.Len() > 0 {
			w.Flush()
		}
		n, err := w.TrackedResponseWriter.Write(b)
		w.bytesWritten += int64(n)
		return n, err
	}

	// If this write would exceed buffer size, flush first
	if w.buffer.Len()+len(b) > w.bufferSize {
		w.Flush()
	}

	n, err := w.buffer.Write(b)
	w.bytesWritten += int64(n)

	// Adaptive flushing strategy based on content type
	if w.autoFlush {
		bufferFullness := float64(w.buffer.Len()) / float64(w.bufferSize)

		// For text-based content, flush earlier for better perceived performance
		if isTextBased && bufferFullness >= 0.7 {
			w.Flush()
		} else if !isTextBased && w.buffer.Len() >= w.bufferSize {
			// For binary content, wait until buffer is completely full
			w.Flush()
		}
	}

	return n, err
}

// Flush writes buffered data to the underlying ResponseWriter
func (w *BufferedResponseWriter) Flush() {
	if w == nil || w.TrackedResponseWriter == nil || w.buffer == nil {
		return
	}

	if w.buffer.Len() > 0 {
		// Only attempt to write if we have something to write
		w.TrackedResponseWriter.Write(w.buffer.Bytes())
		w.buffer.Reset()
	}
}

// Close returns the buffer to the pool
func (w *BufferedResponseWriter) Close() {
	if w == nil {
		return
	}
	if w.buffer != nil {
		w.Flush()
		bufferPool.Put(w.buffer)
		w.buffer = nil
	}
}

// Close flushes any remaining data and returns the buffer to the pool.
// This method should be called after all writing is complete, typically
// using defer to ensure proper cleanup even in error conditions.
//
// After Close is called, the BufferedResponseWriter should not be used again.
// Multiple calls to Close are safe and subsequent calls have no effect.
func (w *BufferedResponseWriter) Close() {
	if w == nil {
		return
	}

	if w.buffer != nil {
		w.Flush()
		bufferPool.Put(w.buffer)
		w.buffer = nil
	}
}
