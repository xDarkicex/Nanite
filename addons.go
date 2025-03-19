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

type Group struct {
	middleware []MiddlewareFunc // Middleware stack for all group routes (hot: accessed every request)
	prefix     string           // Path segment prepended to all child routes (e.g., "/api")
	router     *Router          // Reference to root router instance (cold: set at creation)
}

func (r *Router) Group(prefix string, middleware ...MiddlewareFunc) *Group {
	return &Group{
		router:     r,
		prefix:     prefix,
		middleware: middleware,
	}
}

func (g *Group) Get(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Get(fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) Post(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Post(fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) Put(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Put(fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) Delete(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Delete(fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) Patch(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Patch(fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) Options(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Options(fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) Head(path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Head(fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) Handle(method, path string, handler HandlerFunc, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.Handle(method, fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) WebSocket(path string, handler WebSocketHandler, middleware ...MiddlewareFunc) *Group {
	fullPath := normalizePath(g.prefix + path)
	allMiddleware := append(g.middleware, middleware...)
	g.router.WebSocket(fullPath, handler, allMiddleware...)
	return g
}

func (g *Group) Group(prefix string, middleware ...MiddlewareFunc) *Group {
	fullPrefix := normalizePath(g.prefix + prefix)
	allMiddleware := append(g.middleware, middleware...)
	return &Group{
		router:     g.router,
		prefix:     fullPrefix,
		middleware: allMiddleware,
	}
}

// - middleware: The middleware functions to add
func (g *Group) Use(middleware ...MiddlewareFunc) *Group {
	g.middleware = append(g.middleware, middleware...)
	return g
}

//go:inline
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

		if len(chains) > 0 && (ctx.Request.Method == "POST" || ctx.Request.Method == "PUT" ||
			ctx.Request.Method == "PATCH" || ctx.Request.Method == "DELETE") {
			contentType := ctx.Request.Header.Get("Content-Type")

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

			if strings.HasPrefix(contentType, "application/json") {
				originalBody := ctx.Request.Body
				defer func() {
					if err := originalBody.Close(); err != nil {
						// Only handle error if response not yet committed
						if !ctx.IsWritten() {
							ve := getValidationError("", fmt.Sprintf("body closure error: %v", err))
							if ctx.ValidationErrs == nil {
								ctx.ValidationErrs = make(ValidationErrors, 0, 1)
							}
							ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
							putValidationError(ve)
							ctx.JSON(http.StatusInternalServerError, map[string]interface{}{"errors": ctx.ValidationErrs})
						}
					}
				}()

				maxJSONSize := int64(10 << 20)
				if ctx.Request.ContentLength > maxJSONSize && ctx.Request.ContentLength != -1 {
					ve := getValidationError("", "request body too large")
					if ctx.ValidationErrs == nil {
						ctx.ValidationErrs = make(ValidationErrors, 0, 1)
					}
					ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
					putValidationError(ve)
					ctx.JSON(http.StatusRequestEntityTooLarge, map[string]interface{}{"errors": ctx.ValidationErrs})
					return
				}

				buffer := bufferPool.Get().(*bytes.Buffer)
				buffer.Reset()
				defer bufferPool.Put(buffer)

				limitedBody := io.LimitReader(originalBody, maxJSONSize)
				teeBody := io.TeeReader(limitedBody, buffer)

				var body map[string]interface{}
				if err := json.NewDecoder(teeBody).Decode(&body); err != nil {
					ve := getValidationError("", "invalid JSON")
					if ctx.ValidationErrs == nil {
						ctx.ValidationErrs = make(ValidationErrors, 0, 1)
					}
					ctx.ValidationErrs = append(ctx.ValidationErrs, *ve)
					putValidationError(ve)
					ctx.JSON(http.StatusBadRequest, map[string]interface{}{"errors": ctx.ValidationErrs})
					return
				}

				ctx.Request.Body = io.NopCloser(bytes.NewReader(buffer.Bytes()))
				ctx.Values["body"] = body
			}

			for _, chain := range chains {
				field := ctx.Field(chain.field)
				field.rules = append(field.rules, chain.rules...)
			}
		}

		next()

		for _, chain := range chains {
			chain.Release()
		}
	}
}

//go:inline
func executeMiddlewareChain(c *Context, handler HandlerFunc, middleware []MiddlewareFunc) {
	// Fast path for no middleware
	if len(middleware) == 0 {
		handler(c)
		return
	}

	// Handle common cases with direct function calls (no allocations)
	switch len(middleware) {
	case 1:
		middleware[0](c, func() { handler(c) })
		return
	case 2:
		middleware[0](c, func() {
			middleware[1](c, func() { handler(c) })
		})
		return
	case 3:
		middleware[0](c, func() {
			middleware[1](c, func() {
				middleware[2](c, func() { handler(c) })
			})
		})
		return

	case 4:
		middleware[0](c, func() {
			middleware[1](c, func() {
				middleware[2](c, func() {
					middleware[3](c, func() { handler(c) })
				})
			})
		})
		return
	case 5:
		middleware[0](c, func() {
			middleware[1](c, func() {
				middleware[2](c, func() {
					middleware[3](c, func() {
						middleware[4](c, func() { handler(c) })
					})
				})
			})
		})
		return
	}

	// For larger middleware chains, use a completely non-recursive approach
	// that pre-builds all the functions before executing them
	funcs := make([]func(), len(middleware)+1)

	// The last function just calls the handler
	funcs[len(middleware)] = func() {
		handler(c)
	}

	// Build the middleware chain backwards
	for i := len(middleware) - 1; i >= 0; i-- {
		mw := middleware[i]
		next := funcs[i+1] // Explicitly capture the next function
		funcs[i] = func() {
			mw(c, next)
		}
	}

	// Start the chain execution
	funcs[0]()
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
//
//go:inline
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
//
//go:inline
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
//
//go:inline
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
//
//go:inline
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
			newParams = newParams[:len(params)]
			copy(newParams, params)
			entry.params = newParams
		}
		c.moveToFront(idx)
		return
	}
	idx := c.tail
	entry := &c.entries[idx]
	oldKey := entry.key
	if oldKey.method != "" || oldKey.path != "" {
		delete(c.indices, oldKey)
	}

	if entry.params != nil {
		putParamSlice(entry.params)
	}
	entry.key.method = method
	entry.key.path = path
	entry.handler = handler
	newParams := getParamSlice(len(params))
	newParams = newParams[:len(params)]
	copy(newParams, params)
	entry.params = newParams
	c.indices[entry.key] = idx
	c.moveToFront(idx)
}

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
		params = params[:len(entry.params)]
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

func (c *LRUCache) Stats() (hits, misses int64, ratio float64) {
	hits = atomic.LoadInt64(&c.hits)
	misses = atomic.LoadInt64(&c.misses)
	total := hits + misses
	if total > 0 {
		ratio = float64(hits) / float64(total)
	}
	return
}

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

const (
	DefaultBufferSize = 4096 // Default buffer size for most content types
	TextBufferSize    = 2048 // Smaller buffer size for text-based content for faster flushing
	BinaryBufferSize  = 8192 // Larger buffer size for binary content to minimize syscalls
)

type BufferedResponseWriter struct {
	*TrackedResponseWriter
	buffer     *bytes.Buffer
	bufferSize int
	autoFlush  bool
}

//go:inline
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

//go:inline
func stripContentParams(contentType []byte) []byte {
	for i := 0; i < len(contentType); i++ {
		if contentType[i] == ';' {
			return contentType[:i]
		}
	}
	return contentType
}

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
