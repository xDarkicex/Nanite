// Package nanite provides a lightweight, high-performance HTTP router for Go.
package nanite

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
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
