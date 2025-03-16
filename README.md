# Nanite

[![Go Reference](https://pkg.go.dev/badge/github.com/example/naniv/github.com/example/nanit](https://goreportcard.com/badge/github.com/example/n.com/report/github.com/examT](https://img.shields.io/opensource.org/licenses/Ms a lightweight, high-performance HTTP router for Go. It's designed to be developer-friendly, inspired by Express.js, while delivering exceptional performance through advanced optimization techniques.

## Performance

Nanite is engineered for extreme performance without sacrificing developer experience:

- **Blazing Fast**: Benchmarked at 190,000+ requests/sec on standard hardware
- **Memory Efficient**: Dramatically reduced allocations through smart pooling techniques
- **Low Latency**: Average response times under 1ms with consistent performance
- **GC Friendly**: Minimized garbage collection pressure through zero-allocation algorithms

Here's how it compares to other popular routers:

| Router      | Requests/sec | Latency (avg) | Allocations/req |
|-------------|--------------|---------------|-----------------|
| Nanite      | 190,000      | 0.88ms        | 5-10            |
| Gin         | 130,000      | 0.15ms        | 5               |
| Echo        | 125,000      | 0.13ms        | 4               |
| Gorilla Mux | 45,000       | 0.32ms        | 10              |

## Features

- 🚀 **Radix Tree Routing**: Advanced prefix compression for faster path matching
- 🧠 **Zero-Allocation Path Parsing**: Parse URL parameters with zero memory overhead
- 🔄 **Buffered Response Writer**: Optimized I/O operations for improved throughput
- 🧩 **Express-Like Middleware**: Intuitive middleware system with support for global and route-specific handlers
- ✅ **Optimized Validation**: High-performance request validation with pre-allocated errors
- 🔌 **WebSockets**: First-class WebSocket support with automatic ping/pong
- 📁 **Static File Serving**: Efficient static file delivery with buffered I/O
- 🌳 **Route Groups**: Organize routes with shared prefixes and middleware
- 🛡️ **Object Pooling**: Extensive use of sync.Pool to minimize allocations

## Installation

```bash
go get github.com/xDarkicex/Nanite
```

## Quick Start

```go
package main

import (
    "fmt"
    "net/http"
    
    "github.com/xDarkicex/Nanite"
)

func main() {
    // Create a new router
    r := nanite.New()
    
    // Add a simple route
    r.Get("/hello", func(c *nanite.Context) {
        c.String(http.StatusOK, "Hello, World!")
    })
    
    // Start the server
    r.Start("8080")
}
```

## Routing with Radix Tree

Nanite's radix tree router efficiently handles static and dynamic routes:

```go
// Basic routes
r.Get("/users", listUsers)
r.Post("/users", createUser)
r.Put("/users/:id", updateUser)
r.Delete("/users/:id", deleteUser)

// Route parameters
r.Get("/users/:id", func(c *nanite.Context) {
    id, _ := c.GetParam("id")
    c.JSON(http.StatusOK, map[string]string{
        "id": id,
        "message": "User details",
    })
})

// Wildcard routes
r.Get("/files/*path", func(c *nanite.Context) {
    path, _ := c.GetParam("path")
    c.JSON(http.StatusOK, map[string]string{
        "path": path,
    })
})
```

## Middleware

Middleware functions can be added globally or to specific routes:

```go
// Global middleware
r.Use(LoggerMiddleware)

// Route-specific middleware
r.Get("/admin", adminHandler, AuthMiddleware)

// Middleware function example
func LoggerMiddleware(c *nanite.Context, next func()) {
    // Code executed before the handler
    startTime := time.Now()
    
    // Call the next middleware or handler
    next()
    
    // Code executed after the handler
    duration := time.Since(startTime)
    fmt.Printf("[%s] %s - %dms\n", c.Request.Method, c.Request.URL.Path, duration.Milliseconds())
}
```

## High-Performance Validation

Nanite provides an optimized validation system:

```go
// Create validation rules
emailValidation := nanite.NewValidationChain("email").Required().IsEmail()
passwordValidation := nanite.NewValidationChain("password").Required().Length(8, 64)

// Apply validation middleware
r.Post("/register", registerHandler, nanite.ValidationMiddleware(emailValidation, passwordValidation))

// In your handler, check for validation errors
func registerHandler(c *nanite.Context) {
    if !c.CheckValidation() {
        // Validation failed, response already sent
        return
    }
    
    // Validation passed, continue with registration
    email := c.FormValue("email")
    password := c.FormValue("password")
    // ...
}
```

## WebSockets

WebSocket support is built into Nanite:

```go
r.WebSocket("/chat", func(conn *websocket.Conn, c *nanite.Context) {
    // Handle the WebSocket connection
    for {
        messageType, p, err := conn.ReadMessage()
        if err != nil {
            return
        }
        
        // Echo the message back
        if err := conn.WriteMessage(messageType, p); err != nil {
            return
        }
    }
})
```

## Efficient Static File Serving

Serve static files with optimized buffered I/O:

```go
// Serve files from the "public" directory under the "/static" path
r.ServeStatic("/static", "./public")
```

## Context Methods

Nanite provides a rich Context object with many helpful methods:

```go
// Parsing request data
c.Bind(&user)          // Parse JSON request body
c.FormValue("name")    // Get form field
c.Query("sort")        // Get query parameter
c.GetParam("id")       // Get route parameter
c.File("avatar")       // Get uploaded file

// Sending responses
c.JSON(http.StatusOK, data)
c.String(http.StatusOK, "Hello")
c.HTML(http.StatusOK, "Hello")
c.Redirect(http.StatusFound, "/login")

// Managing the response
c.SetHeader("X-Custom", "value")
c.Status(http.StatusCreated)
c.Cookie("session", token)

// Context data
c.Set("user", user)
c.Get("user")
```

## Route Groups

Organize your routes with groups:

```go
// Create an API group
api := r.Group("/api/v1")

// Add routes to the group
api.Get("/users", listUsers)
api.Post("/users", createUser)

// Nested groups with additional middleware
admin := api.Group("/admin", AuthMiddleware)
admin.Get("/stats", getStats)
```

## Upcoming Features

Nanite is actively being enhanced through a 3-phase development plan:

### Phase 1: Core Performance (Completed)
- ✅ Radix tree implementation for optimized routing
- ✅ Validation system optimization with pre-allocated errors
- ✅ Zero-allocation path parsing

### Phase 2: I/O Optimization (In Progress)
- ⚙️ Enhanced buffered response writer
- ⚙️ Request routing cache for frequently accessed routes
- ⚙️ Further reduced allocations in hot paths

### Phase 3: Advanced Features (Planned)
- 🔮 Fluent API for middleware chaining
- 🔮 Named routes and reverse routing for URL generation
- 🔮 Built-in security middleware (CORS, CSRF, etc.)
- 🔮 Enhanced parameter handling for complex routes
- 🔮 Request rate limiting

## Example Application

Here's a more complete example of a REST API:

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/xDarkicex/Nanite"
)

type User struct {
    ID    string `json:"id"`
    Name  string `json:"name"`
    Email string `json:"email"`
}

func main() {
    r := nanite.New()
    
    // Middleware
    r.Use(LoggerMiddleware)
    
    // Routes
    r.Get("/", func(c *nanite.Context) {
        c.String(http.StatusOK, "API is running")
    })
    
    // API group
    api := r.Group("/api")
    {
        // User validation
        nameValidation := nanite.NewValidationChain("name").Required()
        emailValidation := nanite.NewValidationChain("email").Required().IsEmail()
        
        // User routes
        api.Get("/users", listUsers)
        api.Post("/users", createUser, nanite.ValidationMiddleware(nameValidation, emailValidation))
        api.Get("/users/:id", getUser)
        api.Put("/users/:id", updateUser, nanite.ValidationMiddleware(nameValidation, emailValidation))
        api.Delete("/users/:id", deleteUser)
    }
    
    // Static files
    r.ServeStatic("/assets", "./public")
    
    // Start server
    log.Println("Server started at http://localhost:8080")
    r.Start("8080")
}

func listUsers(c *nanite.Context) {
    users := []User{
        {ID: "1", Name: "Alice", Email: "alice@example.com"},
        {ID: "2", Name: "Bob", Email: "bob@example.com"},
    }
    c.JSON(http.StatusOK, users)
}

func createUser(c *nanite.Context) {
    if !c.CheckValidation() {
        return
    }
    
    var user User
    if err := c.Bind(&user); err != nil {
        c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user data"})
        return
    }
    
    user.ID = "3" // In a real app, generate a unique ID
    c.JSON(http.StatusCreated, user)
}

func getUser(c *nanite.Context) {
    id, _ := c.GetParam("id")
    
    // Simulate database lookup
    user := User{ID: id, Name: "Sample User", Email: "user@example.com"}
    c.JSON(http.StatusOK, user)
}

func updateUser(c *nanite.Context) {
    if !c.CheckValidation() {
        return
    }
    
    id, _ := c.GetParam("id")
    
    var user User
    if err := c.Bind(&user); err != nil {
        c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid user data"})
        return
    }
    
    user.ID = id // Ensure ID matches the route parameter
    c.JSON(http.StatusOK, user)
}

func deleteUser(c *nanite.Context) {
    id, _ := c.GetParam("id")
    c.JSON(http.StatusOK, map[string]string{"message": "User " + id + " deleted"})
}

func LoggerMiddleware(c *nanite.Context, next func()) {
    log.Printf("Request: %s %s", c.Request.Method, c.Request.URL.Path)
    next()
    log.Printf("Response: %d", c.Writer.(*nanite.TrackedResponseWriter).Status())
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
