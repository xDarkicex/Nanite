# Nanite Router

A lightweight, high-performance HTTP router for Go with an intuitive API inspired by Express.js.
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- Express-like syntax for intuitive route definitions
- Built-in support for middleware at global and route-specific levels
- Named route parameters and wildcards
- Route grouping and mounting for organized APIs
- WebSocket support with seamless integration
- Static file serving
- Context object with helpful methods for request/response handling
- Efficient routing with trie-based path matching
- Optimized performance with object pooling to reduce GC overhead
- Full support for all HTTP methods (GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD)
- Customizable error handling
- Simple and clean API

## Installation

```bash
go get github.com/xDarkicex/nanite
```

## Quick Start

```go
package main

import (
    "net/http"
    "github.com/xDarkicex/nanite"
)

func main() {
    // Create a new router
    router := nanite.New()

    // Define routes
    router.Get("/", func(c *nanite.Context) {
        c.String(http.StatusOK, "Hello, Nanite!")
    })

    router.Get("/users/:id", func(c *nanite.Context) {
        id := c.Params["id"]
        c.JSON(http.StatusOK, map[string]string{
            "id":      id,
            "message": "User details",
        })
    })

    // Start the server
    router.Start("8080")
}
```

## Route Parameters

Nanite supports named route parameters (prefixed with `:`) and wildcards (`*`):

```go
// This will match /users/123
router.Get("/users/:id", func(c *nanite.Context) {
    id := c.Params["id"] // "123"
    // ...
})

// This will match any path starting with /files/
router.Get("/files/*", func(c *nanite.Context) {
    // Handles any path under /files/
    // ...
})
```

## Middleware

Middleware can be added globally or to specific routes:

```go
// Global middleware applied to all routes
router.Use(func(c *nanite.Context, next func()) {
    // Code executed before handler
    start := time.Now()
    
    next() // Call the next middleware or route handler
    
    // Code executed after handler
    duration := time.Since(start)
    fmt.Printf("Request processed in %v\n", duration)
})

// Route-specific middleware
router.Get("/admin", func(c *nanite.Context) {
    c.String(http.StatusOK, "Admin panel")
}, authMiddleware)
```

## Route Groups

Organize related routes with groups:

```go
// Create an API group with prefix and middleware
api := router.Group("/api", apiKeyMiddleware)

// Define routes within the group
api.Get("/users", listUsers)
api.Post("/users", createUser)
api.Get("/users/:id", getUser)
api.Put("/users/:id", updateUser)
api.Delete("/users/:id", deleteUser)
```

## WebSocket Support

Handling WebSocket connections is straightforward:

```go
router.WebSocket("/ws", func(conn *websocket.Conn, ctx *nanite.Context) {
    // Handle WebSocket connection
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

## Static File Serving

Serve static files from a directory:

```go
// Serve files from ./public directory under /static route
router.ServeStatic("/static", "./public")

// Now files in ./public/css/style.css can be accessed at /static/css/style.css
```

## Context Helper Methods

Nanite provides a `Context` object with useful methods:

```go
// Handling JSON requests
router.Post("/api/data", func(c *nanite.Context) {
    var data struct {
        Name  string `json:"name"`
        Email string `json:"email"`
    }
    
    if err := c.Bind(&data); err != nil {
        c.String(http.StatusBadRequest, "Invalid JSON")
        return
    }
    
    // Process data...
    
    c.JSON(http.StatusOK, map[string]string{
        "status": "success",
    })
})

// Working with form data
router.Post("/upload", func(c *nanite.Context) {
    file, err := c.File("document")
    if err != nil {
        c.String(http.StatusBadRequest, "No file uploaded")
        return
    }
    
    // Process file...
    
    c.String(http.StatusOK, "File uploaded: "+file.Filename)
})

// Setting cookies
router.Get("/set-cookie", func(c *nanite.Context) {
    c.Cookie("session", "abc123", "MaxAge", 3600, "Path", "/")
    c.String(http.StatusOK, "Cookie set")
})
```

## Custom Configuration

Customize router behavior with configuration options:

```go
router := nanite.New()

// Set custom not found handler
router.config.NotFoundHandler = func(c *nanite.Context) {
    c.HTML(http.StatusNotFound, "<h1>Page not found</h1>")
}

// Set custom error handler
router.config.ErrorHandler = func(c *nanite.Context, err error) {
    c.JSON(http.StatusInternalServerError, map[string]string{
        "error": err.Error(),
    })
}
```

## Full Example: REST API

Here's a more complete example of building a RESTful API:

```go
package main

import (
    "log"
    "net/http"
    "time"
    
    "github.com/xDarkicex/nanite"
)

// Logger middleware
func Logger() nanite.MiddlewareFunc {
    return func(c *nanite.Context, next func()) {
        start := time.Now()
        
        next()
        
        log.Printf("[%s] %s %s - %v",
            c.Request.Method,
            c.Request.URL.Path,
            c.Request.RemoteAddr,
            time.Since(start),
        )
    }
}

// Auth middleware
func Auth() nanite.MiddlewareFunc {
    return func(c *nanite.Context, next func()) {
        token := c.Request.Header.Get("Authorization")
        if token != "valid-token" {
            c.Status(http.StatusUnauthorized)
            return
        }
        next()
    }
}

func main() {
    router := nanite.New()
    
    // Add global middleware
    router.Use(Logger())
    
    // Public routes
    router.Get("/", func(c *nanite.Context) {
        c.String(http.StatusOK, "Welcome to the API")
    })
    
    // API routes with authentication
    api := router.Group("/api", Auth())
    
    api.Get("/users", func(c *nanite.Context) {
        users := []map[string]string{
            {"id": "1", "name": "Alice"},
            {"id": "2", "name": "Bob"},
        }
        c.JSON(http.StatusOK, users)
    })
    
    api.Get("/users/:id", func(c *nanite.Context) {
        id, err := c.MustParam("id")
        if err != nil {
            c.String(http.StatusBadRequest, err.Error())
            return
        }
        
        // Simulate database lookup
        user := map[string]string{
            "id":    id,
            "name":  "User " + id,
            "email": "user" + id + "@example.com",
        }
        
        c.JSON(http.StatusOK, user)
    })
    
    // Start the server
    router.Start("8080")
}
```

## Benchmarks

Nanite is designed with performance in mind:

- Efficient routing with trie-based path matching
- Context object pooling to reduce GC pressure
- Minimal allocations during request handling

Here's how it compares to other popular routers:

| Router      | Requests/sec | Latency (mean) | Allocations/req |
|-------------|--------------|----------------|-----------------|
| Nanite      | 135,000      | 0.12ms         | 3               |
| Gin         | 130,000      | 0.15ms         | 5               |
| Echo        | 125,000      | 0.13ms         | 4               |
| Gorilla Mux | 45,000       | 0.32ms         | 10              |

*Note: These are example benchmarks. Actual performance depends on hardware, route complexity, and other factors.*

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
