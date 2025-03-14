# Nanite

[![Go Reference](https://pkg.go.dev/badge/github.com/example/nanite.svg)](https://pkg.go.dev/github.com/example/nanite)
[![Go Report Card](https://goreportcard.com/badge/github.com/example/nanite)](https://goreportcard.com/report/github.com/example/nanite)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Nanite is a lightweight, high-performance HTTP router for Go. It's designed to be developer-friendly, inspired by Express.js, and optimized for speed and efficiency in routing, middleware handling, and WebSocket support.

## Features

- 🚀 **High Performance**: Optimized routing algorithm with minimal memory allocations
- 🧩 **Middleware Support**: Express-like middleware system with global and route-specific middleware
- 🔍 **Route Parameters**: Support for named parameters and wildcards in routes
- ✅ **Validation**: Built-in request validation for forms, JSON, query parameters, and URL params
- 🔌 **WebSockets**: First-class WebSocket support with automatic connection management
- 📁 **Static File Serving**: Easy serving of static files and directories
- 🛡️ **Context Pool**: Efficient context reuse through a sync.Pool
- ⚡ **Fast Routing**: Optimized path matching with sorted children nodes

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
    
    "github.com/example/nanite"
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

## Routing

Nanite supports all standard HTTP methods and dynamic route parameters:

```go
// Basic routes
r.Get("/users", listUsers)
r.Post("/users", createUser)
r.Put("/users/:id", updateUser)
r.Delete("/users/:id", deleteUser)

// Route parameters
r.Get("/users/:id", func(c *nanite.Context) {
    id, _ := c.GetParam("id")
    c.JSON(http.StatusOK, map[string]interface{}{
        "id": id,
        "message": "User details",
    })
})

// Wildcard routes
r.Get("/files/*", serveFiles)
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

## Request Validation

Nanite provides a powerful validation system:

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

## Static File Serving

Serve static files easily:

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
c.HTML(http.StatusOK, "<h1>Hello</h1>")
c.Redirect(http.StatusFound, "/login")

// Managing the response
c.SetHeader("X-Custom", "value")
c.Status(http.StatusCreated)
c.Cookie("session", token)

// Context data
c.Set("user", user)
c.Get("user")
```

## Custom Configuration

Customize the router with your own configuration:

```go
r := nanite.New()

// Set custom error handler
r.config.ErrorHandler = func(c *nanite.Context, err error) {
    c.JSON(http.StatusInternalServerError, map[string]string{
        "error": err.Error(),
    })
}

// Set custom 404 handler
r.config.NotFoundHandler = func(c *nanite.Context) {
    c.HTML(http.StatusNotFound, "<h1>Page not found</h1>")
}

// Configure WebSocket settings
r.config.WebSocket.ReadTimeout = 30 * time.Second
r.config.WebSocket.PingInterval = 15 * time.Second
```

## Performance

Nanite is designed for high performance with:

- Minimal memory allocations through context pooling
- Efficient routing algorithm using sorted children nodes
- Pre-compiled middleware chains for faster execution
- Optimized path matching

## Example Application

Here's a more complete example of a REST API:

```go
package main

import (
    "log"
    "net/http"
    
    "github.com/example/nanite"
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
    apiRoutes(r)
    
    // Static files
    r.ServeStatic("/assets", "./public")
    
    // Start server
    log.Println("Server started at http://localhost:8080")
    http.ListenAndServe(":8080", r)
}

func apiRoutes(r *nanite.Router) {
    // User validation
    nameValidation := nanite.NewValidationChain("name").Required()
    emailValidation := nanite.NewValidationChain("email").Required().IsEmail()
    
    // User routes
    r.Get("/users", listUsers)
    r.Post("/users", createUser, nanite.ValidationMiddleware(nameValidation, emailValidation))
    r.Get("/users/:id", getUser)
    r.Put("/users/:id", updateUser, nanite.ValidationMiddleware(nameValidation, emailValidation))
    r.Delete("/users/:id", deleteUser)
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

## License

MIT License

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
