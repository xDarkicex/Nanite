package nanite_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xDarkicex/nanite"
)

// --------- Test Handlers ---------
// Simple handler that does nothing
func noopHandler(ctx *nanite.Context) {}

// Handler that reads a single parameter
func paramHandler(ctx *nanite.Context) {
	_, _ = ctx.GetParam("id")
}

// Handler that reads multiple parameters
func multiParamHandler(ctx *nanite.Context) {
	_, _ = ctx.GetParam("id")
	_, _ = ctx.GetParam("name")
}

// JSON response handler
func jsonHandler(ctx *nanite.Context) {
	ctx.JSON(http.StatusOK, map[string]interface{}{"status": "ok"})
}

// --------- Test Middleware ---------
// Each middleware has a distinct implementation to avoid reference cycle issues
func firstMiddleware(ctx *nanite.Context, next func()) {
	ctx.Set("first", true)
	next()
}

func secondMiddleware(ctx *nanite.Context, next func()) {
	ctx.Set("second", true)
	next()
}

func thirdMiddleware(ctx *nanite.Context, next func()) {
	ctx.Set("third", true)
	next()
}

// --------- Router Setup Functions ---------
// Each function creates a fresh router to prevent state buildup between tests

// Static routes setup
func setupStaticRouter() *nanite.Router {
	router := nanite.New()
	router.Get("/", noopHandler)
	router.Get("/users", noopHandler)
	router.Get("/users/profile", noopHandler)
	router.Get("/products", noopHandler)
	router.Get("/products/category", noopHandler)
	router.Post("/users", noopHandler)
	router.Put("/users", noopHandler)
	router.Delete("/users", noopHandler)
	return router
}

// Dynamic routes with parameters
func setupParamRouter() *nanite.Router {
	router := nanite.New()
	router.Get("/users/:id", paramHandler)
	router.Get("/products/:id", paramHandler)
	router.Get("/categories/:id/products/:pid", multiParamHandler)
	router.Get("/users/:id/comments/:cid", multiParamHandler)
	router.Get("/users/:id/products/:pid/comments/:cid", multiParamHandler)
	return router
}

// Router with middleware chains
func setupMiddlewareRouter() *nanite.Router {
	router := nanite.New()
	router.Use(firstMiddleware)

	// Single middleware (global only)
	router.Get("/", noopHandler)

	// Two middlewares (global + one route middleware)
	router.Get("/users/:id", paramHandler, secondMiddleware)

	// Three middlewares (global + two route middlewares)
	router.Get("/products/:id", paramHandler, secondMiddleware, thirdMiddleware)

	// Group middleware
	api := router.Group("/api", secondMiddleware)
	api.Get("/users/:id", paramHandler)
	api.Post("/users", noopHandler)

	return router
}

// --------- Benchmarks ---------

// BenchmarkStaticRoutes measures performance of static route matching
func BenchmarkStaticRoutes(b *testing.B) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"Root", "GET", "/"},
		{"FirstLevel", "GET", "/users"},
		{"SecondLevel", "GET", "/users/profile"},
		{"POST", "POST", "/users"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Create a fresh router for each test case to prevent state buildup
			router := setupStaticRouter()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkParamRoutes measures routes with URL parameters
func BenchmarkParamRoutes(b *testing.B) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"SingleParam", "GET", "/users/123"},
		{"SingleParam2", "GET", "/products/456"},
		{"TwoParams", "GET", "/categories/123/products/456"},
		{"ThreeParams", "GET", "/users/123/products/456/comments/789"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Create a fresh router for each test case
			router := setupParamRouter()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkMiddlewareChain measures middleware execution performance
func BenchmarkMiddlewareChain(b *testing.B) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"SingleMiddleware", "GET", "/"},
		{"TwoMiddlewares", "GET", "/users/123"},
		{"ThreeMiddlewares", "GET", "/products/456"},
		{"GroupMiddleware", "GET", "/api/users/789"},
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Create a fresh router for each middleware test case
			router := setupMiddlewareRouter()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkJSONHandling measures JSON parsing and response performance
func BenchmarkJSONHandling(b *testing.B) {
	// Create a fresh router
	jsonBody := `{"name":"John","email":"john@example.com","age":30}`

	b.Run("JSONProcessing", func(b *testing.B) {
		router := nanite.New()
		router.Use(nanite.JSONParsingMiddleware(nil))
		router.Post("/api/users", jsonHandler)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest("POST", "/api/users", strings.NewReader(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})
}

// BenchmarkRouteCache measures the effectiveness of route caching
func BenchmarkRouteCache(b *testing.B) {
	// With default cache enabled
	b.Run("WithCache", func(b *testing.B) {
		router := nanite.New()
		router.Get("/users/:id", paramHandler)

		req := httptest.NewRequest("GET", "/users/123", nil)
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})

	// With cache disabled
	b.Run("NoCache", func(b *testing.B) {
		router := nanite.New()
		router.SetRouteCacheOptions(0, 0) // Disable cache
		router.Get("/users/:id", paramHandler)

		req := httptest.NewRequest("GET", "/users/123", nil)
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
		}
	})
}

// BenchmarkNotFound measures performance for non-existent routes
func BenchmarkNotFound(b *testing.B) {
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"RootLevel", "GET", "/nonexistent"},
		{"NestedLevel", "GET", "/users/nonexistent"},
		{"DeeplyNested", "GET", "/a/b/c/d/e/f/g"},
		{"WrongMethod", "PATCH", "/products"}, // We only defined GET for /products
	}

	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			// Create a fresh router for each not-found test
			router := setupStaticRouter()

			req := httptest.NewRequest(tt.method, tt.path, nil)
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
			}
		})
	}
}

// BenchmarkGitHubAPI simulates the GitHub API structure (industry standard benchmark)
func BenchmarkGitHubAPI(b *testing.B) {
	paths := []string{
		"/authorizations",
		"/authorizations/123",
		"/applications/client123/tokens/token123",
		"/events",
		"/repos/octocat/hello-world/events",
		"/users/octocat/received_events",
		"/users/octocat/events/orgs/github",
	}

	for _, path := range paths {
		b.Run(path, func(b *testing.B) {
			// Create a fresh GitHub API router for each path test
			router := nanite.New()

			// GitHub API routes based on common router benchmarks
			router.Get("/authorizations", noopHandler)
			router.Get("/authorizations/:id", paramHandler)
			router.Post("/authorizations", noopHandler)
			router.Put("/authorizations/:id", paramHandler)
			router.Delete("/authorizations/:id", paramHandler)
			router.Get("/applications/:client_id/tokens/:access_token", multiParamHandler)
			router.Delete("/applications/:client_id/tokens", paramHandler)
			router.Delete("/applications/:client_id/tokens/:access_token", multiParamHandler)
			router.Get("/events", noopHandler)
			router.Get("/repos/:owner/:repo/events", multiParamHandler)
			router.Get("/networks/:owner/:repo/events", multiParamHandler)
			router.Get("/orgs/:org/events", paramHandler)
			router.Get("/users/:user/received_events", paramHandler)
			router.Get("/users/:user/received_events/public", paramHandler)
			router.Get("/users/:user/events", paramHandler)
			router.Get("/users/:user/events/public", paramHandler)
			router.Get("/users/:user/events/orgs/:org", multiParamHandler)

			req := httptest.NewRequest("GET", path, nil)
			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
			}
		})
	}
}
