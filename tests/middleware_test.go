package nanite_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
	"time"

	"github.com/xDarkicex/nanite"
)

// Simple tracking middleware that logs execution order
func trackingMiddleware(id string) nanite.MiddlewareFunc {
	return func(ctx *nanite.Context, next func()) {
		// Add entry to trace
		trace, _ := ctx.Get("trace").([]string)
		if trace == nil {
			trace = make([]string, 0, 10)
		}
		trace = append(trace, fmt.Sprintf("Enter %s", id))
		ctx.Set("trace", trace)

		// Call next
		next()

		// Record exit
		trace, _ = ctx.Get("trace").([]string)
		trace = append(trace, fmt.Sprintf("Exit %s", id))
		ctx.Set("trace", trace)
	}
}

// Capture stack trace middleware
func stackTraceMiddleware(ctx *nanite.Context, next func()) {
	// Capture current stack depth before proceeding
	var stack [8192]byte
	stackLen := runtime.Stack(stack[:], false)
	trace, _ := ctx.Get("stackDepth").([]int)
	if trace == nil {
		trace = make([]int, 0, 10)
	}
	trace = append(trace, stackLen)
	ctx.Set("stackDepth", trace)

	next()
}

// Test handler that does nothing
func testHandler(ctx *nanite.Context) {
	ctx.String(http.StatusOK, "OK")
}

func TestMiddlewareChainRecursion(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() *nanite.Router
	}{
		{
			name: "SingleMiddleware",
			setupFunc: func() *nanite.Router {
				r := nanite.New()
				r.Use(trackingMiddleware("Global"))
				r.Get("/test", testHandler)
				return r
			},
		},
		{
			name: "ThreeGlobalMiddleware",
			setupFunc: func() *nanite.Router {
				r := nanite.New()
				r.Use(trackingMiddleware("Global1"))
				r.Use(trackingMiddleware("Global2"))
				r.Use(trackingMiddleware("Global3"))
				r.Get("/test", testHandler)
				return r
			},
		},
		{
			name: "GlobalPlusRouteMiddleware",
			setupFunc: func() *nanite.Router {
				r := nanite.New()
				r.Use(trackingMiddleware("Global"))
				r.Get("/test", testHandler, trackingMiddleware("Route"))
				return r
			},
		},
		{
			name: "ComplexMiddlewareStack",
			setupFunc: func() *nanite.Router {
				r := nanite.New()
				r.Use(trackingMiddleware("Global1"))
				r.Use(trackingMiddleware("Global2"))
				r.Get("/test", testHandler,
					trackingMiddleware("Route1"),
					trackingMiddleware("Route2"),
					stackTraceMiddleware)
				return r
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := tt.setupFunc()

			// Run multiple requests to detect growing stacks
			for i := 0; i < 1000; i++ {
				req := httptest.NewRequest("GET", "/test", nil)
				w := httptest.NewRecorder()

				router.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Errorf("Request %d failed with status: %d", i, w.Code)
					break
				}

				// Check for growing stack depth (potential memory leak)
				if i > 0 && i%100 == 0 {
					var m runtime.MemStats
					runtime.ReadMemStats(&m)
					t.Logf("Request %d - Alloc: %v MB, StackInuse: %v MB",
						i, m.Alloc/1024/1024, m.StackInuse/1024/1024)
				}
			}
		})
	}
}

func TestRouteWithThreeMiddlewares(t *testing.T) {
	// This test focuses specifically on the case from the benchmark that failed
	router := nanite.New()
	router.Use(trackingMiddleware("Global"))

	router.Get("/products/:id", testHandler,
		trackingMiddleware("Route1"),
		trackingMiddleware("Route2"))

	// Run multiple iterations, similar to the benchmark
	for i := 0; i < 5000; i++ {
		req := httptest.NewRequest("GET", "/products/456", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		if i > 0 && i%1000 == 0 {
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			t.Logf("Iteration %d - Heap: %v MB, Stack: %v MB",
				i, m.HeapAlloc/1024/1024, m.StackInuse/1024/1024)

			// Force GC to see if memory is being properly cleaned up
			runtime.GC()
			time.Sleep(10 * time.Millisecond)
		}
	}
}
