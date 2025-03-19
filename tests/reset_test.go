package nanite_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/xDarkicex/nanite"
)

// testHelper manages test context lifecycle
type testHelper struct {
	router  *nanite.Router
	mu      sync.Mutex // Protects route registration
	counter int
}

func newTestHelper() *testHelper {
	return &testHelper{
		router: nanite.New(),
	}
}

func (th *testHelper) acquireContext() *nanite.Context {
	th.mu.Lock()
	defer th.mu.Unlock()

	path := "/__test"
	var ctx *nanite.Context

	// Create unique route using path + counter
	th.router.Get(path, func(c *nanite.Context) {
		ctx = c
	})

	// Create request with unique URL parameter
	req := httptest.NewRequest("GET", fmt.Sprintf("%s?_=%d", path, th.counter), nil)
	th.counter++

	rec := httptest.NewRecorder()
	th.router.ServeHTTP(rec, req)
	return ctx
}

// TestReset contains all context reset related tests
func TestReset(t *testing.T) {
	th := newTestHelper()

	t.Run("BasicReset", func(t *testing.T) {
		ctx := th.acquireContext()
		defer ctx.Reset(nil, nil)

		// Initial request
		rec := httptest.NewRecorder()
		ctx.Reset(rec, httptest.NewRequest("GET", "/", nil))
		ctx.String(http.StatusOK, "test")

		// Reset and verify
		newRec := httptest.NewRecorder()
		ctx.Reset(newRec, httptest.NewRequest("GET", "/v2", nil))

		if ctx.IsWritten() {
			t.Error("IsWritten() should be false after reset")
		}
		if ctx.WrittenBytes() != 0 {
			t.Error("WrittenBytes() should reset to 0")
		}
	})

	t.Run("JSONReset", func(t *testing.T) {
		ctx := th.acquireContext()
		defer ctx.Reset(nil, nil)

		rec := httptest.NewRecorder()
		ctx.Reset(rec, httptest.NewRequest("POST", "/", nil))
		ctx.JSON(http.StatusCreated, map[string]string{"status": "created"})

		// Reset and check
		ctx.Reset(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		if ctx.Values["body"] != nil {
			t.Error("Body should be cleared after reset")
		}
	})

	t.Run("FormDataReset", func(t *testing.T) {
		ctx := th.acquireContext()
		defer ctx.Reset(nil, nil)

		// Simulate form submission
		req := httptest.NewRequest("POST", "/", strings.NewReader("name=Alice&age=30"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		ctx.Reset(httptest.NewRecorder(), req)
		ctx.Request.ParseForm()

		// Reset and verify
		ctx.Reset(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		if ctx.Values["formData"] != nil {
			t.Error("Form data should be cleared after reset")
		}
	})

	t.Run("MultipleResets", func(t *testing.T) {
		ctx := th.acquireContext()
		defer ctx.Reset(nil, nil)

		for i := 0; i < 10; i++ {
			rec := httptest.NewRecorder()
			ctx.Reset(rec, httptest.NewRequest("GET", "/", nil))
			ctx.String(http.StatusOK, "iteration "+string(rune(i)))
			ctx.Reset(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		}

		if ctx.WrittenBytes() != 0 {
			t.Error("Written bytes should reset to 0 after multiple cycles")
		}
	})

	t.Run("ConcurrentResets", func(t *testing.T) {
		var wg sync.WaitGroup
		testErr := make(chan error, 1)

		for i := 0; i < 10000; i++ {
			wg.Add(1)
			go func(iter int) {
				defer wg.Done()
				th := newTestHelper()
				ctx := th.acquireContext()
				defer ctx.Reset(nil, nil)

				// Use local response recorder
				rec := httptest.NewRecorder()
				req := httptest.NewRequest("GET", "/", nil)

				ctx.Reset(rec, req)
				ctx.String(http.StatusOK, fmt.Sprintf("goroutine %d", iter))

				// Verify local response
				if !strings.Contains(rec.Body.String(), fmt.Sprintf("goroutine %d", iter)) {
					testErr <- fmt.Errorf("goroutine %d response mismatch", iter)
				}
			}(i)
		}

		go func() {
			wg.Wait()
			close(testErr)
		}()

		for err := range testErr {
			t.Error(err)
		}
	})

	t.Run("ResetWithNil", func(t *testing.T) {
		th := newTestHelper()
		ctx := th.acquireContext()
		defer ctx.Reset(nil, nil)

		// Test nil parameters
		ctx.Reset(nil, nil)
		if ctx.Writer != nil {
			// Check if writer is actually functional
			defer func() {
				if r := recover(); r == nil {
					t.Error("Writer should be in invalid state after nil reset")
				}
			}()
			ctx.Writer.Write([]byte("test")) // Should panic
		}
	})

	t.Run("ValidationReset", func(t *testing.T) {
		ctx := th.acquireContext()
		defer ctx.Reset(nil, nil)

		// Create validation error
		ctx.ValidationErrs = append(ctx.ValidationErrs, nanite.ValidationError{
			Field: "email",
			Err:   "invalid format",
		})

		// Reset and check
		ctx.Reset(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		if len(ctx.ValidationErrs) > 0 {
			t.Error("Validation errors should be reset")
		}
	})

}

// BenchmarkContextReset measures reset performance
func BenchmarkContextReset(b *testing.B) {
	th := newTestHelper()
	ctx := th.acquireContext()
	defer ctx.Reset(nil, nil)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		ctx.Reset(rec, req)
		ctx.Reset(nil, nil)
	}
}
