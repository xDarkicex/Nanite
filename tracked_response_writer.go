package nanite

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
)

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
