package nanite

import (
	"bytes"
	"net/http"
)

//------------------------------------------------------------------------------
// Buffered Response Writer
//------------------------------------------------------------------------------

// BufferedResponseWriter wraps TrackedResponseWriter with a buffer
type BufferedResponseWriter struct {
	*TrackedResponseWriter
	buffer     *bytes.Buffer
	bufferSize int
	autoFlush  bool
}

// newBufferedResponseWriter creates a new BufferedResponseWriter
func newBufferedResponseWriter(w *TrackedResponseWriter, bufferSize int) *BufferedResponseWriter {
	return &BufferedResponseWriter{
		TrackedResponseWriter: w,
		buffer:                bufferPool.Get().(*bytes.Buffer),
		bufferSize:            bufferSize,
		autoFlush:             true,
	}
}

// Write buffers the data and flushes when buffer exceeds size
func (w *BufferedResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten {
		w.WriteHeader(http.StatusOK)
	}

	// If this write would exceed buffer size, flush first
	if w.buffer.Len()+len(b) > w.bufferSize {
		w.Flush()
	}

	n, err := w.buffer.Write(b)
	w.bytesWritten += int64(n)

	// Auto-flush if enabled
	if w.autoFlush && w.buffer.Len() >= w.bufferSize {
		w.Flush()
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
