package hostlib

import (
	"bytes"
)

// DefaultMaxOutputSize is the default limit for stdout/stderr from exec commands (10MB).
// Prevents excessive memory usage from long-running commands with verbose output.
const DefaultMaxOutputSize = 10 * 1024 * 1024

// DefaultMaxRequestSize limits the size of incoming requests (1MB).
// This prevents malicious WASM modules from triggering OOM by claiming huge request sizes.
const DefaultMaxRequestSize = 1 * 1024 * 1024

// BoundedBuffer is a bytes.Buffer wrapper that limits the size of written data.
// It implements io.Writer and can be used with exec.Cmd's Stdout/Stderr.
type BoundedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	Truncated bool
}

// NewBoundedBuffer creates a new BoundedBuffer with the specified limit.
func NewBoundedBuffer(limit int) *BoundedBuffer {
	return &BoundedBuffer{
		limit: limit,
	}
}

// Write implements io.Writer.
// It writes data up to the limit and then silently discards any additional data.
// The Truncated field is set to true if any data was discarded.
func (b *BoundedBuffer) Write(p []byte) (n int, err error) {
	if b.buffer.Len() >= b.limit {
		b.Truncated = true
		return len(p), nil // Pretend we wrote it all to satisfy io.Writer contract
	}

	remaining := b.limit - b.buffer.Len()
	if len(p) > remaining {
		b.Truncated = true
		n, err = b.buffer.Write(p[:remaining])
		if err != nil {
			return n, err
		}
		return len(p), nil // Return len(p) to avoid short write error
	}

	return b.buffer.Write(p)
}

// String returns the buffer contents as a string.
func (b *BoundedBuffer) String() string {
	return b.buffer.String()
}

// Bytes returns the buffer contents as a byte slice.
func (b *BoundedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

// Len returns the current length of the buffer.
func (b *BoundedBuffer) Len() int {
	return b.buffer.Len()
}

// Reset resets the buffer and clears the Truncated flag.
func (b *BoundedBuffer) Reset() {
	b.buffer.Reset()
	b.Truncated = false
}
