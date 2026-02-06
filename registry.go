package hostlib

import (
	"context"
	"fmt"
	"sort"
)

// HandlerRegistry is an immutable collection of named host functions.
// Once created via NewRegistry, handlers cannot be added or removed.
// This ensures thread safety and lock-free lookups during execution.
type HandlerRegistry struct {
	handlers   map[string]ByteHandler
	names      []string // sorted for consistent iteration
	middleware []Middleware
}

// registryBuilder accumulates configuration during registry construction.
type registryBuilder struct {
	handlers   map[string]ByteHandler
	middleware []Middleware
	errors     []error
}

// NewRegistry creates an immutable HandlerRegistry with the given options.
// Returns an error if any handler name is registered twice.
//
// Example usage:
//
//	registry, err := NewRegistry(
//	    WithMiddleware(PanicRecoveryMiddleware()),
//	    WithBundle(AllBundles()),
//	    WithHandler("custom", customHandler),
//	)
func NewRegistry(opts ...RegistryOption) (*HandlerRegistry, error) {
	b := &registryBuilder{
		handlers:   make(map[string]ByteHandler),
		middleware: nil,
		errors:     nil,
	}

	for _, opt := range opts {
		opt(b)
	}

	if len(b.errors) > 0 {
		return nil, b.errors[0] // Return first error
	}

	// Build sorted name list for consistent iteration
	names := make([]string, 0, len(b.handlers))
	for name := range b.handlers {
		names = append(names, name)
	}
	sort.Strings(names)

	// Apply middleware chain to all handlers (FIFO order)
	wrappedHandlers := make(map[string]ByteHandler, len(b.handlers))
	for name, handler := range b.handlers {
		wrapped := handler
		// Apply middleware in reverse order so first middleware wraps outermost
		for i := len(b.middleware) - 1; i >= 0; i-- {
			wrapped = b.middleware[i](wrapped)
		}
		wrappedHandlers[name] = wrapped
	}

	return &HandlerRegistry{
		handlers:   wrappedHandlers,
		names:      names,
		middleware: b.middleware,
	}, nil
}

// Invoke dispatches a host function call by name.
// Returns the JSON response bytes, or an ErrorResponse JSON if the handler is not found.
func (r *HandlerRegistry) Invoke(ctx context.Context, name string, payload []byte) ([]byte, error) {
	handler, ok := r.handlers[name]
	if !ok {
		return NewNotFoundError(name).ToJSON(), nil
	}

	// Wrap context with function name for middleware access
	hctx := HostContextFrom(ctx, name)
	return handler(hctx, payload)
}

// Has returns true if a handler with the given name is registered.
func (r *HandlerRegistry) Has(name string) bool {
	_, ok := r.handlers[name]
	return ok
}

// Names returns a sorted list of all registered handler names.
func (r *HandlerRegistry) Names() []string {
	result := make([]string, len(r.names))
	copy(result, r.names)
	return result
}

// addHandler registers a handler with the given name.
// Returns an error if the name is already registered.
func (b *registryBuilder) addHandler(name string, handler ByteHandler) error {
	if name == "" {
		return fmt.Errorf("handler name cannot be empty")
	}
	if _, exists := b.handlers[name]; exists {
		return fmt.Errorf("duplicate handler name: %q", name)
	}
	b.handlers[name] = handler
	return nil
}

// WithByteHandler registers a raw ByteHandler with the given name.
// Use WithHandler for type-safe registration with automatic JSON handling.
func WithByteHandler(name string, handler ByteHandler) RegistryOption {
	return func(b *registryBuilder) {
		if err := b.addHandler(name, handler); err != nil {
			b.errors = append(b.errors, err)
		}
	}
}

// WithMiddleware adds middleware to the registry.
// Middleware executes in FIFO order (first added wraps first).
func WithMiddleware(mw ...Middleware) RegistryOption {
	return func(b *registryBuilder) {
		b.middleware = append(b.middleware, mw...)
	}
}
