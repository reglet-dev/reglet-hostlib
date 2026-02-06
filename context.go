package hostlib

import (
	"context"
)

// HostContext wraps a standard context.Context with host function-specific helpers.
// It provides access to the invoked function name and allows middleware to store
// request-scoped values without polluting the standard context.
type HostContext interface {
	context.Context

	// FunctionName returns the name of the host function being invoked.
	FunctionName() string

	// SetValue stores a request-scoped value. Unlike context.WithValue,
	// this mutates the existing HostContext for performance.
	SetValue(key, value any)

	// GetValue retrieves a request-scoped value set by SetValue.
	GetValue(key any) (value any, ok bool)
}

// hostContext is the concrete implementation of HostContext.
type hostContext struct {
	context.Context
	values   map[any]any
	funcName string
}

// NewHostContext creates a new HostContext wrapping the given context.
func NewHostContext(ctx context.Context, funcName string) HostContext {
	return &hostContext{
		Context:  ctx,
		funcName: funcName,
		values:   make(map[any]any),
	}
}

// FunctionName returns the name of the host function being invoked.
func (c *hostContext) FunctionName() string {
	return c.funcName
}

// SetValue stores a request-scoped value.
func (c *hostContext) SetValue(key, value any) {
	c.values[key] = value
}

// GetValue retrieves a request-scoped value.
func (c *hostContext) GetValue(key any) (any, bool) {
	v, ok := c.values[key]
	return v, ok
}

// HostContextFrom extracts a HostContext from a context.Context.
// If the context is already a HostContext, it is returned directly.
// Otherwise, a new HostContext is created wrapping the given context.
func HostContextFrom(ctx context.Context, funcName string) HostContext {
	if hc, ok := ctx.(HostContext); ok {
		return hc
	}
	return NewHostContext(ctx, funcName)
}
