package hostlib

import (
	"context"
)

// Middleware is a function that wraps a ByteHandler to add cross-cutting behavior.
// Middleware executes in FIFO order (first registered wraps first, onion model).
//
// Example usage:
//
//	loggingMiddleware := func(next ByteHandler) ByteHandler {
//	    return func(ctx context.Context, payload []byte) ([]byte, error) {
//	        log.Printf("invoking handler...")
//	        return next(ctx, payload)
//	    }
//	}
type Middleware func(next ByteHandler) ByteHandler

// RegistryOption is a functional option for configuring a HandlerRegistry.
type RegistryOption func(*registryBuilder)

// PanicRecoveryMiddleware returns a middleware that catches panics and converts
// them to structured ErrorResponse JSON instead of crashing the host.
func PanicRecoveryMiddleware() Middleware {
	return func(next ByteHandler) ByteHandler {
		return func(ctx context.Context, payload []byte) (resp []byte, err error) {
			defer func() {
				if r := recover(); r != nil {
					resp = NewPanicError(r).ToJSON()
					err = nil // Return JSON error, not Go error
				}
			}()
			return next(ctx, payload)
		}
	}
}

// LoggingMiddleware returns a middleware that logs host function invocations.
// This is provided as an example; production code should use a structured logger.
func LoggingMiddleware(logFn func(format string, args ...any)) Middleware {
	return func(next ByteHandler) ByteHandler {
		return func(ctx context.Context, payload []byte) ([]byte, error) {
			funcName := "unknown"
			if hc, ok := ctx.(HostContext); ok {
				funcName = hc.FunctionName()
			}
			logFn("invoking host function: %s", funcName)
			resp, err := next(ctx, payload)
			if err != nil {
				logFn("host function %s failed: %v", funcName, err)
			} else {
				logFn("host function %s completed", funcName)
			}
			return resp, err
		}
	}
}
