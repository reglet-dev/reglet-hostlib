package hostlib

import (
	"context"
	"encoding/json"
	"strings"
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

// UserAgentMiddleware returns a middleware that adds a User-Agent header to HTTP requests.
func UserAgentMiddleware(userAgent string) Middleware {
	return func(next ByteHandler) ByteHandler {
		return func(ctx context.Context, payload []byte) ([]byte, error) {
			funcName := ""
			if hc, ok := ctx.(HostContext); ok {
				funcName = hc.FunctionName()
			}

			if funcName == "http_request" {
				var req map[string]any
				if err := json.Unmarshal(payload, &req); err == nil {
					headers, ok := req["headers"].(map[string]any)
					if !ok {
						headers = make(map[string]any)
						req["headers"] = headers
					}
					// Only set if not already present
					found := false
					for k := range headers {
						if strings.EqualFold(k, "User-Agent") {
							found = true
							break
						}
					}
					if !found {
						headers["User-Agent"] = userAgent
						payload, _ = json.Marshal(req)
					}
				}
			}

			return next(ctx, payload)
		}
	}
}

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
