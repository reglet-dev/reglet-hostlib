package hostlib

import (
	"context"
	"encoding/json"
	"fmt"
)

// HostFunc is a generic function signature for host functions.
// It accepts a context and a typed request, and returns a typed response.
type HostFunc[Req any, Resp any] func(context.Context, Req) Resp

// ByteHandler is a function that accepts raw bytes (JSON) and returns raw bytes (JSON).
// This is the common interface that WASM runtimes can easily use.
type ByteHandler func(context.Context, []byte) ([]byte, error)

// NewJSONHandler wraps a typed HostFunc into a ByteHandler.
// It handles the JSON unmarshalling of the request and marshaling of the response.
//
// For infrastructure failures (malformed JSON, serialization errors), the handler
// returns a structured ErrorResponse JSON instead of a Go error. This ensures
// plugins always receive valid JSON and prevents WASM runtime traps.
//
// Usage:
//
//	execHandler := hostfuncs.NewJSONHandler(func(ctx context.Context, req hostfuncs.ExecCommandRequest) hostfuncs.ExecCommandResponse {
//	    return hostfuncs.PerformExecCommand(ctx, req)
//	})
//
//	// In WASM runtime handler:
//	reqBytes := readMemory(ptr, len)
//	respBytes, err := execHandler(ctx, reqBytes)
//	writeMemory(respBytes)
func NewJSONHandler[Req any, Resp any](fn HostFunc[Req, Resp]) ByteHandler {
	return func(ctx context.Context, payload []byte) ([]byte, error) {
		var req Req
		if err := json.Unmarshal(payload, &req); err != nil {
			// Return structured JSON error instead of Go error
			return NewValidationError(fmt.Sprintf("failed to unmarshal request: %v", err)).ToJSON(), nil
		}

		resp := fn(ctx, req)

		respBytes, err := json.Marshal(resp)
		if err != nil {
			// Return structured JSON error instead of Go error
			return NewInternalError(fmt.Sprintf("failed to marshal response: %v", err)).ToJSON(), nil
		}

		return respBytes, nil
	}
}
