package hostlib

import (
	"encoding/json"
)

// ErrorResponse represents a structured error that can be returned as JSON to plugins.
// This ensures plugins receive consistent, parseable errors instead of causing WASM traps.
type ErrorResponse struct {
	// Error is a machine-readable error type identifier (e.g., "VALIDATION_ERROR", "INTERNAL_ERROR").
	Error string `json:"error"`

	// Message is a human-readable error description.
	Message string `json:"message"`

	// Code is a numeric error code (e.g., 400, 500).
	Code int `json:"code"`
}

// ToJSON serializes the ErrorResponse to JSON bytes.
// Returns nil if serialization fails (which should never happen for this simple type).
func (e ErrorResponse) ToJSON() []byte {
	data, err := json.Marshal(e)
	if err != nil {
		return nil
	}
	return data
}

// NewValidationError creates an error response for bad input (e.g., malformed JSON).
func NewValidationError(message string) ErrorResponse {
	return ErrorResponse{
		Error:   "VALIDATION_ERROR",
		Message: message,
		Code:    400,
	}
}

// NewNotFoundError creates an error response for unknown handler names.
func NewNotFoundError(name string) ErrorResponse {
	return ErrorResponse{
		Error:   "NOT_FOUND",
		Message: "unknown host function: " + name,
		Code:    404,
	}
}

// NewInternalError creates an error response for unexpected failures.
func NewInternalError(message string) ErrorResponse {
	return ErrorResponse{
		Error:   "INTERNAL_ERROR",
		Message: message,
		Code:    500,
	}
}

// NewPanicError creates an error response for recovered panics.
func NewPanicError(panicValue any) ErrorResponse {
	var msg string
	if err, ok := panicValue.(error); ok {
		msg = err.Error()
	} else if s, ok := panicValue.(string); ok {
		msg = s
	} else {
		msg = "panic recovered"
	}
	return ErrorResponse{
		Error:   "INTERNAL_ERROR",
		Message: "panic: " + msg,
		Code:    500,
	}
}
