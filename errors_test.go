package hostlib

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorResponse_ToJSON(t *testing.T) {
	tests := []struct {
		name     string
		err      ErrorResponse
		expected string
	}{
		{
			name: "validation error",
			err: ErrorResponse{
				Error:   "VALIDATION_ERROR",
				Message: "invalid JSON",
				Code:    400,
			},
			expected: `{"error":"VALIDATION_ERROR","message":"invalid JSON","code":400}`,
		},
		{
			name: ErrorResponse{
				Error:   "NOT_FOUND",
				Message: "unknown host function: foo",
				Code:    404,
			}.Error,
			err: ErrorResponse{
				Error:   "NOT_FOUND",
				Message: "unknown host function: foo",
				Code:    404,
			},
			expected: `{"error":"NOT_FOUND","message":"unknown host function: foo","code":404}`,
		},
		{
			name: "internal error",
			err: ErrorResponse{
				Error:   "INTERNAL_ERROR",
				Message: "panic: oh no",
				Code:    500,
			},
			expected: `{"error":"INTERNAL_ERROR","message":"panic: oh no","code":500}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.ToJSON()
			require.NotNil(t, got)
			assert.JSONEq(t, tt.expected, string(got))
		})
	}
}

func TestNewValidationError(t *testing.T) {
	err := NewValidationError("failed to unmarshal request")
	assert.Equal(t, "VALIDATION_ERROR", err.Error)
	assert.Equal(t, "failed to unmarshal request", err.Message)
	assert.Equal(t, 400, err.Code)
}

func TestNewNotFoundError(t *testing.T) {
	err := NewNotFoundError("unknown_func")
	assert.Equal(t, "NOT_FOUND", err.Error)
	assert.Equal(t, "unknown host function: unknown_func", err.Message)
	assert.Equal(t, 404, err.Code)
}

func TestNewInternalError(t *testing.T) {
	err := NewInternalError("database connection failed")
	assert.Equal(t, "INTERNAL_ERROR", err.Error)
	assert.Equal(t, "database connection failed", err.Message)
	assert.Equal(t, 500, err.Code)
}

func TestNewPanicError(t *testing.T) {
	tests := []struct {
		name       string
		panicValue any
		wantMsg    string
	}{
		{
			name:       "string panic",
			panicValue: "oops",
			wantMsg:    "panic: oops",
		},
		{
			name:       "error panic",
			panicValue: func() error { var v any; return json.Unmarshal(nil, &v) }(),
			wantMsg:    "panic: unexpected end of JSON input",
		},
		{
			name:       "other panic",
			panicValue: 42,
			wantMsg:    "panic: panic recovered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewPanicError(tt.panicValue)
			assert.Equal(t, "INTERNAL_ERROR", err.Error)
			assert.Equal(t, tt.wantMsg, err.Message)
			assert.Equal(t, 500, err.Code)
		})
	}
}
