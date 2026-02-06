package hostlib

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewJSONHandler(t *testing.T) {
	// Define a simple test function
	type TestReq struct {
		Input string `json:"input"`
	}
	type TestResp struct {
		Output string `json:"output"`
	}

	echoFunc := func(ctx context.Context, req TestReq) TestResp {
		return TestResp{Output: "echo: " + req.Input}
	}

	handler := NewJSONHandler(echoFunc)

	t.Run("success", func(t *testing.T) {
		req := TestReq{Input: "hello"}
		reqBytes, err := json.Marshal(req)
		require.NoError(t, err)

		respBytes, err := handler(context.Background(), reqBytes)
		require.NoError(t, err)

		var resp TestResp
		err = json.Unmarshal(respBytes, &resp)
		require.NoError(t, err)
		assert.Equal(t, "echo: hello", resp.Output)
	})

	t.Run("invalid JSON returns ErrorResponse", func(t *testing.T) {
		// NewJSONHandler now returns structured JSON error instead of Go error
		respBytes, err := handler(context.Background(), []byte("{invalid-json"))
		require.NoError(t, err) // No Go error
		require.NotNil(t, respBytes)

		var errResp ErrorResponse
		require.NoError(t, json.Unmarshal(respBytes, &errResp))
		assert.Equal(t, "VALIDATION_ERROR", errResp.Error)
		assert.Equal(t, 400, errResp.Code)
		assert.Contains(t, errResp.Message, "unmarshal")
	})
}

func TestNewJSONHandler_WithExec(t *testing.T) {
	// Verify it works with the actual Exec types
	handler := NewJSONHandler(func(ctx context.Context, req ExecCommandRequest) ExecCommandResponse {
		// Mock implementation
		return ExecCommandResponse{
			Stdout:   "mocked",
			ExitCode: 0,
		}
	})

	req := ExecCommandRequest{Command: "echo"}
	reqBytes, err := json.Marshal(req)
	require.NoError(t, err)

	respBytes, err := handler(context.Background(), reqBytes)
	require.NoError(t, err)

	var resp ExecCommandResponse
	err = json.Unmarshal(respBytes, &resp)
	require.NoError(t, err)
	assert.Equal(t, "mocked", resp.Stdout)
}
