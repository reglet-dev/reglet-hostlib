package hostlib

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRegistry_Empty(t *testing.T) {
	reg, err := NewRegistry()
	require.NoError(t, err)
	require.NotNil(t, reg)
	assert.Empty(t, reg.Names())
}

func TestNewRegistry_WithByteHandler(t *testing.T) {
	echoHandler := func(ctx context.Context, payload []byte) ([]byte, error) {
		return payload, nil
	}

	reg, err := NewRegistry(
		WithByteHandler("echo", echoHandler),
	)
	require.NoError(t, err)

	assert.True(t, reg.Has("echo"))
	assert.False(t, reg.Has("nonexistent"))
	assert.Equal(t, []string{"echo"}, reg.Names())
}

func TestNewRegistry_DuplicateHandler(t *testing.T) {
	handler := func(ctx context.Context, payload []byte) ([]byte, error) {
		return nil, nil
	}

	_, err := NewRegistry(
		WithByteHandler("test", handler),
		WithByteHandler("test", handler), // duplicate
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate handler name")
}

func TestNewRegistry_EmptyName(t *testing.T) {
	handler := func(ctx context.Context, payload []byte) ([]byte, error) {
		return nil, nil
	}

	_, err := NewRegistry(
		WithByteHandler("", handler),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be empty")
}

func TestHandlerRegistry_Invoke(t *testing.T) {
	echoHandler := func(ctx context.Context, payload []byte) ([]byte, error) {
		return append([]byte("echo:"), payload...), nil
	}

	reg, err := NewRegistry(
		WithByteHandler("echo", echoHandler),
	)
	require.NoError(t, err)

	t.Run("found handler", func(t *testing.T) {
		resp, err := reg.Invoke(context.Background(), "echo", []byte("hello"))
		require.NoError(t, err)
		assert.Equal(t, "echo:hello", string(resp))
	})

	t.Run("not found handler", func(t *testing.T) {
		resp, err := reg.Invoke(context.Background(), "unknown", []byte("test"))
		require.NoError(t, err)

		var errResp ErrorResponse
		require.NoError(t, json.Unmarshal(resp, &errResp))
		assert.Equal(t, "NOT_FOUND", errResp.Error)
		assert.Equal(t, 404, errResp.Code)
		assert.Contains(t, errResp.Message, "unknown")
	})
}

func TestHandlerRegistry_Names_Sorted(t *testing.T) {
	handler := func(ctx context.Context, payload []byte) ([]byte, error) {
		return nil, nil
	}

	reg, err := NewRegistry(
		WithByteHandler("zebra", handler),
		WithByteHandler("alpha", handler),
		WithByteHandler("middle", handler),
	)
	require.NoError(t, err)

	names := reg.Names()
	assert.Equal(t, []string{"alpha", "middle", "zebra"}, names)
}

func TestHandlerRegistry_Invoke_SetsHostContext(t *testing.T) {
	var capturedName string
	handler := func(ctx context.Context, payload []byte) ([]byte, error) {
		if hc, ok := ctx.(HostContext); ok {
			capturedName = hc.FunctionName()
		}
		return nil, nil
	}

	reg, err := NewRegistry(
		WithByteHandler("test_func", handler),
	)
	require.NoError(t, err)

	_, err = reg.Invoke(context.Background(), "test_func", nil)
	require.NoError(t, err)
	assert.Equal(t, "test_func", capturedName)
}

func TestWithMiddleware(t *testing.T) {
	var callOrder []string

	middleware1 := func(next ByteHandler) ByteHandler {
		return func(ctx context.Context, payload []byte) ([]byte, error) {
			callOrder = append(callOrder, "mw1-before")
			resp, err := next(ctx, payload)
			callOrder = append(callOrder, "mw1-after")
			return resp, err
		}
	}

	middleware2 := func(next ByteHandler) ByteHandler {
		return func(ctx context.Context, payload []byte) ([]byte, error) {
			callOrder = append(callOrder, "mw2-before")
			resp, err := next(ctx, payload)
			callOrder = append(callOrder, "mw2-after")
			return resp, err
		}
	}

	handler := func(ctx context.Context, payload []byte) ([]byte, error) {
		callOrder = append(callOrder, "handler")
		return nil, nil
	}

	reg, err := NewRegistry(
		WithMiddleware(middleware1, middleware2),
		WithByteHandler("test", handler),
	)
	require.NoError(t, err)

	_, err = reg.Invoke(context.Background(), "test", nil)
	require.NoError(t, err)

	// FIFO order: mw1 wraps mw2 wraps handler
	expected := []string{"mw1-before", "mw2-before", "handler", "mw2-after", "mw1-after"}
	assert.Equal(t, expected, callOrder)
}
