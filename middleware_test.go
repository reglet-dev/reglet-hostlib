package hostlib

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPanicRecoveryMiddleware(t *testing.T) {
	panicHandler := func(ctx context.Context, payload []byte) ([]byte, error) {
		panic("test panic")
	}

	mw := PanicRecoveryMiddleware()
	wrapped := mw(panicHandler)

	// Should not panic, should return structured error
	resp, err := wrapped(context.Background(), []byte("{}"))
	require.NoError(t, err)
	require.NotNil(t, resp)

	var errResp ErrorResponse
	require.NoError(t, json.Unmarshal(resp, &errResp))
	assert.Equal(t, "INTERNAL_ERROR", errResp.Error)
	assert.Equal(t, 500, errResp.Code)
	assert.Contains(t, errResp.Message, "panic")
	assert.Contains(t, errResp.Message, "test panic")
}

func TestPanicRecoveryMiddleware_NoPanic(t *testing.T) {
	normalHandler := func(ctx context.Context, payload []byte) ([]byte, error) {
		return []byte(`{"result":"ok"}`), nil
	}

	mw := PanicRecoveryMiddleware()
	wrapped := mw(normalHandler)

	resp, err := wrapped(context.Background(), []byte("{}"))
	require.NoError(t, err)
	assert.Equal(t, `{"result":"ok"}`, string(resp))
}

func TestMiddlewareOrder_FIFO(t *testing.T) {
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

	middleware3 := func(next ByteHandler) ByteHandler {
		return func(ctx context.Context, payload []byte) ([]byte, error) {
			callOrder = append(callOrder, "mw3-before")
			resp, err := next(ctx, payload)
			callOrder = append(callOrder, "mw3-after")
			return resp, err
		}
	}

	handler := func(ctx context.Context, payload []byte) ([]byte, error) {
		callOrder = append(callOrder, "handler")
		return nil, nil
	}

	reg, err := NewRegistry(
		WithMiddleware(middleware1, middleware2, middleware3),
		WithByteHandler("test", handler),
	)
	require.NoError(t, err)

	_, err = reg.Invoke(context.Background(), "test", nil)
	require.NoError(t, err)

	// FIFO: mw1 wraps mw2 wraps mw3 wraps handler (onion model)
	expected := []string{
		"mw1-before", "mw2-before", "mw3-before",
		"handler",
		"mw3-after", "mw2-after", "mw1-after",
	}
	assert.Equal(t, expected, callOrder)
}

func TestMiddleware_AppliesToAllHandlers(t *testing.T) {
	handlerCalls := make(map[string]bool)

	trackingMiddleware := func(next ByteHandler) ByteHandler {
		return func(ctx context.Context, payload []byte) ([]byte, error) {
			if hc, ok := ctx.(HostContext); ok {
				handlerCalls[hc.FunctionName()] = true
			}
			return next(ctx, payload)
		}
	}

	handler1 := func(ctx context.Context, payload []byte) ([]byte, error) {
		return nil, nil
	}
	handler2 := func(ctx context.Context, payload []byte) ([]byte, error) {
		return nil, nil
	}

	reg, err := NewRegistry(
		WithMiddleware(trackingMiddleware),
		WithByteHandler("handler1", handler1),
		WithByteHandler("handler2", handler2),
	)
	require.NoError(t, err)

	_, _ = reg.Invoke(context.Background(), "handler1", nil)
	_, _ = reg.Invoke(context.Background(), "handler2", nil)

	assert.True(t, handlerCalls["handler1"])
	assert.True(t, handlerCalls["handler2"])
}

func TestLoggingMiddleware(t *testing.T) {
	var logs []string
	logFn := func(format string, args ...any) {
		logs = append(logs, format)
	}

	handler := func(ctx context.Context, payload []byte) ([]byte, error) {
		return []byte("ok"), nil
	}

	reg, err := NewRegistry(
		WithMiddleware(LoggingMiddleware(logFn)),
		WithByteHandler("test", handler),
	)
	require.NoError(t, err)

	_, err = reg.Invoke(context.Background(), "test", nil)
	require.NoError(t, err)

	assert.Len(t, logs, 2)
	assert.Contains(t, logs[0], "invoking")
	assert.Contains(t, logs[1], "completed")
}
