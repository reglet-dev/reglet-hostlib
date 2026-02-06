package hostlib

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHostContext(t *testing.T) {
	ctx := context.Background()
	hc := NewHostContext(ctx, "dns_lookup")

	require.NotNil(t, hc)
	assert.Equal(t, "dns_lookup", hc.FunctionName())
}

func TestHostContext_SetGetValue(t *testing.T) {
	hc := NewHostContext(context.Background(), "test_func")

	// Initially no value
	_, ok := hc.GetValue("key1")
	assert.False(t, ok)

	// Set a value
	hc.SetValue("key1", "value1")
	val, ok := hc.GetValue("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)

	// Set another value
	hc.SetValue("key2", 42)
	val2, ok := hc.GetValue("key2")
	assert.True(t, ok)
	assert.Equal(t, 42, val2)

	// First value still there
	val, ok = hc.GetValue("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)
}

func TestHostContext_ImplementsContext(t *testing.T) {
	parent := context.Background()
	hc := NewHostContext(parent, "http_request")

	// Verify it implements context.Context
	var ctx context.Context = hc
	assert.NotNil(t, ctx)

	// Verify context methods work
	assert.Nil(t, hc.Done())
	assert.Nil(t, hc.Err())
	assert.Nil(t, hc.Value("nonexistent"))
}

func TestHostContextFrom(t *testing.T) {
	t.Run("wraps plain context", func(t *testing.T) {
		ctx := context.Background()
		hc := HostContextFrom(ctx, "tcp_connect")
		assert.Equal(t, "tcp_connect", hc.FunctionName())
	})

	t.Run("returns existing HostContext unchanged", func(t *testing.T) {
		original := NewHostContext(context.Background(), "original")
		original.SetValue("marker", true)

		returned := HostContextFrom(original, "different")

		// Should return the same HostContext
		assert.Equal(t, "original", returned.FunctionName())
		val, ok := returned.GetValue("marker")
		assert.True(t, ok)
		assert.Equal(t, true, val)
	})
}
