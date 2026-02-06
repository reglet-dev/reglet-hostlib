package hostlib

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkBundle(t *testing.T) {
	bundle := NetworkBundle()
	handlers := bundle.Handlers()

	assert.Len(t, handlers, 3)
	assert.Contains(t, handlers, "dns_lookup")
	assert.Contains(t, handlers, "tcp_connect")
	assert.Contains(t, handlers, "http_request")
}

func TestExecBundle(t *testing.T) {
	bundle := ExecBundle()
	handlers := bundle.Handlers()

	assert.Len(t, handlers, 1)
	assert.Contains(t, handlers, "exec_command")
}

func TestSMTPBundle(t *testing.T) {
	bundle := SMTPBundle()
	handlers := bundle.Handlers()

	assert.Len(t, handlers, 1)
	assert.Contains(t, handlers, "smtp_connect")
}

func TestNetfilterBundle(t *testing.T) {
	bundle := NetfilterBundle()
	handlers := bundle.Handlers()

	assert.Len(t, handlers, 1)
	assert.Contains(t, handlers, "ssrf_check")
}

func TestAllBundles(t *testing.T) {
	bundle := AllBundles()
	handlers := bundle.Handlers()

	// Should include all 6 built-in functions
	assert.Len(t, handlers, 6)
	assert.Contains(t, handlers, "dns_lookup")
	assert.Contains(t, handlers, "tcp_connect")
	assert.Contains(t, handlers, "http_request")
	assert.Contains(t, handlers, "exec_command")
	assert.Contains(t, handlers, "smtp_connect")
	assert.Contains(t, handlers, "ssrf_check")
}

func TestWithBundle(t *testing.T) {
	reg, err := NewRegistry(
		WithBundle(NetworkBundle()),
	)
	require.NoError(t, err)

	names := reg.Names()
	assert.Len(t, names, 3)
	assert.Contains(t, names, "dns_lookup")
	assert.Contains(t, names, "tcp_connect")
	assert.Contains(t, names, "http_request")
}

func TestWithBundle_AllBundles(t *testing.T) {
	reg, err := NewRegistry(
		WithBundle(AllBundles()),
	)
	require.NoError(t, err)

	names := reg.Names()
	assert.Len(t, names, 6)
}

func TestWithHandler_Generic(t *testing.T) {
	type CustomReq struct {
		Input string `json:"input"`
	}
	type CustomResp struct {
		Output string `json:"output"`
	}

	reg, err := NewRegistry(
		WithHandler("custom", func(ctx context.Context, req CustomReq) CustomResp {
			return CustomResp{Output: "processed: " + req.Input}
		}),
	)
	require.NoError(t, err)

	assert.True(t, reg.Has("custom"))

	// Test invocation
	reqBytes, _ := json.Marshal(CustomReq{Input: "test"})
	respBytes, err := reg.Invoke(context.Background(), "custom", reqBytes)
	require.NoError(t, err)

	var resp CustomResp
	require.NoError(t, json.Unmarshal(respBytes, &resp))
	assert.Equal(t, "processed: test", resp.Output)
}

func TestWithHandler_AndBundle_Combined(t *testing.T) {
	type CustomReq struct {
		Value int `json:"value"`
	}
	type CustomResp struct {
		Doubled int `json:"doubled"`
	}

	reg, err := NewRegistry(
		WithBundle(ExecBundle()),
		WithHandler("double", func(ctx context.Context, req CustomReq) CustomResp {
			return CustomResp{Doubled: req.Value * 2}
		}),
	)
	require.NoError(t, err)

	names := reg.Names()
	assert.Len(t, names, 2)
	assert.Contains(t, names, "exec_command")
	assert.Contains(t, names, "double")

	// Test custom handler works
	reqBytes, _ := json.Marshal(CustomReq{Value: 21})
	respBytes, err := reg.Invoke(context.Background(), "double", reqBytes)
	require.NoError(t, err)

	var resp CustomResp
	require.NoError(t, json.Unmarshal(respBytes, &resp))
	assert.Equal(t, 42, resp.Doubled)
}
