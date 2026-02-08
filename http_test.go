package hostlib

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerformHTTPRequest_InvalidURL(t *testing.T) {
	req := HTTPRequest{
		Method: "GET",
		URL:    "",
	}

	resp := PerformHTTPRequest(context.Background(), req)

	require.NotNil(t, resp.Error)
	assert.Equal(t, "INVALID_REQUEST", resp.Error.Code)
}

func TestPerformHTTPRequest_DefaultMethod(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	req := HTTPRequest{
		URL:     "https://example.com",
		Timeout: 5000,
	}

	resp := PerformHTTPRequest(context.Background(), req)

	// Should succeed or fail with network error, not INVALID_REQUEST
	if resp.Error != nil {
		assert.NotEqual(t, "INVALID_REQUEST", resp.Error.Code)
	}
}

func TestHTTPRequest_Fields(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer token"}
	followRedirects := false

	req := HTTPRequest{
		Method:          "POST",
		URL:             "https://api.example.com/v1",
		Headers:         headers,
		Body:            []byte(`{"key": "value"}`),
		Timeout:         30000,
		FollowRedirects: &followRedirects,
		MaxRedirects:    5,
	}

	assert.Equal(t, "POST", req.Method)
	assert.Equal(t, "https://api.example.com/v1", req.URL)
	assert.Equal(t, headers, req.Headers)
	assert.Equal(t, []byte(`{"key": "value"}`), req.Body)
	assert.Equal(t, 30000, req.Timeout)
	assert.False(t, *req.FollowRedirects)
	assert.Equal(t, 5, req.MaxRedirects)
}

func TestHTTPResponse_Fields(t *testing.T) {
	resp := HTTPResponse{
		StatusCode:    200,
		Headers:       map[string][]string{"Content-Type": {"application/json"}},
		Body:          []byte(`{"result": "ok"}`),
		BodyTruncated: false,
		LatencyMs:     150,
	}

	assert.Equal(t, 200, resp.StatusCode)
	assert.Equal(t, "application/json", resp.Headers["Content-Type"][0])
	assert.Equal(t, []byte(`{"result": "ok"}`), resp.Body)
	assert.False(t, resp.BodyTruncated)
	assert.Equal(t, int64(150), resp.LatencyMs)
}

func TestHTTPError_Error(t *testing.T) {
	err := &HTTPError{
		Code:    "TIMEOUT",
		Message: "request timed out",
	}

	assert.Equal(t, "request timed out", err.Error())
}

func TestDefaultHTTPConfig(t *testing.T) {
	cfg := defaultHTTPConfig()

	assert.Equal(t, 30*time.Second, cfg.timeout)
	assert.Equal(t, 10, cfg.maxRedirects)
	assert.True(t, cfg.followRedirects)
	assert.Equal(t, int64(10*1024*1024), cfg.maxBodySize)
}

func TestHTTPOptions(t *testing.T) {
	cfg := defaultHTTPConfig()

	WithHTTPRequestTimeout(60 * time.Second)(&cfg)
	assert.Equal(t, 60*time.Second, cfg.timeout)

	WithHTTPMaxRedirects(5)(&cfg)
	assert.Equal(t, 5, cfg.maxRedirects)

	WithHTTPFollowRedirects(false)(&cfg)
	assert.False(t, cfg.followRedirects)

	WithHTTPMaxBodySize(1024)(&cfg)
	assert.Equal(t, int64(1024), cfg.maxBodySize)
}

func TestHTTPOptions_IgnoresInvalid(t *testing.T) {
	cfg := defaultHTTPConfig()

	WithHTTPRequestTimeout(-1 * time.Second)(&cfg)
	assert.Equal(t, 30*time.Second, cfg.timeout, "should keep default for negative timeout")

	WithHTTPMaxRedirects(-1)(&cfg)
	assert.Equal(t, 10, cfg.maxRedirects, "should keep default for negative redirects")

	WithHTTPMaxBodySize(-1)(&cfg)
	assert.Equal(t, int64(10*1024*1024), cfg.maxBodySize, "should keep default for negative body size")
}

func TestPerformHTTPRequest_SSRFProtection_BlocksPrivateIP(t *testing.T) {
	resp := PerformHTTPRequest(context.Background(),
		HTTPRequest{Method: "GET", URL: "http://127.0.0.1/"},
		WithHTTPSSRFProtection(false),
	)
	require.NotNil(t, resp.Error)
	assert.Equal(t, "SSRF_BLOCKED", resp.Error.Code)
}

func TestPerformHTTPRequest_SSRFProtection_AllowPrivateWhenEnabled(t *testing.T) {
	// For this test, we expect it NOT to be blocked by SSRF,
	// but it likely fails to connect since nothing is running on 127.0.0.1:80
	// unless we spin up a server.
	// But the key is that error code is NOT "SSRF_BLOCKED".

	resp := PerformHTTPRequest(context.Background(),
		HTTPRequest{Method: "GET", URL: "http://127.0.0.1/"},
		// Allow private IPs
		WithHTTPSSRFProtection(true),
		// Short timeout to fail fast if it tries to connect
		WithHTTPRequestTimeout(100*time.Millisecond),
	)

	// If it fails, it should NOT be SSRF_BLOCKED
	if resp.Error != nil {
		assert.NotEqual(t, "SSRF_BLOCKED", resp.Error.Code, "Should allow private IP connection")
	}
}
