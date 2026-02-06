package hostlib

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerformTCPConnect_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	req := TCPConnectRequest{
		Host:    "example.com",
		Port:    80,
		Timeout: 5000,
	}

	resp := PerformTCPConnect(context.Background(), req)

	assert.True(t, resp.Connected, "should connect to example.com:80")
	assert.NotEmpty(t, resp.RemoteAddr, "should have remote address")
	assert.Nil(t, resp.Error)
	assert.Greater(t, resp.LatencyMs, int64(0), "should have non-zero latency")
}

func TestPerformTCPConnect_InvalidHost(t *testing.T) {
	req := TCPConnectRequest{
		Host: "",
		Port: 80,
	}

	resp := PerformTCPConnect(context.Background(), req)

	require.NotNil(t, resp.Error)
	assert.Equal(t, "INVALID_REQUEST", resp.Error.Code)
	assert.False(t, resp.Connected)
}

func TestPerformTCPConnect_InvalidPort(t *testing.T) {
	tests := []struct {
		name string
		port int
	}{
		{"zero port", 0},
		{"negative port", -1},
		{"port too high", 65536},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := TCPConnectRequest{
				Host: "example.com",
				Port: tc.port,
			}

			resp := PerformTCPConnect(context.Background(), req)

			require.NotNil(t, resp.Error)
			assert.Equal(t, "INVALID_REQUEST", resp.Error.Code)
		})
	}
}

func TestPerformTCPConnect_ConnectionRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	req := TCPConnectRequest{
		Host:    "127.0.0.1",
		Port:    59999, // Unlikely to have a service here
		Timeout: 1000,
	}

	resp := PerformTCPConnect(context.Background(), req)

	assert.False(t, resp.Connected)
	require.NotNil(t, resp.Error)
	// Error code depends on whether port is closed or firewalled
	assert.Contains(t, []string{"CONNECTION_REFUSED", "TIMEOUT", "CONNECTION_FAILED"}, resp.Error.Code)
}

func TestTCPConnectRequest_Fields(t *testing.T) {
	req := TCPConnectRequest{
		Host:    "test.example.com",
		Port:    443,
		Timeout: 10000,
	}

	assert.Equal(t, "test.example.com", req.Host)
	assert.Equal(t, 443, req.Port)
	assert.Equal(t, 10000, req.Timeout)
}

func TestTCPError_Error(t *testing.T) {
	err := &TCPError{
		Code:    "TEST_CODE",
		Message: "test error message",
	}

	assert.Equal(t, "test error message", err.Error())
}

func TestDefaultTCPConfig(t *testing.T) {
	cfg := defaultTCPConfig()

	assert.Equal(t, 5*time.Second, cfg.timeout)
}

func TestWithTCPTimeout(t *testing.T) {
	cfg := defaultTCPConfig()
	opt := WithTCPTimeout(10 * time.Second)
	opt(&cfg)

	assert.Equal(t, 10*time.Second, cfg.timeout)
}

func TestWithTCPTimeout_IgnoresInvalid(t *testing.T) {
	cfg := defaultTCPConfig()
	opt := WithTCPTimeout(-1 * time.Second)
	opt(&cfg)

	assert.Equal(t, 5*time.Second, cfg.timeout, "should keep default for negative duration")
}

func TestPerformTCPConnect_TLS_Success(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	// Connect to example.com:443 (HTTPS)
	// This is a reliable external host for testing TLS
	req := TCPConnectRequest{
		Host:    "example.com",
		Port:    443,
		Timeout: 5000,
		UseTLS:  true,
	}

	resp := PerformTCPConnect(context.Background(), req)

	if !resp.Connected {
		t.Logf("TLS connection failed: %v", resp.Error)
	}
	require.True(t, resp.Connected, "should connect to example.com:443 with TLS")
	assert.NotEmpty(t, resp.RemoteAddr)
	assert.Nil(t, resp.Error)

	// Verify TLS fields
	assert.NotEmpty(t, resp.TLSVersion, "should have TLS version")
	assert.NotEmpty(t, resp.TLSCipherSuite, "should have cipher suite")
	assert.NotEmpty(t, resp.TLSCertSubject, "should have cert subject")
	assert.NotEmpty(t, resp.TLSCertIssuer, "should have cert issuer")
}

func TestPerformTCPConnect_TLS_HandshakeFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	// Connect to an HTTP port (80) with TLS, which should fail the handshake
	req := TCPConnectRequest{
		Host:    "example.com",
		Port:    80,
		Timeout: 5000,
		UseTLS:  true,
	}

	resp := PerformTCPConnect(context.Background(), req)

	assert.False(t, resp.Connected, "should not connect successfully with TLS to non-TLS port")
	require.NotNil(t, resp.Error)
	// The error might be "oversized record received with length..." or similar TLS error
	// mapped to TLS_ERROR or CONNECTION_FAILED depending on implementation details
	t.Logf("Got expected error: %s", resp.Error.Code)
}

func TestPerformTCPConnect_SSRFProtection_BlocksPrivateIP(t *testing.T) {
	resp := PerformTCPConnect(context.Background(),
		TCPConnectRequest{Host: "127.0.0.1", Port: 80},
		WithTCPSSRFProtection(false),
	)
	require.False(t, resp.Connected)
	require.NotNil(t, resp.Error)
	assert.Equal(t, "SSRF_BLOCKED", resp.Error.Code)
}

func TestPerformTCPConnect_SSRFProtection_AllowPrivateWhenEnabled(t *testing.T) {
	// This test would need a local server to connect to, or we can just expect a different error than SSRF_BLOCKED
	// Since we don't have a server listening on 127.0.0.1:80 (necessarily), we expect CONNECTION_REFUSED or similar.
	// The key is that it shouldn't be SSRF_BLOCKED.

	resp := PerformTCPConnect(context.Background(),
		TCPConnectRequest{Host: "127.0.0.1", Port: 80},
		WithTCPSSRFProtection(true), // allowPrivate=true
	)
	// Should attempt connection (may fail if nothing listening, but not SSRF_BLOCKED)
	if resp.Error != nil {
		assert.NotEqual(t, "SSRF_BLOCKED", resp.Error.Code, "Should not be blocked by SSRF when allowed")
	}
}
