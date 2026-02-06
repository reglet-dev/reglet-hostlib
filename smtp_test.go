package hostlib

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerformSMTPConnect_InvalidHost(t *testing.T) {
	req := SMTPConnectRequest{
		Host: "",
		Port: 25,
	}

	resp := PerformSMTPConnect(context.Background(), req)

	require.NotNil(t, resp.Error)
	assert.Equal(t, "INVALID_REQUEST", resp.Error.Code)
	assert.False(t, resp.Connected)
}

func TestPerformSMTPConnect_InvalidPort(t *testing.T) {
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
			req := SMTPConnectRequest{
				Host: "smtp.example.com",
				Port: tc.port,
			}

			resp := PerformSMTPConnect(context.Background(), req)

			require.NotNil(t, resp.Error)
			assert.Equal(t, "INVALID_REQUEST", resp.Error.Code)
		})
	}
}

func TestSMTPConnectRequest_Fields(t *testing.T) {
	req := SMTPConnectRequest{
		Host:        "smtp.example.com",
		Port:        587,
		UseTLS:      false,
		UseSTARTTLS: true,
		Timeout:     10000,
	}

	assert.Equal(t, "smtp.example.com", req.Host)
	assert.Equal(t, 587, req.Port)
	assert.False(t, req.UseTLS)
	assert.True(t, req.UseSTARTTLS)
	assert.Equal(t, 10000, req.Timeout)
}

func TestSMTPConnectResponse_Fields(t *testing.T) {
	resp := SMTPConnectResponse{
		Connected:  true,
		Banner:     "220 smtp.example.com ESMTP",
		TLSVersion: "TLS 1.3",
		LatencyMs:  50,
	}

	assert.True(t, resp.Connected)
	assert.Equal(t, "220 smtp.example.com ESMTP", resp.Banner)
	assert.Equal(t, "TLS 1.3", resp.TLSVersion)
	assert.Equal(t, int64(50), resp.LatencyMs)
}

func TestSMTPError_Error(t *testing.T) {
	err := &SMTPError{
		Code:    "CONNECTION_REFUSED",
		Message: "connection refused",
	}

	assert.Equal(t, "connection refused", err.Error())
}

func TestDefaultSMTPConfig(t *testing.T) {
	cfg := defaultSMTPConfig()

	assert.Equal(t, 30*time.Second, cfg.timeout)
	assert.Nil(t, cfg.tlsConfig)
}

func TestSMTPOptions(t *testing.T) {
	cfg := defaultSMTPConfig()

	WithSMTPTimeout(60 * time.Second)(&cfg)
	assert.Equal(t, 60*time.Second, cfg.timeout)
}

func TestSMTPOptions_IgnoresInvalid(t *testing.T) {
	cfg := defaultSMTPConfig()

	WithSMTPTimeout(-1 * time.Second)(&cfg)
	assert.Equal(t, 30*time.Second, cfg.timeout, "should keep default for negative timeout")
}

func TestTLSVersionString(t *testing.T) {
	assert.Equal(t, "TLS 1.0", tlsVersionString(0x0301))
	assert.Equal(t, "TLS 1.1", tlsVersionString(0x0302))
	assert.Equal(t, "TLS 1.2", tlsVersionString(0x0303))
	assert.Equal(t, "TLS 1.3", tlsVersionString(0x0304))
	assert.Equal(t, "", tlsVersionString(0))
}

func TestClassifySMTPError(t *testing.T) {
	tests := []struct {
		message      string
		expectedCode string
	}{
		{"connection timeout", "TIMEOUT"},
		{"connection refused", "CONNECTION_REFUSED"},
		{"no such host", "HOST_NOT_FOUND"},
		{"certificate error", "TLS_CERTIFICATE_ERROR"},
		{"some other error", "CONNECTION_FAILED"},
	}

	for _, tc := range tests {
		t.Run(tc.message, func(t *testing.T) {
			// Using a custom error for testing
			customErr := &testError{message: tc.message}
			result := classifySMTPError(customErr)
			assert.Equal(t, tc.expectedCode, result.Code)
		})
	}
}

type testError struct {
	message string
}

func (e *testError) Error() string {
	return e.message
}

func TestPerformSMTPConnect_SSRFProtection_BlocksPrivateIP(t *testing.T) {
	resp := PerformSMTPConnect(context.Background(),
		SMTPConnectRequest{Host: "127.0.0.1", Port: 25},
		WithSMTPSSRFProtection(false),
	)
	require.False(t, resp.Connected)
	require.NotNil(t, resp.Error)
	assert.Equal(t, "SSRF_BLOCKED", resp.Error.Code)
}

func TestPerformSMTPConnect_SSRFProtection_AllowPrivateWhenEnabled(t *testing.T) {
	resp := PerformSMTPConnect(context.Background(),
		SMTPConnectRequest{Host: "127.0.0.1", Port: 25},
		WithSMTPSSRFProtection(true),
	)
	// Should attempt connection (may fail, but not SSRF_BLOCKED)
	if resp.Error != nil {
		assert.NotEqual(t, "SSRF_BLOCKED", resp.Error.Code)
	}
}
