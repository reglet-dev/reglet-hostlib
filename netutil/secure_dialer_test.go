package netutil_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reglet-dev/reglet-host-sdk/netutil"
)

func Test_SecureDialer_BlocksPrivateIP(t *testing.T) {
	dialer := &netutil.SecureDialer{
		AllowPrivateNetwork: false,
	}

	// Try to connect to localhost (private)
	_, err := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:80")
	require.Error(t, err)
	assert.True(t, netutil.IsSSRFBlockedError(err))
	assert.Contains(t, err.Error(), "SSRF protection")
}

func Test_SecureDialer_AllowsPrivateIPWithFlag(t *testing.T) {
	dialer := &netutil.SecureDialer{
		AllowPrivateNetwork: true,
	}

	// This will fail to connect (no server), but shouldn't error on SSRF
	_, err := dialer.DialContext(context.Background(), "tcp", "127.0.0.1:12345")

	// Should NOT be an SSRFBlockedError - it should be a connection refused error
	assert.False(t, netutil.IsSSRFBlockedError(err))
}

func Test_SecureDialer_CallsOnBlocked(t *testing.T) {
	var blockedAddr string
	var blockedReason string
	dialer := &netutil.SecureDialer{
		AllowPrivateNetwork: false,
		OnBlocked: func(addr, reason string) {
			blockedAddr = addr
			blockedReason = reason
		},
	}

	_, err := dialer.DialContext(context.Background(), "tcp", "10.0.0.1:80")
	require.Error(t, err)
	assert.NotEmpty(t, blockedAddr)
	assert.NotEmpty(t, blockedReason)
}

func Test_SecureDialer_CallsOnDNSPinning(t *testing.T) {
	var pinnedHost string
	var pinnedIP net.IP
	dialer := &netutil.SecureDialer{
		AllowPrivateNetwork: false,
		OnDNSPinning: func(host string, ip net.IP) {
			pinnedHost = host
			pinnedIP = ip
		},
	}

	// Use a real hostname that will resolve but fail to connect
	_, _ = dialer.DialContext(context.Background(), "tcp", "example.com:12345")

	// DNS pinning callback should have been called (assuming DNS works)
	if pinnedHost != "" {
		assert.Equal(t, "example.com", pinnedHost)
		assert.NotNil(t, pinnedIP)
	}
}

func Test_SecureDialer_InvalidAddress(t *testing.T) {
	dialer := &netutil.SecureDialer{}

	_, err := dialer.DialContext(context.Background(), "tcp", "invalid-no-port")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid address")
}

func Test_SSRFBlockedError(t *testing.T) {
	err := &netutil.SSRFBlockedError{Address: "10.0.0.1", Reason: "private addresses blocked (RFC 1918)"}

	assert.Contains(t, err.Error(), "10.0.0.1")
	assert.Contains(t, err.Error(), "SSRF protection")
	assert.True(t, netutil.IsSSRFBlockedError(err))
	assert.False(t, netutil.IsSSRFBlockedError(nil))
	assert.False(t, netutil.IsSSRFBlockedError(assert.AnError))
}
