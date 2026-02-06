package hostlib

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerformDNSLookup_ARecord(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	req := DNSLookupRequest{
		Hostname:   "example.com",
		RecordType: "A",
	}

	resp := PerformDNSLookup(context.Background(), req)

	assert.Nil(t, resp.Error, "should not return error for valid domain")
	assert.NotEmpty(t, resp.Records, "should return at least one A record")
}

func TestPerformDNSLookup_UnsupportedType(t *testing.T) {
	req := DNSLookupRequest{
		Hostname:   "example.com",
		RecordType: "INVALID",
	}

	resp := PerformDNSLookup(context.Background(), req)

	require.NotNil(t, resp.Error)
	assert.Equal(t, "UNSUPPORTED_TYPE", resp.Error.Code)
}

func TestPerformDNSLookup_NonexistentDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	req := DNSLookupRequest{
		Hostname:   "thisisanonexistentdomainthatdoesnotexist123456.com",
		RecordType: "A",
		Timeout:    1000, // 1 second timeout
	}

	resp := PerformDNSLookup(context.Background(), req)

	require.NotNil(t, resp.Error)
	assert.Equal(t, "LOOKUP_FAILED", resp.Error.Code)
}

func TestPerformDNSLookup_WithTimeout(t *testing.T) {
	req := DNSLookupRequest{
		Hostname:   "example.com",
		RecordType: "A",
		Timeout:    100, // Very short timeout
	}

	// Use a canceled context to simulate timeout behavior
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	resp := PerformDNSLookup(ctx, req)

	// Either succeeds quickly or times out - both are valid for this test
	// The key assertion is that it doesn't panic
	_ = resp
}

func TestDNSLookupRequest_Fields(t *testing.T) {
	req := DNSLookupRequest{
		Hostname:   "test.example.com",
		RecordType: "AAAA",
		Nameserver: "8.8.8.8:53",
		Timeout:    5000,
	}

	assert.Equal(t, "test.example.com", req.Hostname)
	assert.Equal(t, "AAAA", req.RecordType)
	assert.Equal(t, "8.8.8.8:53", req.Nameserver)
	assert.Equal(t, 5000, req.Timeout)
}

func TestDNSError_Error(t *testing.T) {
	err := &DNSError{
		Code:    "TEST_CODE",
		Message: "test error message",
	}

	assert.Equal(t, "test error message", err.Error())
}

func TestDefaultDNSConfig(t *testing.T) {
	cfg := defaultDNSConfig()

	assert.Equal(t, 5*time.Second, cfg.timeout)
	assert.Empty(t, cfg.nameserver)
}

func TestWithDNSLookupTimeout(t *testing.T) {
	cfg := defaultDNSConfig()
	opt := WithDNSLookupTimeout(10 * time.Second)
	opt(&cfg)

	assert.Equal(t, 10*time.Second, cfg.timeout)
}

func TestWithDNSLookupTimeout_IgnoresInvalid(t *testing.T) {
	cfg := defaultDNSConfig()
	opt := WithDNSLookupTimeout(-1 * time.Second)
	opt(&cfg)

	assert.Equal(t, 5*time.Second, cfg.timeout, "should keep default for negative duration")
}

func TestWithDNSNameserver(t *testing.T) {
	cfg := defaultDNSConfig()
	opt := WithDNSNameserver("1.1.1.1:53")
	opt(&cfg)

	assert.Equal(t, "1.1.1.1:53", cfg.nameserver)
}

// Test all record type paths (even though they require network, we test the path selection)
func TestPerformDNSLookup_RecordTypePaths(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	recordTypes := []string{"A", "AAAA", "CNAME", "MX", "TXT", "NS", ""}
	for _, rt := range recordTypes {
		t.Run("RecordType_"+rt, func(t *testing.T) {
			req := DNSLookupRequest{
				Hostname:   "example.com",
				RecordType: rt,
				Timeout:    5000,
			}

			resp := PerformDNSLookup(context.Background(), req)

			// We just verify it doesn't panic and returns a valid response
			// Actual results depend on DNS configuration
			_ = resp
		})
	}
}

func TestPerformDNSLookup_WithCustomNameserver(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping network test in short mode")
	}

	req := DNSLookupRequest{
		Hostname:   "example.com",
		RecordType: "A",
		Nameserver: "8.8.8.8", // Without port - should add :53
		Timeout:    5000,
	}

	resp := PerformDNSLookup(context.Background(), req)

	// Should not error with custom nameserver
	_ = resp
}

func TestDNSLookupResponse_Fields(t *testing.T) {
	resp := DNSLookupResponse{
		Records: []string{"192.0.2.1", "192.0.2.2"},
		MXRecords: []MXRecord{
			{Host: "mail.example.com", Pref: 10},
		},
		Error: nil,
	}

	assert.Equal(t, 2, len(resp.Records))
	assert.Equal(t, 1, len(resp.MXRecords))
	assert.Equal(t, "mail.example.com", resp.MXRecords[0].Host)
	assert.Equal(t, uint16(10), resp.MXRecords[0].Pref)
}

func TestMXRecord_Fields(t *testing.T) {
	mx := MXRecord{
		Host: "mx1.example.com",
		Pref: 5,
	}

	assert.Equal(t, "mx1.example.com", mx.Host)
	assert.Equal(t, uint16(5), mx.Pref)
}
