package extractor_test

import (
	"testing"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-host-sdk/capability"
	"github.com/reglet-dev/reglet-host-sdk/extractor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetworkExtractor_Extract(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]interface{}
		expected *hostfunc.GrantSet
	}{
		{
			name: "HTTPS URL extracts host and port 443",
			config: map[string]interface{}{
				"url": "https://example.com/path",
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"example.com"}, Ports: []string{"443"}},
					},
				},
			},
		},
		{
			name: "HTTP URL extracts host and port 80",
			config: map[string]interface{}{
				"url": "http://api.github.com/users",
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"api.github.com"}, Ports: []string{"80"}},
					},
				},
			},
		},
		{
			name: "TCP with host and integer port",
			config: map[string]interface{}{
				"host": "example.com",
				"port": 22,
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"example.com"}, Ports: []string{"22"}},
					},
				},
			},
		},
		{
			name: "TCP with IP and port",
			config: map[string]interface{}{
				"host": "192.168.1.1",
				"port": 3306,
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"192.168.1.1"}, Ports: []string{"3306"}},
					},
				},
			},
		},
		{
			name: "TCP with port only (no host) uses wildcard",
			config: map[string]interface{}{
				"port": 22,
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"*"}, Ports: []string{"22"}},
					},
				},
			},
		},
		{
			name: "TCP with string port uses wildcard host",
			config: map[string]interface{}{
				"port": "8080",
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"*"}, Ports: []string{"8080"}},
					},
				},
			},
		},
		{
			name: "TCP with float64 port uses wildcard host",
			config: map[string]interface{}{
				"port": 3306.0,
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"*"}, Ports: []string{"3306"}},
					},
				},
			},
		},
		{
			name: "TCP with uint64 port and host",
			config: map[string]interface{}{
				"host": "example.com",
				"port": uint64(443),
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"example.com"}, Ports: []string{"443"}},
					},
				},
			},
		},
		{
			name: "DNS with custom nameserver",
			config: map[string]interface{}{
				"hostname":   "example.com",
				"nameserver": "8.8.8.8",
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"8.8.8.8"}, Ports: []string{"53"}},
					},
				},
			},
		},
		{
			name: "DNS without nameserver returns nil",
			config: map[string]interface{}{
				"hostname":    "example.com",
				"record_type": "A",
			},
			expected: nil,
		},
		{
			name: "Invalid URL falls back to wildcard",
			config: map[string]interface{}{
				"url": "not-a-valid-url",
			},
			expected: nil,
		},
		{
			name: "URL with unknown scheme uses both ports",
			config: map[string]interface{}{
				"url": "ftp://example.com/file",
			},
			expected: &hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"example.com"}, Ports: []string{"*"}},
					},
				},
			},
		},
		{
			name:     "Empty config returns nil",
			config:   map[string]interface{}{},
			expected: nil,
		},
		{
			name: "Empty URL returns nil",
			config: map[string]interface{}{
				"url": "",
			},
			expected: nil,
		},
	}

	ext := &extractor.NetworkExtractor{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ext.Extract(tt.config)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestFileExtractor_Extract(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]interface{}
		expected *hostfunc.GrantSet
	}{
		{
			name: "Valid path extracts read capability",
			config: map[string]interface{}{
				"path": "/etc/passwd",
			},
			expected: &hostfunc.GrantSet{
				FS: &hostfunc.FileSystemCapability{
					Rules: []hostfunc.FileSystemRule{
						{Read: []string{"/etc/passwd"}},
					},
				},
			},
		},
		{
			name: "Empty path returns nil",
			config: map[string]interface{}{
				"path": "",
			},
			expected: nil,
		},
		{
			name:     "Missing path returns nil",
			config:   map[string]interface{}{},
			expected: nil,
		},
	}

	ext := &extractor.FileExtractor{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ext.Extract(tt.config)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestCommandExtractor_Extract(t *testing.T) {
	tests := []struct {
		name     string
		config   map[string]interface{}
		expected *hostfunc.GrantSet
	}{
		{
			name: "Valid command extracts exec capability",
			config: map[string]interface{}{
				"command": "/bin/sh",
			},
			expected: &hostfunc.GrantSet{
				Exec: &hostfunc.ExecCapability{
					Commands: []string{"/bin/sh"},
				},
			},
		},
		{
			name: "cmd alias extracts exec capability",
			config: map[string]interface{}{
				"cmd": "/usr/bin/python",
			},
			expected: &hostfunc.GrantSet{
				Exec: &hostfunc.ExecCapability{
					Commands: []string{"/usr/bin/python"},
				},
			},
		},
		{
			name: "Empty command returns nil",
			config: map[string]interface{}{
				"command": "",
			},
			expected: nil,
		},
		{
			name:     "Missing command returns nil",
			config:   map[string]interface{}{},
			expected: nil,
		},
	}

	ext := &extractor.CommandExtractor{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ext.Extract(tt.config)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestRegisterDefaultExtractors(t *testing.T) {
	registry := capability.NewRegistry()
	extractor.RegisterDefaultExtractors(registry)

	// Verify all expected extractors are registered
	expectedPlugins := []string{"file", "file.managed", "command", "http", "tcp", "dns", "smtp"}
	for _, name := range expectedPlugins {
		ext, ok := registry.Get(name)
		require.True(t, ok, "extractor for %q should be registered", name)
		require.NotNil(t, ext, "extractor for %q should not be nil", name)
	}

	// Verify network extractors share the same instance
	httpExt, _ := registry.Get("http")
	tcpExt, _ := registry.Get("tcp")
	assert.Same(t, httpExt, tcpExt, "http and tcp should share the same NetworkExtractor")
}
