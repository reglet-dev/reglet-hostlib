package policy_test

import (
	"testing"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-hostlib/policy"
	"github.com/stretchr/testify/assert"
)

func TestPolicy_CheckNetwork(t *testing.T) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))

	grants := &hostfunc.GrantSet{
		Network: &hostfunc.NetworkCapability{
			Rules: []hostfunc.NetworkRule{
				{Hosts: []string{"example.com", "*.internal"}, Ports: []string{"80", "443", "8000-8010", "*"}},
			},
		},
	}

	tests := []struct {
		name string
		req  hostfunc.NetworkRequest
		want bool
	}{
		{"Allowed host and port", hostfunc.NetworkRequest{Host: "example.com", Port: 80}, true},
		{"Allowed wildcard host", hostfunc.NetworkRequest{Host: "svc.internal", Port: 443}, true},
		{"Allowed range port", hostfunc.NetworkRequest{Host: "example.com", Port: 8005}, true},
		{"Allowed wildcard port", hostfunc.NetworkRequest{Host: "example.com", Port: 9999}, true},
		{"Denied host", hostfunc.NetworkRequest{Host: "google.com", Port: 80}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, p.CheckNetwork(tt.req, grants))
		})
	}
}

func TestPolicy_CheckNetwork_SpecificPorts(t *testing.T) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		Network: &hostfunc.NetworkCapability{
			Rules: []hostfunc.NetworkRule{
				{Hosts: []string{"example.com"}, Ports: []string{"80", "8000-8010"}},
			},
		},
	}

	assert.True(t, p.CheckNetwork(hostfunc.NetworkRequest{Host: "example.com", Port: 80}, grants))
	assert.True(t, p.CheckNetwork(hostfunc.NetworkRequest{Host: "example.com", Port: 8005}, grants))
	assert.False(t, p.CheckNetwork(hostfunc.NetworkRequest{Host: "example.com", Port: 443}, grants))
	assert.False(t, p.CheckNetwork(hostfunc.NetworkRequest{Host: "example.com", Port: 8011}, grants))
}

func TestPolicy_CheckNetwork_MultipleRules(t *testing.T) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	// Test that multiple rules work correctly - each rule is independent
	grants := &hostfunc.GrantSet{
		Network: &hostfunc.NetworkCapability{
			Rules: []hostfunc.NetworkRule{
				{Hosts: []string{"api.internal"}, Ports: []string{"80"}},
				{Hosts: []string{"*.external.com"}, Ports: []string{"443"}},
			},
		},
	}

	// Should match first rule
	assert.True(t, p.CheckNetwork(hostfunc.NetworkRequest{Host: "api.internal", Port: 80}, grants))
	// Should match second rule
	assert.True(t, p.CheckNetwork(hostfunc.NetworkRequest{Host: "www.external.com", Port: 443}, grants))
	// Should NOT match (port 443 on api.internal not in any rule)
	assert.False(t, p.CheckNetwork(hostfunc.NetworkRequest{Host: "api.internal", Port: 443}, grants))
	// Should NOT match (port 80 on external.com not in any rule)
	assert.False(t, p.CheckNetwork(hostfunc.NetworkRequest{Host: "www.external.com", Port: 80}, grants))
}

func TestPolicy_CheckFileSystem(t *testing.T) {
	p := policy.NewPolicy(
		policy.WithDenialHandler(&policy.NopDenialHandler{}),
		policy.WithSymlinkResolution(false), // Disable for deterministic tests
	)

	grants := &hostfunc.GrantSet{
		FS: &hostfunc.FileSystemCapability{
			Rules: []hostfunc.FileSystemRule{
				{Read: []string{"/data/**", "/etc/hosts"}, Write: []string{"/tmp/*"}},
			},
		},
	}

	tests := []struct {
		name string
		req  hostfunc.FileSystemRequest
		want bool
	}{
		{"Allowed read exact", hostfunc.FileSystemRequest{Path: "/etc/hosts", Operation: "read"}, true},
		{"Allowed read glob", hostfunc.FileSystemRequest{Path: "/data/foo/bar", Operation: "read"}, true},
		{"Allowed write glob", hostfunc.FileSystemRequest{Path: "/tmp/foo", Operation: "write"}, true},
		{"Denied read", hostfunc.FileSystemRequest{Path: "/etc/passwd", Operation: "read"}, false},
		{"Denied write", hostfunc.FileSystemRequest{Path: "/data/foo", Operation: "write"}, false},
		{"Denied write outside glob", hostfunc.FileSystemRequest{Path: "/tmp/foo/bar", Operation: "write"}, false},
		{"Cleaned path match", hostfunc.FileSystemRequest{Path: "/data/../data/foo/bar", Operation: "read"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, p.CheckFileSystem(tt.req, grants))
		})
	}
}

func TestPolicy_CheckFileSystem_RelativePath(t *testing.T) {
	// Test that relative paths are denied without cwd
	p := policy.NewPolicy(
		policy.WithDenialHandler(&policy.NopDenialHandler{}),
		policy.WithSymlinkResolution(false),
	)
	grants := &hostfunc.GrantSet{
		FS: &hostfunc.FileSystemCapability{
			Rules: []hostfunc.FileSystemRule{
				{Read: []string{"/app/**"}},
			},
		},
	}

	// Relative path without cwd should be denied
	assert.False(t, p.CheckFileSystem(hostfunc.FileSystemRequest{Path: "data/file.txt", Operation: "read"}, grants))

	// With cwd set, relative path should work
	pWithCwd := policy.NewPolicy(
		policy.WithDenialHandler(&policy.NopDenialHandler{}),
		policy.WithWorkingDirectory("/app"),
		policy.WithSymlinkResolution(false),
	)
	assert.True(t, pWithCwd.CheckFileSystem(hostfunc.FileSystemRequest{Path: "data/file.txt", Operation: "read"}, grants))
}

func TestPolicy_CheckEnvironment(t *testing.T) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		Env: &hostfunc.EnvironmentCapability{
			Variables: []string{"APP_*", "DEBUG"},
		},
	}

	assert.True(t, p.CheckEnvironment(hostfunc.EnvironmentRequest{Variable: "DEBUG"}, grants))
	assert.True(t, p.CheckEnvironment(hostfunc.EnvironmentRequest{Variable: "APP_ENV"}, grants))
	assert.False(t, p.CheckEnvironment(hostfunc.EnvironmentRequest{Variable: "PATH"}, grants))
}

func TestPolicy_CheckExec(t *testing.T) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		Exec: &hostfunc.ExecCapability{
			Commands: []string{"/usr/bin/*"},
		},
	}

	assert.True(t, p.CheckExec(hostfunc.ExecCapabilityRequest{Command: "/usr/bin/ls"}, grants))
	assert.False(t, p.CheckExec(hostfunc.ExecCapabilityRequest{Command: "/bin/sh"}, grants))
}

func TestPolicy_CheckKeyValue(t *testing.T) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		KV: &hostfunc.KeyValueCapability{
			Rules: []hostfunc.KeyValueRule{
				{Keys: []string{"config/*"}, Operation: "read"},
			},
		},
	}

	assert.True(t, p.CheckKeyValue(hostfunc.KeyValueRequest{Key: "config/db", Operation: "read"}, grants))
	assert.False(t, p.CheckKeyValue(hostfunc.KeyValueRequest{Key: "config/db", Operation: "write"}, grants))
	assert.False(t, p.CheckKeyValue(hostfunc.KeyValueRequest{Key: "secret", Operation: "read"}, grants))
}

func TestPolicy_CheckKeyValue_MultipleRules(t *testing.T) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		KV: &hostfunc.KeyValueCapability{
			Rules: []hostfunc.KeyValueRule{
				{Keys: []string{"config/*"}, Operation: "read"},
				{Keys: []string{"cache/*"}, Operation: "read-write"},
			},
		},
	}

	// config/* is read-only
	assert.True(t, p.CheckKeyValue(hostfunc.KeyValueRequest{Key: "config/db", Operation: "read"}, grants))
	assert.False(t, p.CheckKeyValue(hostfunc.KeyValueRequest{Key: "config/db", Operation: "write"}, grants))

	// cache/* is read-write
	assert.True(t, p.CheckKeyValue(hostfunc.KeyValueRequest{Key: "cache/session", Operation: "read"}, grants))
	assert.True(t, p.CheckKeyValue(hostfunc.KeyValueRequest{Key: "cache/session", Operation: "write"}, grants))
}
