package policy_test

import (
	"testing"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-hostlib/policy"
)

func BenchmarkCheckNetwork(b *testing.B) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		Network: &hostfunc.NetworkCapability{
			Rules: []hostfunc.NetworkRule{
				{Hosts: []string{"example.com", "*.internal"}, Ports: []string{"80", "443"}},
			},
		},
	}
	req := hostfunc.NetworkRequest{Host: "example.com", Port: 80}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.CheckNetwork(req, grants)
	}
}

func BenchmarkCheckFileSystem(b *testing.B) {
	p := policy.NewPolicy(
		policy.WithDenialHandler(&policy.NopDenialHandler{}),
		policy.WithSymlinkResolution(false),
	)
	grants := &hostfunc.GrantSet{
		FS: &hostfunc.FileSystemCapability{
			Rules: []hostfunc.FileSystemRule{
				{Read: []string{"/data/**", "/etc/hosts"}},
			},
		},
	}
	req := hostfunc.FileSystemRequest{Path: "/data/foo/bar", Operation: "read"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.CheckFileSystem(req, grants)
	}
}

func BenchmarkCheckEnvironment(b *testing.B) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		Env: &hostfunc.EnvironmentCapability{
			Variables: []string{"APP_*"},
		},
	}
	req := hostfunc.EnvironmentRequest{Variable: "APP_DEBUG"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.CheckEnvironment(req, grants)
	}
}

func BenchmarkCheckExec(b *testing.B) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		Exec: &hostfunc.ExecCapability{
			Commands: []string{"/usr/bin/*", "/opt/tools/**"},
		},
	}
	req := hostfunc.ExecCapabilityRequest{Command: "/usr/bin/ls"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.CheckExec(req, grants)
	}
}

func BenchmarkCheckKeyValue(b *testing.B) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		KV: &hostfunc.KeyValueCapability{
			Rules: []hostfunc.KeyValueRule{
				{Keys: []string{"config/*", "cache/**"}, Operation: "read-write"},
			},
		},
	}
	req := hostfunc.KeyValueRequest{Key: "config/database", Operation: "read"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.CheckKeyValue(req, grants)
	}
}
