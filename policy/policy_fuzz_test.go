package policy_test

import (
	"testing"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-host-sdk/policy"
)

func FuzzMatchHost(f *testing.F) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		Network: &hostfunc.NetworkCapability{
			Rules: []hostfunc.NetworkRule{
				{Hosts: []string{"example.com", "*.internal"}, Ports: []string{"80"}},
			},
		},
	}
	f.Add("example.com")
	f.Add("api.internal")
	f.Add("evil.com")

	f.Fuzz(func(t *testing.T, host string) {
		req := hostfunc.NetworkRequest{Host: host, Port: 80}
		// We just ensure it doesn't panic
		p.CheckNetwork(req, grants)
	})
}

func FuzzMatchPath(f *testing.F) {
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
	f.Add("/data/file.txt")
	f.Add("/etc/hosts")
	f.Add("/etc/passwd")

	f.Fuzz(func(t *testing.T, path string) {
		req := hostfunc.FileSystemRequest{Path: path, Operation: "read"}
		p.CheckFileSystem(req, grants)
	})
}

func FuzzMatchPort(f *testing.F) {
	p := policy.NewPolicy(policy.WithDenialHandler(&policy.NopDenialHandler{}))
	grants := &hostfunc.GrantSet{
		Network: &hostfunc.NetworkCapability{
			Rules: []hostfunc.NetworkRule{
				{Hosts: []string{"*"}, Ports: []string{"80", "8000-8010"}},
			},
		},
	}
	f.Add(80)
	f.Add(8005)
	f.Add(443)

	f.Fuzz(func(t *testing.T, port int) {
		req := hostfunc.NetworkRequest{Host: "example.com", Port: port}
		p.CheckNetwork(req, grants)
	})
}
