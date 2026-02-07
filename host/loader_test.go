package host_test

import (
	"testing"

	"github.com/reglet-dev/reglet-host-sdk/host"
	"github.com/reglet-dev/reglet-host-sdk/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// LoaderIntegrationSuite tests the Loader with full integration.
type LoaderIntegrationSuite struct {
	suite.Suite
	registry *registry.Registry
	loader   *host.Loader
}

func (s *LoaderIntegrationSuite) SetupTest() {
	// Create and configure registry
	reg := registry.NewRegistry(registry.WithStrictMode(false))
	err := reg.Register("network", map[string]any{"type": "object"})
	s.Require().NoError(err)
	err = reg.Register("fs", map[string]any{"type": "object"})
	s.Require().NoError(err)
	err = reg.Register("env", map[string]any{"type": "object"})
	s.Require().NoError(err)
	err = reg.Register("exec", map[string]any{"type": "object"})
	s.Require().NoError(err)
	err = reg.Register("kv", map[string]any{"type": "object"})
	s.Require().NoError(err)

	s.registry = reg.(*registry.Registry)
	s.loader = host.NewLoader(host.WithRegistry(reg))
}

func (s *LoaderIntegrationSuite) TestValidManifest() {
	yaml := `
name: "test-plugin"
version: "1.0.0"
capabilities:
  network:
    rules:
      - hosts: ["example.com"]
        ports: ["80"]
  fs:
    rules:
      - read: ["/data/**"]
`
	manifest, err := s.loader.LoadManifest([]byte(yaml), nil)
	s.Require().NoError(err)
	s.Equal("test-plugin", manifest.Name)

	// Check GrantSet structure
	s.NotNil(manifest.Capabilities.Network)
	s.Len(manifest.Capabilities.Network.Rules, 1)
	s.Equal([]string{"example.com"}, manifest.Capabilities.Network.Rules[0].Hosts)
	s.Equal([]string{"80"}, manifest.Capabilities.Network.Rules[0].Ports)

	s.NotNil(manifest.Capabilities.FS)
	s.Len(manifest.Capabilities.FS.Rules, 1)
	s.Equal([]string{"/data/**"}, manifest.Capabilities.FS.Rules[0].Read)
}

func (s *LoaderIntegrationSuite) TestManifestWithMultipleRules() {
	yaml := `
name: "multi-rule-plugin"
version: "1.0.0"
capabilities:
  network:
    rules:
      - hosts: ["api.internal"]
        ports: ["80"]
      - hosts: ["*.external.com"]
        ports: ["443"]
  kv:
    rules:
      - op: read
        keys: ["config/*"]
      - op: read-write
        keys: ["cache/*"]
`
	manifest, err := s.loader.LoadManifest([]byte(yaml), nil)
	s.Require().NoError(err)

	// Check network rules
	s.NotNil(manifest.Capabilities.Network)
	s.Len(manifest.Capabilities.Network.Rules, 2)
	s.Equal([]string{"api.internal"}, manifest.Capabilities.Network.Rules[0].Hosts)
	s.Equal([]string{"80"}, manifest.Capabilities.Network.Rules[0].Ports)
	s.Equal([]string{"*.external.com"}, manifest.Capabilities.Network.Rules[1].Hosts)
	s.Equal([]string{"443"}, manifest.Capabilities.Network.Rules[1].Ports)

	// Check KV rules
	s.NotNil(manifest.Capabilities.KV)
	s.Len(manifest.Capabilities.KV.Rules, 2)
}

func (s *LoaderIntegrationSuite) TestInvalidYAML() {
	yaml := `
name: "test-plugin"
version: "1.0.0"
capabilities:
  network: "should be an object"
`
	_, err := s.loader.LoadManifest([]byte(yaml), nil)
	s.Require().Error(err)
}

func (s *LoaderIntegrationSuite) TestMissingSchemaRegistration() {
	// Create loader with empty registry
	emptyReg := registry.NewRegistry()
	loaderEmpty := host.NewLoader(host.WithRegistry(emptyReg))

	yaml := `
name: "test-plugin"
version: "1.0.0"
capabilities:
  network:
    rules:
      - hosts: ["example.com"]
        ports: ["443"]
`
	_, err := loaderEmpty.LoadManifest([]byte(yaml), nil)
	s.Require().Error(err)
	s.Contains(err.Error(), "no schema registered for capability kind: network")
}

func (s *LoaderIntegrationSuite) TestEnvCapability() {
	yaml := `
name: "env-plugin"
version: "1.0.0"
capabilities:
  env:
    vars: ["APP_*", "DEBUG"]
`
	manifest, err := s.loader.LoadManifest([]byte(yaml), nil)
	s.Require().NoError(err)
	s.NotNil(manifest.Capabilities.Env)
	s.Equal([]string{"APP_*", "DEBUG"}, manifest.Capabilities.Env.Variables)
}

func (s *LoaderIntegrationSuite) TestExecCapability() {
	yaml := `
name: "exec-plugin"
version: "1.0.0"
capabilities:
  exec:
    commands: ["/usr/bin/ls", "/usr/bin/cat"]
`
	manifest, err := s.loader.LoadManifest([]byte(yaml), nil)
	s.Require().NoError(err)
	s.NotNil(manifest.Capabilities.Exec)
	s.Equal([]string{"/usr/bin/ls", "/usr/bin/cat"}, manifest.Capabilities.Exec.Commands)
}

func TestLoaderIntegrationSuite(t *testing.T) {
	suite.Run(t, new(LoaderIntegrationSuite))
}

// Additional standalone tests for backwards compatibility
func TestLoader_Integration(t *testing.T) {
	// 1. Setup Registry
	reg := registry.NewRegistry(registry.WithStrictMode(false))
	err := reg.Register("network", map[string]any{"type": "object"})
	require.NoError(t, err)
	err = reg.Register("fs", map[string]any{"type": "object"})
	require.NoError(t, err)

	// 2. Setup Loader
	loader := host.NewLoader(
		host.WithRegistry(reg),
	)

	t.Run("Valid Manifest", func(t *testing.T) {
		yaml := `
name: "test-plugin"
version: "1.0.0"
capabilities:
  network:
    rules:
      - hosts: ["example.com"]
        ports: ["80"]
`
		manifest, err := loader.LoadManifest([]byte(yaml), nil)
		require.NoError(t, err)
		assert.Equal(t, "test-plugin", manifest.Name)
		assert.NotNil(t, manifest.Capabilities.Network)
		assert.Len(t, manifest.Capabilities.Network.Rules, 1)
	})

	t.Run("Missing Capability Registration", func(t *testing.T) {
		emptyReg := registry.NewRegistry()
		loaderEmpty := host.NewLoader(host.WithRegistry(emptyReg))

		yaml2 := `
name: "test-plugin"
version: "1.0.0"
capabilities:
  network:
    rules:
      - hosts: ["example.com"]
        ports: ["443"]
`
		_, err := loaderEmpty.LoadManifest([]byte(yaml2), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no schema registered for capability kind: network")
	})
}
