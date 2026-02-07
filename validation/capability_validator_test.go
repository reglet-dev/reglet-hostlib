// OWNERSHIP: REGLET RUNTIME (should NOT be in SDK)
// STATUS: Needs migration to reglet/internal/infrastructure/validation/

package validation_test

import (
	"testing"

	abi "github.com/reglet-dev/reglet-abi"
	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-host-sdk/validation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockRegistry struct {
	schemas map[string]string
}

func (m *mockRegistry) Register(name string, capability interface{}) error { return nil }
func (m *mockRegistry) GetSchema(name string) (string, bool) {
	s, ok := m.schemas[name]
	return s, ok
}
func (m *mockRegistry) List() []string { return nil }

func TestCapabilityValidator_Validate(t *testing.T) {
	registry := &mockRegistry{
		schemas: map[string]string{
			"network": `{"type": "object", "properties": {"rules": {"type": "array"}}}`,
			"fs":      `{"type": "object", "required": ["rules"], "properties": {"rules": {"type": "array"}}}`,
		},
	}
	validator := validation.NewCapabilityValidator(registry)

	t.Run("Valid Manifest with Network", func(t *testing.T) {
		manifest := &abi.Manifest{
			Name:    "test-plugin",
			Version: "1.0.0",
			Capabilities: hostfunc.GrantSet{
				Network: &hostfunc.NetworkCapability{
					Rules: []hostfunc.NetworkRule{
						{Hosts: []string{"example.com"}, Ports: []string{"443"}},
					},
				},
			},
		}
		res, err := validator.Validate(manifest)
		require.NoError(t, err)
		assert.True(t, res.Valid)
		assert.Empty(t, res.Errors)
	})

	t.Run("Valid Manifest with FS", func(t *testing.T) {
		manifest := &abi.Manifest{
			Version: "1.0.0",
			Capabilities: hostfunc.GrantSet{
				FS: &hostfunc.FileSystemCapability{
					Rules: []hostfunc.FileSystemRule{
						{Read: []string{"/tmp"}},
					},
				},
			},
		}
		res, err := validator.Validate(manifest)
		require.NoError(t, err)
		assert.True(t, res.Valid)
		assert.Empty(t, res.Errors)
	})

	t.Run("Empty GrantSet", func(t *testing.T) {
		manifest := &abi.Manifest{
			Version:      "1.0.0",
			Capabilities: hostfunc.GrantSet{},
		}
		res, err := validator.Validate(manifest)
		require.NoError(t, err)
		assert.True(t, res.Valid)
	})
}
