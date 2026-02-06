package validation

import abi "github.com/reglet-dev/reglet-abi"

// CapabilityValidator validates plugin capabilities against a schema.
type CapabilityValidator interface {
	// Validate checks that the manifest capabilities match the registered schemas.
	Validate(manifest *abi.Manifest) (*ValidationResult, error)
}
