// OWNERSHIP: REGLET RUNTIME (should NOT be in SDK)
// STATUS: Needs migration to reglet/internal/infrastructure/validation/

// Package validation provides validation logic for plugin manifests and capabilities.
package validation

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	abi "github.com/reglet-dev/reglet-abi"
	"github.com/reglet-dev/reglet-host-sdk/registry"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

// Validator implements validation using JSON schemas.
type Validator struct {
	registry registry.CapabilityRegistry
	compiler *jsonschema.Compiler
}

// NewCapabilityValidator creates a new validator.
func NewCapabilityValidator(registry registry.CapabilityRegistry) CapabilityValidator {
	return &Validator{
		registry: registry,
		compiler: jsonschema.NewCompiler(),
	}
}

// Validate checks the manifest capabilities against registered schemas.
func (v *Validator) Validate(manifest *abi.Manifest) (*ValidationResult, error) {
	result := &ValidationResult{Valid: true}

	// Helper to validate a specific capability section
	validateSection := func(kind string, data interface{}) {
		if data == nil {
			return
		}

		// 1. Get Schema
		schemaStr, ok := v.registry.GetSchema(kind)
		if !ok {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   kind,
				Message: fmt.Sprintf("no schema registered for capability kind: %s", kind),
			})
			return
		}

		// 2. Add Resource (ignoring duplicates) and Compile
		if err := v.compiler.AddResource(kind, strings.NewReader(schemaStr)); err != nil {
			// If resource already exists, we can proceed. Ideally check err type, but string check is fallback.
			if !strings.Contains(err.Error(), "already exists") {
				result.Valid = false
				result.Errors = append(result.Errors, ValidationError{
					Field:   kind,
					Message: fmt.Sprintf("failed to add schema resource for %s: %v", kind, err),
				})
				return
			}
		}

		sch, err := v.compiler.Compile(kind)
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   kind,
				Message: fmt.Sprintf("invalid schema for %s: %v", kind, err),
			})
			return
		}

		// 3. Marshal/Unmarshal to interface{} for validation
		b, _ := json.Marshal(data)
		var obj interface{}
		if err := json.Unmarshal(b, &obj); err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, ValidationError{
				Field:   kind,
				Message: fmt.Sprintf("failed to prepare validation object: %v", err),
			})
			return
		}

		// 4. Validate
		if err := sch.Validate(obj); err != nil {
			result.Valid = false
			var ve *jsonschema.ValidationError
			if errors.As(err, &ve) {
				result.Errors = append(result.Errors, ValidationError{
					Field:   kind,
					Message: ve.Error(),
				})
			} else {
				result.Errors = append(result.Errors, ValidationError{
					Field:   kind,
					Message: err.Error(),
				})
			}
		}
	}

	// Validate specific GrantSet sections
	grants := manifest.Capabilities

	// Check Network
	if grants.Network != nil && len(grants.Network.Rules) > 0 {
		validateSection("network", grants.Network)
	}

	// Check FS
	if grants.FS != nil && len(grants.FS.Rules) > 0 {
		validateSection("fs", grants.FS)
	}

	// Check Env
	if grants.Env != nil && len(grants.Env.Variables) > 0 {
		validateSection("env", grants.Env)
	}

	// Check Exec
	if grants.Exec != nil && len(grants.Exec.Commands) > 0 {
		validateSection("exec", grants.Exec)
	}

	// Check KV
	if grants.KV != nil && len(grants.KV.Rules) > 0 {
		validateSection("kv", grants.KV)
	}

	return result, nil
}
