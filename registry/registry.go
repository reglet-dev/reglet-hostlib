// Package registry implements a capability registry for managing JSON schemas.
package registry

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sync"

	"github.com/invopop/jsonschema"
)

// Registry implements ports.CapabilityRegistry using in-memory storage.
type Registry struct {
	schemas    map[string]string
	mu         sync.RWMutex
	strictMode bool
	reflector  *jsonschema.Reflector
}

// RegistryOption configures the Registry.
type RegistryOption func(*Registry)

// WithStrictMode enables strict validation mode (if applicable).
func WithStrictMode(strict bool) RegistryOption {
	return func(r *Registry) {
		r.strictMode = strict
	}
}

// NewRegistry creates a new capability registry.
func NewRegistry(opts ...RegistryOption) CapabilityRegistry {
	r := &Registry{
		schemas:    make(map[string]string),
		reflector:  new(jsonschema.Reflector),
		strictMode: true,
	}

	// Configure reflector defaults if needed
	r.reflector.ExpandedStruct = true

	for _, opt := range opts {
		opt(r)
	}

	return r
}

// Register adds a schema for a capability kind.
// model can be a Go struct (to generate schema) or a raw JSON schema string/map.
func (r *Registry) Register(kind string, model interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.schemas[kind]; exists {
		return fmt.Errorf("capability kind already registered: %s", kind)
	}

	var schemaStr string

	switch v := model.(type) {
	case string:
		schemaStr = v
	case map[string]interface{}:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("failed to marshal schema map: %w", err)
		}
		schemaStr = string(b)
	default:
		// Assume it's a Go struct, generate schema
		if reflect.ValueOf(model).Kind() != reflect.Struct {
			// If it's not a struct, maybe it's a pointer to struct?
			t := reflect.TypeOf(model)
			if t.Kind() == reflect.Ptr && t.Elem().Kind() == reflect.Struct {
				// OK
			} else {
				// Fallback: try marshaling as JSON (e.g. byte slice representing schema)
				if b, ok := model.([]byte); ok {
					schemaStr = string(b)
					goto Save
				}
				// If strictly strict, maybe error? But for now let's try jsonschema reflection anyway
			}
		}

		s := r.reflector.Reflect(model)
		b, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal generated schema: %w", err)
		}
		schemaStr = string(b)
	}

Save:
	r.schemas[kind] = schemaStr
	return nil
}

// GetSchema retrieves the JSON Schema for a capability type.
func (r *Registry) GetSchema(kind string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.schemas[kind]
	return s, ok
}

// List returns all registered capability type names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.schemas))
	for k := range r.schemas {
		keys = append(keys, k)
	}
	return keys
}
