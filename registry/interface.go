package registry

// CapabilityRegistry manages JSON schemas for capability types.
type CapabilityRegistry interface {
	// Register adds a schema for a capability kind (e.g. "network", "fs").
	// model can be a struct (to generate schema) or a JSON schema string/map.
	Register(kind string, model interface{}) error

	// GetSchema returns the JSON schema for a capability kind.
	GetSchema(kind string) (string, bool)

	// List returns all registered capability kinds.
	List() []string
}
