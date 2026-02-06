package validation

// ValidationResult represents the outcome of a capability validation.
type ValidationResult struct {
	Errors []ValidationError
	Valid  bool
}

// ValidationError represents a specific validation error.
type ValidationError struct {
	Field   string
	Message string
}
