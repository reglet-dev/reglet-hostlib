package ports

import "context"

// AuthProvider retrieves authentication credentials for registries.
type AuthProvider interface {
	// GetCredentials returns (username, password, error).
	GetCredentials(ctx context.Context, registry string) (string, string, error)
}
