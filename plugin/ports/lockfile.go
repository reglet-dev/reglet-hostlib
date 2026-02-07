package ports

import (
	"context"

	"github.com/reglet-dev/reglet-host-sdk/plugin/entities"
)

// VersionResolver converts version constraints to exact versions.
type VersionResolver interface {
	Resolve(constraint string, available []string) (string, error)
}

// LockfileRepository manages lockfile persistence.
type LockfileRepository interface {
	Load(ctx context.Context, path string) (*entities.Lockfile, error)
	Save(ctx context.Context, lockfile *entities.Lockfile, path string) error
	Exists(ctx context.Context, path string) (bool, error)
}

// PluginDigester computes digests for plugins.
type PluginDigester interface {
	DigestBytes(data []byte) string
	DigestFile(ctx context.Context, path string) (string, error)
}
