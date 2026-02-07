// Package grantstore provides file-based persistence for capability grants.
package grantstore

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"gopkg.in/yaml.v3"
)

// fileStoreConfig holds configuration for the FileStore.
type fileStoreConfig struct {
	path     string
	dirPerm  os.FileMode
	filePerm os.FileMode
}

func defaultFileStoreConfig() fileStoreConfig {
	return fileStoreConfig{
		path:     filepath.Join(os.Getenv("HOME"), ".reglet", "grants.yaml"),
		dirPerm:  0o755,
		filePerm: 0o600,
	}
}

// FileStoreOption configures a FileStore instance.
type FileStoreOption func(*fileStoreConfig)

// WithPath sets the path to the grants file.
func WithPath(path string) FileStoreOption {
	return func(c *fileStoreConfig) {
		if path != "" {
			c.path = path
		}
	}
}

// WithFilePermissions sets the file permissions for the grants file.
func WithFilePermissions(perm os.FileMode) FileStoreOption {
	return func(c *fileStoreConfig) {
		c.filePerm = perm
	}
}

// WithDirPermissions sets the directory permissions for the grants directory.
func WithDirPermissions(perm os.FileMode) FileStoreOption {
	return func(c *fileStoreConfig) {
		c.dirPerm = perm
	}
}

// FileStore provides file-based persistence for capability grants.
// Serializes directly to/from hostfunc.GrantSet (ABI types) - no conversion needed.
type FileStore struct {
	config fileStoreConfig
}

// NewFileStore creates a new FileStore with the given options.
func NewFileStore(opts ...FileStoreOption) *FileStore {
	cfg := defaultFileStoreConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &FileStore{config: cfg}
}

// Load retrieves all granted capabilities.
func (s *FileStore) Load() (*hostfunc.GrantSet, error) {
	data, err := os.ReadFile(s.config.path)
	if os.IsNotExist(err) {
		return &hostfunc.GrantSet{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read grant store: %w", err)
	}

	var grants hostfunc.GrantSet
	if err := yaml.Unmarshal(data, &grants); err != nil {
		return nil, fmt.Errorf("failed to parse grant store: %w", err)
	}
	return &grants, nil
}

// Save persists the granted capabilities.
func (s *FileStore) Save(grants *hostfunc.GrantSet) error {
	if grants == nil {
		grants = &hostfunc.GrantSet{}
	}

	clean := grants.Clone()
	clean.Deduplicate()

	data, err := yaml.Marshal(clean)
	if err != nil {
		return fmt.Errorf("failed to marshal grants: %w", err)
	}

	dir := filepath.Dir(s.config.path)
	if err := os.MkdirAll(dir, s.config.dirPerm); err != nil {
		return fmt.Errorf("failed to create grant store directory: %w", err)
	}

	if err := os.WriteFile(s.config.path, data, s.config.filePerm); err != nil {
		return fmt.Errorf("failed to write grant store: %w", err)
	}
	return nil
}

// ConfigPath returns the path to the backing store.
func (s *FileStore) ConfigPath() string {
	return s.config.path
}
