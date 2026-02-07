package resolvers

import (
	"context"

	"github.com/reglet-dev/reglet-host-sdk/plugin/ports"
	"github.com/reglet-dev/reglet-host-sdk/plugin/entities"
	"github.com/reglet-dev/reglet-host-sdk/plugin/services"
	"github.com/reglet-dev/reglet-host-sdk/plugin/values"
)

// CachedPluginResolver checks local cache for plugins.
type CachedPluginResolver struct {
	services.BaseResolver
	repository ports.PluginRepository
}

// NewCachedPluginResolver creates a cached plugin resolver.
func NewCachedPluginResolver(repository ports.PluginRepository) *CachedPluginResolver {
	return &CachedPluginResolver{
		repository: repository,
	}
}

// Resolve checks cache, otherwise delegates to next.
func (r *CachedPluginResolver) Resolve(ctx context.Context, ref values.PluginReference) (*entities.Plugin, error) {
	plugin, _, err := r.repository.Find(ctx, ref)
	if err == nil {
		return plugin, nil // Found in cache
	}

	// Not in cache, try next resolver
	return r.ResolveNext(ctx, ref)
}
