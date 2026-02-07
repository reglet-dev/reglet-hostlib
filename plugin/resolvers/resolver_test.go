package resolvers

import (
	"context"
	"errors"
	"testing"

	"github.com/reglet-dev/reglet-host-sdk/plugin"
	"github.com/reglet-dev/reglet-host-sdk/plugin/dto"
	"github.com/reglet-dev/reglet-host-sdk/plugin/entities"
	"github.com/reglet-dev/reglet-host-sdk/plugin/values"
)

func TestCachedPluginResolver(t *testing.T) {
	ref := values.NewPluginReference("reg", "org", "repo", "name", "1.0")
	p := entities.NewPlugin(ref, values.Digest{}, values.PluginMetadata{})

	t.Run("ReturnsCachedPlugin", func(t *testing.T) {
		repo := &plugin.MockRepository{FindPlugin: p}
		resolver := NewCachedPluginResolver(repo)

		got, err := resolver.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		if got != p {
			t.Error("expected cached plugin")
		}
	})

	t.Run("DelegatesOnCacheMiss", func(t *testing.T) {
		repo := &plugin.MockRepository{FindErr: errors.New("not found")}
		resolver := NewCachedPluginResolver(repo)
		next := &plugin.MockResolver{Err: errors.New("delegated")}
		resolver.SetNext(next)

		_, err := resolver.Resolve(context.Background(), ref)
		if err == nil || err.Error() != "delegated" {
			t.Errorf("expected delegation error, got %v", err)
		}
	})
}

func TestRegistryPluginResolver(t *testing.T) {
	logger := plugin.NewTestLogger()
	ref := values.NewPluginReference("reg", "org", "repo", "name", "1.0")
	p := entities.NewPlugin(ref, values.Digest{}, values.PluginMetadata{})
	artifact := dto.NewPluginArtifactDTO(p, nil)

	t.Run("PullAndCacheSuccess", func(t *testing.T) {
		registry := &plugin.MockRegistry{PullArtifact: artifact}
		repo := &plugin.MockRepository{}
		resolver := NewRegistryPluginResolver(registry, repo, logger)

		got, err := resolver.Resolve(context.Background(), ref)
		if err != nil {
			t.Fatalf("Resolve failed: %v", err)
		}
		if got != p {
			t.Error("expected pulled plugin")
		}
	})

	t.Run("PullFailure", func(t *testing.T) {
		registry := &plugin.MockRegistry{PullErr: errors.New("network error")}
		repo := &plugin.MockRepository{}
		resolver := NewRegistryPluginResolver(registry, repo, logger)

		_, err := resolver.Resolve(context.Background(), ref)
		if err == nil {
			t.Error("expected pull error")
		}
	})

	t.Run("CacheStorageFailure", func(t *testing.T) {
		registry := &plugin.MockRegistry{PullArtifact: artifact}
		repo := &plugin.MockRepository{StoreErr: errors.New("disk full")}
		resolver := NewRegistryPluginResolver(registry, repo, logger)

		_, err := resolver.Resolve(context.Background(), ref)
		if err == nil {
			t.Error("expected cache storage error")
		}
	})
}
