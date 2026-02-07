package plugin_test

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/reglet-dev/reglet-host-sdk/plugin"
	"github.com/reglet-dev/reglet-host-sdk/plugin/dto"
	"github.com/reglet-dev/reglet-host-sdk/plugin/entities"
	"github.com/reglet-dev/reglet-host-sdk/plugin/services"
	"github.com/reglet-dev/reglet-host-sdk/plugin/values"
)

func TestPluginService_LoadPlugin(t *testing.T) {
	ref := values.NewPluginReference("reg", "org", "repo", "name", "1.0")
	meta := values.NewPluginMetadata("name", "1.0", "desc", nil)
	digest, _ := values.NewDigest("sha256", "abc")
	p := entities.NewPlugin(ref, digest, meta)

	// Mock strategy that returns a plugin
	resolver := &plugin.MockResolver{FoundPlugin: p}

	t.Run("Success_NoVerification", func(t *testing.T) {
		repo := &plugin.MockRepository{FindPath: "/path/to/wasm"}
		svc := plugin.NewPluginService(
			repo,
			nil, // no registry needed
			plugin.WithResolver(resolver),
		)

		spec := &dto.PluginSpecDTO{Name: "reg/org/repo/name:1.0"}
		path, err := svc.LoadPlugin(context.Background(), spec)
		if err != nil {
			t.Fatalf("LoadPlugin failed: %v", err)
		}
		if path != "/path/to/wasm" {
			t.Errorf("expected path /path/to/wasm, got %s", path)
		}
	})

	t.Run("Success_WithDigestVerification", func(t *testing.T) {
		repo := &plugin.MockRepository{FindPath: "/path/to/wasm"}
		svc := plugin.NewPluginService(
			repo,
			nil, // no registry needed
			plugin.WithResolver(resolver),
		)

		spec := &dto.PluginSpecDTO{Name: "reg/org/repo/name:1.0", Digest: "sha256:abc"}
		_, err := svc.LoadPlugin(context.Background(), spec)
		if err != nil {
			t.Errorf("LoadPlugin failed: %v", err)
		}
	})

	t.Run("Fail_DigestMismatch", func(t *testing.T) {
		repo := &plugin.MockRepository{FindPath: "/path/to/wasm"}
		svc := plugin.NewPluginService(
			repo,
			nil, // no registry needed
			plugin.WithResolver(resolver),
		)

		spec := &dto.PluginSpecDTO{Name: "reg/org/repo/name:1.0", Digest: "sha256:bad"}
		_, err := svc.LoadPlugin(context.Background(), spec)
		if err == nil {
			t.Error("LoadPlugin should fail on digest mismatch")
		}
	})

	t.Run("Success_WithSignatureVerification", func(t *testing.T) {
		repo := &plugin.MockRepository{FindPath: "/path/to/wasm"}
		verifier := &plugin.MockVerifier{}
		svc := plugin.NewPluginService(
			repo,
			nil, // no registry needed
			plugin.WithResolver(resolver),
			plugin.WithIntegrityVerifier(verifier),
			plugin.WithIntegrityService(services.NewIntegrityService(true)), // Require signing
			plugin.WithLogger(plugin.NewTestLogger()),
		)

		spec := &dto.PluginSpecDTO{Name: "reg/org/repo/name:1.0"}
		_, err := svc.LoadPlugin(context.Background(), spec)
		if err != nil {
			t.Errorf("LoadPlugin failed: %v", err)
		}
	})

	t.Run("Fail_SignatureVerification", func(t *testing.T) {
		repo := &plugin.MockRepository{FindPath: "/path/to/wasm"}
		verifier := &plugin.MockVerifier{VerifyErr: errors.New("sig fail")}
		svc := plugin.NewPluginService(
			repo,
			nil, // no registry needed
			plugin.WithResolver(resolver),
			plugin.WithIntegrityVerifier(verifier),
			plugin.WithIntegrityService(services.NewIntegrityService(true)),
			plugin.WithLogger(plugin.NewTestLogger()),
		)

		spec := &dto.PluginSpecDTO{Name: "reg/org/repo/name:1.0"}
		_, err := svc.LoadPlugin(context.Background(), spec)
		if err == nil {
			t.Error("LoadPlugin should fail on signature error")
		}
	})

	t.Run("Fail_Resolution", func(t *testing.T) {
		// Here we want to use the type MockResolver to create a NEW instance
		badResolver := &plugin.MockResolver{Err: errors.New("not found")}
		svc := plugin.NewPluginService(
			&plugin.MockRepository{},
			nil, // no registry needed
			plugin.WithResolver(badResolver),
		)
		spec := &dto.PluginSpecDTO{Name: "reg/org/repo/name:1.0"}
		_, err := svc.LoadPlugin(context.Background(), spec)
		if err == nil {
			t.Error("LoadPlugin should fail on resolution error")
		}
	})
}

func TestPluginService_PublishPlugin(t *testing.T) {
	ref := values.NewPluginReference("reg", "org", "repo", "name", "1.0")
	meta := values.NewPluginMetadata("name", "1.0", "desc", nil)
	digest, _ := values.NewDigest("sha256", "abc")
	p := entities.NewPlugin(ref, digest, meta)

	t.Run("Success_PushOnly", func(t *testing.T) {
		registry := &plugin.MockRegistry{}
		svc := plugin.NewPluginService(nil, registry, plugin.WithLogger(plugin.NewTestLogger()))

		err := svc.PublishPlugin(context.Background(), p, io.LimitReader(&mockReader{}, 0), false)
		if err != nil {
			t.Errorf("PublishPlugin failed: %v", err)
		}
	})

	t.Run("Success_PushAndSign", func(t *testing.T) {
		registry := &plugin.MockRegistry{}
		verifier := &plugin.MockVerifier{}
		svc := plugin.NewPluginService(
			nil,
			registry,
			plugin.WithIntegrityVerifier(verifier),
			plugin.WithLogger(plugin.NewTestLogger()),
		)

		err := svc.PublishPlugin(context.Background(), p, io.LimitReader(&mockReader{}, 0), true)
		if err != nil {
			t.Errorf("PublishPlugin failed: %v", err)
		}
	})
}

type mockReader struct{}

func (m *mockReader) Read(p []byte) (n int, err error) { return 0, io.EOF }
