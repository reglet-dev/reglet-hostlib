package wazero

import (
	"context"
	"fmt"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	hostlib "github.com/reglet-dev/reglet-host-sdk"
	"github.com/tetratelabs/wazero/api"
)

// CapabilityChecker validates operations against granted capabilities.
// It can be used as middleware or directly in handler implementations.
type CapabilityChecker interface {
	// CheckNetwork validates network operations.
	CheckNetwork(pluginName string, req hostfunc.NetworkRequest) error

	// CheckFileSystem validates filesystem operations.
	CheckFileSystem(pluginName string, req hostfunc.FileSystemRequest) error

	// CheckEnvironment validates environment variable access.
	CheckEnvironment(pluginName string, req hostfunc.EnvironmentRequest) error

	// CheckExec validates command execution.
	CheckExec(pluginName string, req hostfunc.ExecCapabilityRequest) error
}

// WazeroCapabilityHandler creates a wazero GoModuleFunc that wraps a handler
// with capability checking.
func WazeroCapabilityHandler(
	handler func(ctx context.Context, mod api.Module, stack []uint64),
	checker CapabilityChecker,
) api.GoModuleFunc {
	return func(ctx context.Context, mod api.Module, stack []uint64) {
		// Add plugin name to context
		pluginName := GetPluginName(ctx, mod)
		ctx = WithPluginName(ctx, pluginName)

		// Call the wrapped handler
		handler(ctx, mod, stack)
	}
}

// NewCapabilityGetterFromChecker creates a CapabilityGetter function from a CapabilityChecker.
// This allows the SDK's exec security features to use the capability checker.
func NewCapabilityGetterFromChecker(checker CapabilityChecker) hostlib.CapabilityGetter {
	return func(pluginName, capability string) bool {
		//  Strictly treat the string as an Exec command request
		err := checker.CheckExec(pluginName, hostfunc.ExecCapabilityRequest{Command: capability})
		return err == nil
	}
}

// CapabilityDeniedError represents a capability check failure.
type CapabilityDeniedError struct {
	PluginName string
	Kind       string
	Pattern    string
}

func (e *CapabilityDeniedError) Error() string {
	return fmt.Sprintf("capability denied: plugin %q requires %s:%s", e.PluginName, e.Kind, e.Pattern)
}
