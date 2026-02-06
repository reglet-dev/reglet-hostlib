package wazero

import (
	"context"

	"github.com/tetratelabs/wazero/api"
)

// contextKey is a private type for context keys.
type contextKey struct {
	name string
}

var pluginNameKey = &contextKey{name: "plugin_name"}

// WithPluginName adds the plugin name to the context.
// This is used by capability checkers to identify which plugin is making a request.
func WithPluginName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, pluginNameKey, name)
}

// PluginNameFromContext retrieves the plugin name from the context.
func PluginNameFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(pluginNameKey).(string)
	return name, ok
}

// GetPluginName extracts the plugin name from context, falling back to the module name.
func GetPluginName(ctx context.Context, mod api.Module) string {
	if name, ok := PluginNameFromContext(ctx); ok {
		return name
	}
	return mod.Name()
}
