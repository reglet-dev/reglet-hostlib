package hostlib

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-hostlib/policy"
)

// CapabilityChecker checks if operations are allowed based on granted capabilities.
// It uses the SDK's typed Policy for capability enforcement.
type CapabilityChecker struct {
	policy              policy.Policy
	grantedCapabilities map[string]*hostfunc.GrantSet
	cwd                 string // Current working directory for resolving relative paths
}

// CapabilityCheckerOption configures a CapabilityChecker.
type CapabilityCheckerOption func(*capabilityCheckerConfig)

type capabilityCheckerConfig struct {
	cwd               string
	symlinkResolution bool
}

// WithCapabilityWorkingDirectory sets the working directory for path resolution.
func WithCapabilityWorkingDirectory(cwd string) CapabilityCheckerOption {
	return func(c *capabilityCheckerConfig) {
		c.cwd = cwd
	}
}

// WithCapabilitySymlinkResolution enables or disables symlink resolution.
func WithCapabilitySymlinkResolution(enabled bool) CapabilityCheckerOption {
	return func(c *capabilityCheckerConfig) {
		c.symlinkResolution = enabled
	}
}

// NewCapabilityChecker creates a new capability checker with the given capabilities.
// The cwd is obtained at construction time to avoid side-effects during capability checks.
func NewCapabilityChecker(caps map[string]*hostfunc.GrantSet, opts ...CapabilityCheckerOption) *CapabilityChecker {
	cfg := capabilityCheckerConfig{
		symlinkResolution: true,
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	// Get cwd if not provided
	if cfg.cwd == "" {
		cfg.cwd, _ = os.Getwd() // Best effort - empty string will cause relative paths to fail safely
	}

	return &CapabilityChecker{
		policy: policy.NewPolicy(
			policy.WithWorkingDirectory(cfg.cwd),
			policy.WithSymlinkResolution(cfg.symlinkResolution),
		),
		grantedCapabilities: caps,
		cwd:                 cfg.cwd,
	}
}

// CheckNetwork performs typed network capability check.
func (c *CapabilityChecker) CheckNetwork(pluginName string, req hostfunc.NetworkRequest) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return fmt.Errorf("no capabilities granted to plugin %s", pluginName)
	}

	if c.policy.CheckNetwork(req, grants) {
		return nil
	}

	return fmt.Errorf("network capability denied: %s:%d", req.Host, req.Port)
}

// CheckNetworkConnection checks if a specific network connection (host:port) is allowed.
// It uses EvaluateNetwork (silent) first to avoid logspam, and only checks loudly if denied.
func (c *CapabilityChecker) CheckNetworkConnection(pluginName, host string, port int) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return fmt.Errorf("no capabilities granted to plugin %s", pluginName)
	}

	req := hostfunc.NetworkRequest{Host: host, Port: port}

	// 1. Silent Check: See if ANY rule matches this specific request.
	if c.policy.EvaluateNetwork(req, grants) {
		return nil
	}

	// 2. Loud Check: If denied, call CheckNetwork to trigger the DenialHandler (logging).
	// We know it will return false, but we call it for the side effect.
	c.policy.CheckNetwork(req, grants)

	return fmt.Errorf("network capability denied: %s:%d", host, port)
}

// CheckFileSystem performs typed filesystem capability check.
func (c *CapabilityChecker) CheckFileSystem(pluginName string, req hostfunc.FileSystemRequest) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return fmt.Errorf("no capabilities granted to plugin %s", pluginName)
	}

	if c.policy.CheckFileSystem(req, grants) {
		return nil
	}

	return fmt.Errorf("filesystem capability denied: %s %s", req.Operation, req.Path)
}

// CheckEnvironment performs typed environment capability check.
func (c *CapabilityChecker) CheckEnvironment(pluginName string, req hostfunc.EnvironmentRequest) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return fmt.Errorf("no capabilities granted to plugin %s", pluginName)
	}

	if c.policy.CheckEnvironment(req, grants) {
		return nil
	}

	return fmt.Errorf("environment capability denied: %s", req.Variable)
}

// CheckExec performs typed exec capability check.
func (c *CapabilityChecker) CheckExec(pluginName string, req hostfunc.ExecCapabilityRequest) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return fmt.Errorf("no capabilities granted to plugin %s", pluginName)
	}

	if c.policy.CheckExec(req, grants) {
		return nil
	}

	return fmt.Errorf("exec capability denied: %s", req.Command)
}

// AllowsPrivateNetwork checks if the plugin is allowed to access private network addresses.
func (c *CapabilityChecker) AllowsPrivateNetwork(pluginName string) bool {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return false
	}

	// Create a dummy request for private access.
	req := hostfunc.NetworkRequest{Host: "127.0.0.1", Port: 0}
	return c.policy.EvaluateNetwork(req, grants)
}

// ToCapabilityGetter returns a CapabilityGetter function that uses this checker.
// This allows integration with the exec security features.
func (c *CapabilityChecker) ToCapabilityGetter(pluginName string) CapabilityGetter {
	return func(plugin, capability string) bool {
		// The capability pattern for exec env vars is "env:VARNAME"
		// This can be stored in two places:
		// 1. Exec.Commands as "env:PATH" (Reglet pattern)
		// 2. Env.Variables as "PATH" (SDK pattern)
		if varName, found := strings.CutPrefix(capability, "env:"); found {
			// Try Env.Variables with just "VARNAME"
			if err := c.CheckEnvironment(pluginName, hostfunc.EnvironmentRequest{Variable: varName}); err == nil {
				return true
			}
			// If not found in explicit Env, fallback to checking Exec allowlist for "env:VARNAME"
			if err := c.CheckExec(pluginName, hostfunc.ExecCapabilityRequest{Command: capability}); err == nil {
				return true
			}
			return false
		}
		// For other capabilities, assume it is an exec command
		err := c.CheckExec(pluginName, hostfunc.ExecCapabilityRequest{Command: capability})
		return err == nil
	}
}

// Context helpers for plugin name propagation

type capabilityContextKey struct {
	name string
}

var pluginNameContextKey = &capabilityContextKey{name: "plugin_name"}

// WithCapabilityPluginName adds the plugin name to the context.
func WithCapabilityPluginName(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, pluginNameContextKey, name)
}

// CapabilityPluginNameFromContext retrieves the plugin name from the context.
func CapabilityPluginNameFromContext(ctx context.Context) (string, bool) {
	name, ok := ctx.Value(pluginNameContextKey).(string)
	return name, ok
}
