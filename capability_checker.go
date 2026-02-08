package hostlib

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	"github.com/reglet-dev/reglet-host-sdk/policy"
)

// CapabilityChecker checks if operations are allowed based on granted capabilities.
// It uses the SDK's typed Policy for capability enforcement.
type CapabilityChecker struct {
	policy              policy.Policy
	grantedCapabilities map[string]*hostfunc.GrantSet
	cwd                 string // Current working directory for resolving relative paths
	denialHandler       DenialHandler
}

// DenialHandler is called when a capability is denied.
// It allows custom logging or auditing.
type DenialHandler func(ctx context.Context, pluginName, capabilityKind, pattern, message string)

// CapabilityCheckerOption configures a CapabilityChecker.
type CapabilityCheckerOption func(*capabilityCheckerConfig)

type capabilityCheckerConfig struct {
	cwd               string
	symlinkResolution bool
	denialHandler     DenialHandler
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

// WithCapabilityDenialHandler sets the handler for denied capabilities.
func WithCapabilityDenialHandler(handler DenialHandler) CapabilityCheckerOption {
	return func(c *capabilityCheckerConfig) {
		c.denialHandler = handler
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
		cfg.cwd, _ = os.Getwd()
	}

	return &CapabilityChecker{
		policy: policy.NewPolicy(
			policy.WithWorkingDirectory(cfg.cwd),
			policy.WithSymlinkResolution(cfg.symlinkResolution),
		),
		grantedCapabilities: caps,
		cwd:                 cfg.cwd,
		denialHandler:       cfg.denialHandler,
	}
}

// CheckNetwork performs typed network capability check.
func (c *CapabilityChecker) CheckNetwork(ctx context.Context, pluginName string, req hostfunc.NetworkRequest) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return c.handleDeny(ctx, pluginName, "network", fmt.Sprintf("%s:%d", req.Host, req.Port), "no capabilities granted")
	}

	if c.policy.CheckNetwork(req, grants) {
		return nil
	}

	return c.handleDeny(ctx, pluginName, "network", fmt.Sprintf("%s:%d", req.Host, req.Port), "network capability denied")
}

// CheckNetworkConnection checks if a specific network connection (host:port) is allowed.
func (c *CapabilityChecker) CheckNetworkConnection(ctx context.Context, pluginName, host string, port int) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return c.handleDeny(ctx, pluginName, "network", fmt.Sprintf("%s:%d", host, port), "no capabilities granted")
	}

	req := hostfunc.NetworkRequest{Host: host, Port: port}

	// 1. Silent Check
	if c.policy.EvaluateNetwork(req, grants) {
		return nil
	}

	// 2. Loud Check
	c.policy.CheckNetwork(req, grants)
	return c.handleDeny(ctx, pluginName, "network", fmt.Sprintf("%s:%d", host, port), "network capability denied")
}

// CheckFileSystem performs typed filesystem capability check.
func (c *CapabilityChecker) CheckFileSystem(ctx context.Context, pluginName string, req hostfunc.FileSystemRequest) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return c.handleDeny(ctx, pluginName, "fs", req.Path, "no capabilities granted")
	}

	if c.policy.CheckFileSystem(req, grants) {
		return nil
	}

	return c.handleDeny(ctx, pluginName, "fs", req.Path, "filesystem capability denied")
}

// CheckEnvironment performs typed environment capability check.
func (c *CapabilityChecker) CheckEnvironment(ctx context.Context, pluginName string, req hostfunc.EnvironmentRequest) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return c.handleDeny(ctx, pluginName, "env", req.Variable, "no capabilities granted")
	}

	if c.policy.CheckEnvironment(req, grants) {
		return nil
	}

	return c.handleDeny(ctx, pluginName, "env", req.Variable, "environment capability denied")
}

// CheckExec performs typed exec capability check.
func (c *CapabilityChecker) CheckExec(ctx context.Context, pluginName string, req hostfunc.ExecCapabilityRequest) error {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return c.handleDeny(ctx, pluginName, "exec", req.Command, "no capabilities granted")
	}

	if c.policy.CheckExec(req, grants) {
		return nil
	}

	return c.handleDeny(ctx, pluginName, "exec", req.Command, "exec capability denied")
}

func (c *CapabilityChecker) handleDeny(ctx context.Context, pluginName, kind, pattern, message string) error {
	fullMsg := fmt.Sprintf("%s: %s", message, pattern)
	if c.denialHandler != nil {
		c.denialHandler(ctx, pluginName, kind, pattern, fullMsg)
	}
	return fmt.Errorf("%s", fullMsg)
}

// AllowsPrivateNetwork checks if the plugin is allowed to access private network addresses.
func (c *CapabilityChecker) AllowsPrivateNetwork(pluginName string) bool {
	grants, ok := c.grantedCapabilities[pluginName]
	if !ok || grants == nil {
		return false
	}

	req := hostfunc.NetworkRequest{Host: "127.0.0.1", Port: 0}
	return c.policy.EvaluateNetwork(req, grants)
}

// ToCapabilityGetter returns a CapabilityGetter function that uses this checker.
func (c *CapabilityChecker) ToCapabilityGetter(ctx context.Context, pluginName string) CapabilityGetter {
	return func(plugin, capability string) bool {
		if varName, found := strings.CutPrefix(capability, "env:"); found {
			if err := c.CheckEnvironment(ctx, pluginName, hostfunc.EnvironmentRequest{Variable: varName}); err == nil {
				return true
			}
			if err := c.CheckExec(ctx, pluginName, hostfunc.ExecCapabilityRequest{Command: capability}); err == nil {
				return true
			}
			return false
		}
		err := c.CheckExec(ctx, pluginName, hostfunc.ExecCapabilityRequest{Command: capability})
		return err == nil
	}
}

// CapabilityMiddleware returns a middleware that enforces capabilities for standard host functions.
func CapabilityMiddleware(checker *CapabilityChecker) Middleware {
	return func(next ByteHandler) ByteHandler {
		return func(ctx context.Context, payload []byte) ([]byte, error) {
			funcName := ""
			if hc, ok := ctx.(HostContext); ok {
				funcName = hc.FunctionName()
			}

			pluginName, ok := CapabilityPluginNameFromContext(ctx)
			if !ok {
				return next(ctx, payload)
			}

			// Add SSRF protection context based on plugin capabilities
			allowPrivate := checker.AllowsPrivateNetwork(pluginName)
			ctx = context.WithValue(ctx, "ssrf_allow_private", allowPrivate)

			// Validate capability based on function name and payload
			switch funcName {
			case "dns_lookup":
				var req hostfunc.DNSRequest
				if err := json.Unmarshal(payload, &req); err == nil {
					if err := checker.CheckNetwork(ctx, pluginName, hostfunc.NetworkRequest{Host: req.Hostname, Port: 53}); err != nil {
						return NewValidationError(err.Error()).ToJSON(), nil
					}
				}
			case "tcp_connect":
				var req hostfunc.TCPRequest
				if err := json.Unmarshal(payload, &req); err == nil {
					port, _ := strconv.Atoi(req.Port)
					if err := checker.CheckNetwork(ctx, pluginName, hostfunc.NetworkRequest{Host: req.Host, Port: port}); err != nil {
						return NewValidationError(err.Error()).ToJSON(), nil
					}
				}
			case "smtp_connect":
				var req hostfunc.SMTPRequest
				if err := json.Unmarshal(payload, &req); err == nil {
					port, _ := strconv.Atoi(req.Port)
					if err := checker.CheckNetwork(ctx, pluginName, hostfunc.NetworkRequest{Host: req.Host, Port: port}); err != nil {
						return NewValidationError(err.Error()).ToJSON(), nil
					}
				}
			case "http_request":
				var req hostfunc.HTTPRequest
				if err := json.Unmarshal(payload, &req); err == nil {
					if err := checkHTTPCapability(ctx, checker, pluginName, req.URL); err != nil {
						return NewValidationError(err.Error()).ToJSON(), nil
					}
				}
			case "exec_command":
				var req hostfunc.ExecRequest
				if err := json.Unmarshal(payload, &req); err == nil {
					// Detection logic
					execType := GetExecutionTypeDescription(req.Command, req.Args)
					if IsDangerousExecution(req.Command, req.Args) {
						if err := checker.CheckExec(ctx, pluginName, hostfunc.ExecCapabilityRequest{Command: req.Command}); err != nil {
							msg := fmt.Sprintf("%s requires 'exec:%s' capability", execType, req.Command)
							return NewValidationError(msg).ToJSON(), nil
						}
					} else {
						if err := checker.CheckExec(ctx, pluginName, hostfunc.ExecCapabilityRequest{Command: req.Command}); err != nil {
							return NewValidationError(err.Error()).ToJSON(), nil
						}
					}
				}
			}

			return next(ctx, payload)
		}
	}
}

func checkHTTPCapability(ctx context.Context, checker *CapabilityChecker, pluginName, rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	portStr := parsedURL.Port()
	if portStr == "" {
		if parsedURL.Scheme == "https" {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}

	port, _ := strconv.Atoi(portStr)
	return checker.CheckNetworkConnection(ctx, pluginName, parsedURL.Hostname(), port)
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
