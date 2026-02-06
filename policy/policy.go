package policy

import (
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/reglet-dev/reglet-abi/hostfunc"
)

// policyConfig holds configuration for the Policy engine.
type policyConfig struct {
	denialHandler   DenialHandler // Handler invoked on policy denials
	cwd             string        // Working directory for relative path resolution
	resolveSymlinks bool          // Whether to resolve symlinks (security feature)
}

func defaultPolicyConfig() policyConfig {
	return policyConfig{
		cwd:             "",
		resolveSymlinks: true,                   // Secure default
		denialHandler:   &StderrDenialHandler{}, // Log to stderr by default
	}
}

// PolicyOption configures the Policy.
type PolicyOption func(*policyConfig)

// WithWorkingDirectory sets the working directory for relative path resolution.
func WithWorkingDirectory(cwd string) PolicyOption {
	return func(c *policyConfig) {
		c.cwd = cwd
	}
}

// WithSymlinkResolution enables/disables symlink resolution.
// Default is true (secure). Disable only for testing.
func WithSymlinkResolution(enabled bool) PolicyOption {
	return func(c *policyConfig) {
		c.resolveSymlinks = enabled
	}
}

// WithDenialHandler sets the denial handler.
func WithDenialHandler(h DenialHandler) PolicyOption {
	return func(c *policyConfig) {
		c.denialHandler = h
	}
}

// Engine implements the Policy interface with stateless enforcement.
type Engine struct {
	cache  sync.Map // key: *hostfunc.GrantSet, value: *compiledGrantSet
	config policyConfig
}

type compiledGrantSet struct {
	networkRules []compiledNetworkRule
	fsRules      []compiledFSRule
	env          []string
	exec         []string
	kvRules      []compiledKVRule
}

type compiledNetworkRule struct {
	hosts []string
	ports []portRange
}

type compiledFSRule struct {
	read  []string
	write []string
}

type compiledKVRule struct {
	op   string
	keys []string
}

type portRange struct {
	min, max int
}

// NewPolicy creates a new Policy engine.
func NewPolicy(opts ...PolicyOption) Policy {
	cfg := defaultPolicyConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Engine{config: cfg}
}

func (p *Engine) getCompiled(grants *hostfunc.GrantSet) *compiledGrantSet {
	if grants == nil {
		return nil
	}
	if v, ok := p.cache.Load(grants); ok {
		return v.(*compiledGrantSet)
	}

	c := &compiledGrantSet{
		networkRules: compileNetworkRules(grants.Network),
		fsRules:      compileFSRules(grants.FS),
		env:          compileEnv(grants.Env),
		exec:         compileExec(grants.Exec),
		kvRules:      compileKVRules(grants.KV),
	}

	p.cache.Store(grants, c)
	return c
}

func compileNetworkRules(network *hostfunc.NetworkCapability) []compiledNetworkRule {
	if network == nil {
		return nil
	}
	var rules []compiledNetworkRule
	for _, rule := range network.Rules {
		cr := compiledNetworkRule{
			hosts: compilePatterns(rule.Hosts),
			ports: compilePorts(rule.Ports),
		}
		rules = append(rules, cr)
	}
	return rules
}

func compilePorts(ports []string) []portRange {
	var ranges []portRange
	for _, portStr := range ports {
		if portStr == "*" {
			ranges = append(ranges, portRange{0, 65535})
			continue
		}
		if strings.Contains(portStr, "-") {
			parts := strings.Split(portStr, "-")
			if len(parts) == 2 {
				minPort, _ := strconv.Atoi(strings.TrimSpace(parts[0]))
				maxPort, _ := strconv.Atoi(strings.TrimSpace(parts[1]))
				ranges = append(ranges, portRange{minPort, maxPort})
			}
		} else {
			val, _ := strconv.Atoi(strings.TrimSpace(portStr))
			ranges = append(ranges, portRange{val, val})
		}
	}
	return ranges
}

func compileFSRules(fs *hostfunc.FileSystemCapability) []compiledFSRule {
	if fs == nil {
		return nil
	}
	var rules []compiledFSRule
	for _, rule := range fs.Rules {
		cr := compiledFSRule{
			read:  compilePatterns(rule.Read),
			write: compilePatterns(rule.Write),
		}
		rules = append(rules, cr)
	}
	return rules
}

func compileEnv(env *hostfunc.EnvironmentCapability) []string {
	if env == nil {
		return nil
	}
	return compilePatterns(env.Variables)
}

func compileExec(exec *hostfunc.ExecCapability) []string {
	if exec == nil {
		return nil
	}
	return compilePatterns(exec.Commands)
}

func compileKVRules(kv *hostfunc.KeyValueCapability) []compiledKVRule {
	if kv == nil {
		return nil
	}
	var rules []compiledKVRule
	for _, rule := range kv.Rules {
		cr := compiledKVRule{
			op:   rule.Operation,
			keys: compilePatterns(rule.Keys),
		}
		rules = append(rules, cr)
	}
	return rules
}

func compilePatterns(patterns []string) []string {
	var valid []string
	for _, p := range patterns {
		if doublestar.ValidatePattern(p) {
			valid = append(valid, p)
		}
	}
	return valid
}

func (p *Engine) CheckNetwork(req hostfunc.NetworkRequest, grants *hostfunc.GrantSet) bool {
	if p.EvaluateNetwork(req, grants) {
		return true
	}
	p.config.denialHandler.OnDenial("network", req, "host/port not allowed")
	return false
}

func (p *Engine) EvaluateNetwork(req hostfunc.NetworkRequest, grants *hostfunc.GrantSet) bool {
	c := p.getCompiled(grants)
	if c == nil {
		return false
	}

	// Check each rule - a request must match at least one rule's hosts AND ports
	for _, rule := range c.networkRules {
		hostMatch := false
		for _, pattern := range rule.hosts {
			if matched, _ := doublestar.Match(pattern, req.Host); matched {
				hostMatch = true
				break
			}
		}

		portMatch := false
		for _, pr := range rule.ports {
			if req.Port >= pr.min && req.Port <= pr.max {
				portMatch = true
				break
			}
		}

		if hostMatch && portMatch {
			return true
		}
	}
	return false
}

func (p *Engine) CheckFileSystem(req hostfunc.FileSystemRequest, grants *hostfunc.GrantSet) bool {
	if p.EvaluateFileSystem(req, grants) {
		return true
	}
	p.config.denialHandler.OnDenial("fs", req, "path not allowed")
	return false
}

func (p *Engine) EvaluateFileSystem(req hostfunc.FileSystemRequest, grants *hostfunc.GrantSet) bool {
	c := p.getCompiled(grants)
	if c == nil {
		return false
	}

	// Normalize and secure the path
	path := filepath.Clean(req.Path)
	if !filepath.IsAbs(path) {
		if p.config.cwd == "" {
			return false // Deny relative paths without cwd
		}
		path = filepath.Join(p.config.cwd, path)
	}

	// Resolve symlinks to prevent traversal attacks
	if p.config.resolveSymlinks {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			path = resolved
		}
	}

	for _, rule := range c.fsRules {
		var patterns []string
		switch req.Operation {
		case "read":
			patterns = rule.read
		case "write":
			patterns = rule.write
		}

		for _, pattern := range patterns {
			if matched, _ := doublestar.Match(pattern, path); matched {
				return true
			}
		}
	}
	return false
}

func (p *Engine) CheckEnvironment(req hostfunc.EnvironmentRequest, grants *hostfunc.GrantSet) bool {
	if p.EvaluateEnvironment(req, grants) {
		return true
	}
	p.config.denialHandler.OnDenial("env", req, "variable not allowed")
	return false
}

func (p *Engine) EvaluateEnvironment(req hostfunc.EnvironmentRequest, grants *hostfunc.GrantSet) bool {
	c := p.getCompiled(grants)
	if c == nil {
		return false
	}

	for _, pattern := range c.env {
		if matched, _ := doublestar.Match(pattern, req.Variable); matched {
			return true
		}
	}
	return false
}

func (p *Engine) CheckExec(req hostfunc.ExecCapabilityRequest, grants *hostfunc.GrantSet) bool {
	if p.EvaluateExec(req, grants) {
		return true
	}
	p.config.denialHandler.OnDenial("exec", req, "command not allowed")
	return false
}

func (p *Engine) EvaluateExec(req hostfunc.ExecCapabilityRequest, grants *hostfunc.GrantSet) bool {
	c := p.getCompiled(grants)
	if c == nil {
		return false
	}

	cmd := filepath.Clean(req.Command)
	for _, pattern := range c.exec {
		if matched, _ := doublestar.Match(pattern, cmd); matched {
			return true
		}
	}
	return false
}

func (p *Engine) CheckKeyValue(req hostfunc.KeyValueRequest, grants *hostfunc.GrantSet) bool {
	if p.EvaluateKeyValue(req, grants) {
		return true
	}
	p.config.denialHandler.OnDenial("kv", req, "key/operation not allowed")
	return false
}

func (p *Engine) EvaluateKeyValue(req hostfunc.KeyValueRequest, grants *hostfunc.GrantSet) bool {
	c := p.getCompiled(grants)
	if c == nil {
		return false
	}

	// Check each KV rule
	for _, rule := range c.kvRules {
		// Check operation
		var allowedOp bool
		switch rule.op {
		case "read-write":
			allowedOp = true
		case "read":
			allowedOp = req.Operation == "read"
		case "write":
			allowedOp = req.Operation == "write"
		}

		if !allowedOp {
			continue
		}

		// Check keys
		for _, pattern := range rule.keys {
			if matched, _ := doublestar.Match(pattern, req.Key); matched {
				return true
			}
		}
	}
	return false
}
