package netutil

import (
	"net"
	"strings"
)

// NetfilterResult represents the result of an address validation.
type NetfilterResult struct {
	// Reason provides the reason if the address was blocked.
	Reason string `json:"reason,omitempty"`

	// ResolvedIP is the resolved IP address if DNS resolution was performed.
	ResolvedIP string `json:"resolved_ip,omitempty"`

	// Allowed indicates whether the address is allowed.
	Allowed bool `json:"allowed"`
}

// NetfilterOption is a functional option for configuring netfilter behavior.
type NetfilterOption func(*netfilterConfig)

type netfilterConfig struct {
	allowlist      []string // Explicitly allowed addresses/CIDRs
	blocklist      []string // Explicitly blocked addresses/CIDRs
	allowedPorts   []int    // Only allow specific ports (empty = all)
	blockedPorts   []int    // Block specific ports
	blockPrivate   bool     // Block RFC 1918 private addresses
	blockLocalhost bool     // Block localhost/loopback
	blockLinkLocal bool     // Block link-local addresses
	blockMulticast bool     // Block multicast addresses
	resolveDNS     bool     // Resolve hostnames before checking
}

// defaultNetfilterConfig returns secure defaults for netfilter.
// By default, blocks all SSRF-vulnerable addresses.
func defaultNetfilterConfig() netfilterConfig {
	return netfilterConfig{
		allowlist:      nil,
		blocklist:      nil,
		blockPrivate:   true, // Block RFC 1918 (10.x, 172.16.x, 192.168.x)
		blockLocalhost: true, // Block 127.x, ::1
		blockLinkLocal: true, // Block 169.254.x, fe80::
		blockMulticast: true, // Block 224.x-239.x, ff00::
		resolveDNS:     true, // Resolve hostnames to prevent DNS rebinding
		allowedPorts:   nil,
		blockedPorts:   nil,
	}
}

// WithAllowlist sets explicitly allowed addresses or CIDRs.
// Allowed addresses bypass all other checks.
func WithAllowlist(addresses ...string) NetfilterOption {
	return func(c *netfilterConfig) {
		c.allowlist = addresses
	}
}

// WithBlocklist sets explicitly blocked addresses or CIDRs.
// Blocklist is checked before other rules.
func WithBlocklist(addresses ...string) NetfilterOption {
	return func(c *netfilterConfig) {
		c.blocklist = addresses
	}
}

// WithBlockPrivate enables/disables blocking of RFC 1918 private addresses.
func WithBlockPrivate(block bool) NetfilterOption {
	return func(c *netfilterConfig) {
		c.blockPrivate = block
	}
}

// WithBlockLocalhost enables/disables blocking of localhost/loopback.
func WithBlockLocalhost(block bool) NetfilterOption {
	return func(c *netfilterConfig) {
		c.blockLocalhost = block
	}
}

// WithBlockLinkLocal enables/disables blocking of link-local addresses.
func WithBlockLinkLocal(block bool) NetfilterOption {
	return func(c *netfilterConfig) {
		c.blockLinkLocal = block
	}
}

// WithResolveDNS enables/disables DNS resolution before checking.
func WithResolveDNS(resolve bool) NetfilterOption {
	return func(c *netfilterConfig) {
		c.resolveDNS = resolve
	}
}

// WithAllowedPorts restricts connections to specific ports.
func WithAllowedPorts(ports ...int) NetfilterOption {
	return func(c *netfilterConfig) {
		c.allowedPorts = ports
	}
}

// WithBlockedPorts blocks specific ports.
func WithBlockedPorts(ports ...int) NetfilterOption {
	return func(c *netfilterConfig) {
		c.blockedPorts = ports
	}
}

// ValidateAddress validates whether an address is allowed for outbound connections.
// This is the primary SSRF protection mechanism.
//
// SECURITY CRITICAL: This function MUST be called before any outbound network connection.
//
// Example usage:
//
//	result := netutil.ValidateAddress("example.com:443")
//	if !result.Allowed {
//	    return fmt.Errorf("blocked: %s", result.Reason)
//	}
func ValidateAddress(address string, opts ...NetfilterOption) NetfilterResult {
	cfg := defaultNetfilterConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Parse host and port
	host, port, err := parseAddress(address)
	if err != nil {
		return NetfilterResult{
			Allowed: false,
			Reason:  "invalid address format: " + err.Error(),
		}
	}

	// Check port restrictions
	if result := checkPortRestrictions(port, cfg); !result.Allowed {
		return result
	}

	// Check explicit allowlist/blocklist
	result := checkHostLists(host, cfg)
	if result.Allowed || result.Reason != "" {
		return result
	}

	// Resolve and validate IP
	return resolveAndValidateIP(host, cfg)
}

// checkPortRestrictions validates port against allowlist and blocklist.
func checkPortRestrictions(port int, cfg netfilterConfig) NetfilterResult {
	// Check allowlist
	if len(cfg.allowedPorts) > 0 && port > 0 {
		allowed := false
		for _, p := range cfg.allowedPorts {
			if p == port {
				allowed = true
				break
			}
		}
		if !allowed {
			return NetfilterResult{
				Allowed: false,
				Reason:  "port not in allowlist",
			}
		}
	}

	// Check blocklist
	for _, p := range cfg.blockedPorts {
		if p == port {
			return NetfilterResult{
				Allowed: false,
				Reason:  "port is blocked",
			}
		}
	}

	return NetfilterResult{Allowed: true}
}

// checkHostLists checks host against explicit allowlist and blocklist.
// Returns a result with Reason set if a decision was made, empty Reason to continue checking.
func checkHostLists(host string, cfg netfilterConfig) NetfilterResult {
	// Check explicit allowlist first
	if len(cfg.allowlist) > 0 {
		for _, allowed := range cfg.allowlist {
			if matchesPattern(host, allowed) {
				return NetfilterResult{
					Allowed: true,
				}
			}
		}
	}

	// Check explicit blocklist
	for _, blocked := range cfg.blocklist {
		if matchesPattern(host, blocked) {
			return NetfilterResult{
				Allowed: false,
				Reason:  "address in blocklist",
			}
		}
	}

	return NetfilterResult{Reason: ""} // Continue checking
}

// resolveAndValidateIP resolves the hostname to an IP and validates it.
func resolveAndValidateIP(host string, cfg netfilterConfig) NetfilterResult {
	var ip net.IP
	if cfg.resolveDNS {
		ips, err := net.LookupIP(host)
		if err != nil {
			// If host is already an IP, parse it directly
			ip = net.ParseIP(host)
			if ip == nil {
				return NetfilterResult{
					Allowed: false,
					Reason:  "DNS resolution failed: " + err.Error(),
				}
			}
		} else if len(ips) > 0 {
			ip = ips[0]
		}
	} else {
		ip = net.ParseIP(host)
	}

	if ip != nil {
		// Check IP-based restrictions
		result := validateIP(ip, cfg)
		if !result.Allowed {
			return result
		}
		result.ResolvedIP = ip.String()
		return result
	}

	// If we couldn't resolve/parse IP and DNS resolution is disabled,
	// allow by default (hostname-only mode)
	return NetfilterResult{
		Allowed: true,
	}
}

// validateIP checks an IP address against all security rules.
func validateIP(ip net.IP, cfg netfilterConfig) NetfilterResult {
	// Check blocklist CIDRs
	for _, blocked := range cfg.blocklist {
		_, cidr, err := net.ParseCIDR(blocked)
		if err == nil && cidr.Contains(ip) {
			return NetfilterResult{
				Allowed: false,
				Reason:  "IP in blocklist CIDR",
			}
		}
	}

	// Check IP security restrictions
	if result := checkIPSecurityRestrictions(ip, cfg); !result.Allowed {
		return result
	}

	// Check allowlist CIDRs (if allowlist has CIDRs)
	if len(cfg.allowlist) > 0 {
		for _, allowed := range cfg.allowlist {
			_, cidr, err := net.ParseCIDR(allowed)
			if err == nil && cidr.Contains(ip) {
				return NetfilterResult{
					Allowed:    true,
					ResolvedIP: ip.String(),
				}
			}
		}
	}

	return NetfilterResult{
		Allowed:    true,
		ResolvedIP: ip.String(),
	}
}

// checkIPSecurityRestrictions checks IP against security policies (localhost, private, link-local, etc).
func checkIPSecurityRestrictions(ip net.IP, cfg netfilterConfig) NetfilterResult {
	// Check localhost/loopback
	if cfg.blockLocalhost && ip.IsLoopback() {
		return NetfilterResult{
			Allowed: false,
			Reason:  "localhost/loopback addresses blocked",
		}
	}

	// Check private addresses (RFC 1918)
	if cfg.blockPrivate && ip.IsPrivate() {
		return NetfilterResult{
			Allowed: false,
			Reason:  "private addresses blocked (RFC 1918)",
		}
	}

	// Check link-local
	if cfg.blockLinkLocal && ip.IsLinkLocalUnicast() {
		return NetfilterResult{
			Allowed: false,
			Reason:  "link-local addresses blocked",
		}
	}

	// Check multicast
	if cfg.blockMulticast && ip.IsMulticast() {
		return NetfilterResult{
			Allowed: false,
			Reason:  "multicast addresses blocked",
		}
	}

	// Check unspecified (0.0.0.0, ::)
	if ip.IsUnspecified() {
		return NetfilterResult{
			Allowed: false,
			Reason:  "unspecified address blocked",
		}
	}

	return NetfilterResult{Allowed: true}
}

// parseAddress extracts host and port from an address string.
func parseAddress(address string) (host string, port int, err error) {
	// Handle addresses without port
	if !strings.Contains(address, ":") {
		return address, 0, nil
	}

	// Try to split host:port
	h, p, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		// May be an IPv6 address without port
		if strings.Contains(address, "::") || strings.Count(address, ":") > 1 {
			return address, 0, nil
		}
		return "", 0, splitErr
	}

	host = h
	if p != "" {
		// Parse port number
		for _, c := range p {
			if c < '0' || c > '9' {
				return "", 0, &net.AddrError{Err: "invalid port", Addr: address}
			}
			port = port*10 + int(c-'0')
		}
	}

	return host, port, nil
}

// matchesPattern checks if a host matches a pattern (hostname, IP, or CIDR).
func matchesPattern(host, pattern string) bool {
	// Direct match
	if host == pattern {
		return true
	}

	// Wildcard match (*.example.com)
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // .example.com
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	// CIDR match
	ip := net.ParseIP(host)
	if ip != nil {
		_, cidr, err := net.ParseCIDR(pattern)
		if err == nil && cidr.Contains(ip) {
			return true
		}
	}

	return false
}
