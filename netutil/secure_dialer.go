package netutil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// SecureDialer provides DNS pinning and SSRF protection for network connections.
// It resolves DNS once, validates with ValidateAddress, and caches the resolved IP
// with a configurable TTL to prevent DNS rebinding attacks.
type SecureDialer struct {
	// OnBlocked is called when SSRF protection blocks an address.
	OnBlocked func(addr string, reason string)

	// OnDNSPinning is called when DNS is resolved and pinned.
	OnDNSPinning func(host string, ip net.IP)

	// Resolver is an optional custom DNS resolver.
	Resolver *net.Resolver

	// Timeout is the dial timeout. Default: 30s.
	Timeout time.Duration

	// CacheTTL is the duration to cache resolved IPs. Default: 5min.
	CacheTTL time.Duration

	// AllowPrivateNetwork allows connections to private/localhost addresses.
	// When true, maps to WithBlockPrivate(false) and WithBlockLocalhost(false).
	AllowPrivateNetwork bool

	mu    sync.RWMutex
	cache map[string]pinnedEntry
}

type pinnedEntry struct {
	ip        net.IP
	timestamp time.Time
}

// DialContext connects to the address with DNS pinning and SSRF protection.
// It resolves DNS once, validates against SSRF rules via ValidateAddress, and
// connects using the pinned IP to prevent DNS rebinding attacks.
func (d *SecureDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	// Check cache first
	if ip, ok := d.getCached(host); ok {
		return d.dialIP(ctx, network, ip, port)
	}

	// Check if it's already an IP address
	if ip := net.ParseIP(host); ip != nil {
		if err := d.validateWithNetfilter(host, port); err != nil {
			return nil, err
		}
		d.cacheIP(host, ip)
		return d.dialIP(ctx, network, ip, port)
	}

	// Resolve DNS
	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("DNS lookup failed for %q: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %q", host)
	}

	// Prefer IPv4 for compatibility
	var selectedIP net.IP
	for _, ipAddr := range ips {
		ip := ipAddr.IP
		if ip.To4() != nil {
			selectedIP = ip
			break
		}
	}
	if selectedIP == nil {
		selectedIP = ips[0].IP
	}

	// Notify about DNS pinning
	if d.OnDNSPinning != nil {
		d.OnDNSPinning(host, selectedIP)
	}

	// Validate the resolved IP using ValidateAddress (skipping DNS since we already resolved)
	if err := d.validateResolvedIP(selectedIP); err != nil {
		return nil, err
	}

	// Cache the validated resolution
	d.cacheIP(host, selectedIP)

	return d.dialIP(ctx, network, selectedIP, port)
}

// validateWithNetfilter validates an address using ValidateAddress.
func (d *SecureDialer) validateWithNetfilter(host, port string) error {
	addr := host
	if port != "" {
		addr = net.JoinHostPort(host, port)
	}

	var opts []NetfilterOption
	opts = append(opts, WithResolveDNS(false)) // We handle DNS ourselves
	if d.AllowPrivateNetwork {
		opts = append(opts, WithBlockPrivate(false), WithBlockLocalhost(false))
	}

	result := ValidateAddress(addr, opts...)
	if !result.Allowed {
		if d.OnBlocked != nil {
			d.OnBlocked(addr, result.Reason)
		}
		return &SSRFBlockedError{Address: addr, Reason: result.Reason}
	}
	return nil
}

// validateResolvedIP validates a resolved IP using netfilter rules.
func (d *SecureDialer) validateResolvedIP(ip net.IP) error {
	var opts []NetfilterOption
	opts = append(opts, WithResolveDNS(false))
	if d.AllowPrivateNetwork {
		opts = append(opts, WithBlockPrivate(false), WithBlockLocalhost(false))
	}

	result := ValidateAddress(ip.String(), opts...)
	if !result.Allowed {
		if d.OnBlocked != nil {
			d.OnBlocked(ip.String(), result.Reason)
		}
		return &SSRFBlockedError{Address: ip.String(), Reason: result.Reason}
	}
	return nil
}

// getCached returns a cached IP if it exists and hasn't expired.
func (d *SecureDialer) getCached(host string) (net.IP, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.cache == nil {
		return nil, false
	}

	entry, ok := d.cache[host]
	if !ok {
		return nil, false
	}

	ttl := d.CacheTTL
	if ttl == 0 {
		ttl = 5 * time.Minute
	}

	if time.Since(entry.timestamp) >= ttl {
		return nil, false
	}

	return entry.ip, true
}

// cacheIP stores a resolved IP in the cache.
func (d *SecureDialer) cacheIP(host string, ip net.IP) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.cache == nil {
		d.cache = make(map[string]pinnedEntry)
	}

	d.cache[host] = pinnedEntry{
		ip:        ip,
		timestamp: time.Now(),
	}
}

// dialIP connects to the specified IP and port.
func (d *SecureDialer) dialIP(ctx context.Context, network string, ip net.IP, port string) (net.Conn, error) {
	timeout := d.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	dialer := &net.Dialer{
		Timeout: timeout,
	}

	addr := net.JoinHostPort(ip.String(), port)
	return dialer.DialContext(ctx, network, addr)
}

// SSRFBlockedError is returned when SSRF protection blocks a connection.
type SSRFBlockedError struct {
	Address string
	Reason  string
}

func (e *SSRFBlockedError) Error() string {
	return fmt.Sprintf("SSRF protection blocked connection to %s: %s", e.Address, e.Reason)
}

// IsSSRFBlockedError returns true if the error is an SSRFBlockedError.
func IsSSRFBlockedError(err error) bool {
	var ssrfErr *SSRFBlockedError
	return errors.As(err, &ssrfErr)
}
