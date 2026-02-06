// They can be used by any WASM plugin host, not just Reglet.
//
// The implementations are designed to be thin wrappers that consuming applications
// (like Reglet) can call from their WASM host function handlers. The SDK handles
// the core logic; the host handles wire format encoding/decoding and memory management.
package hostlib

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DNSLookupRequest contains parameters for a DNS lookup operation.
type DNSLookupRequest struct {
	// Hostname is the domain name to resolve.
	Hostname string `json:"hostname"`

	// RecordType is the DNS record type (A, AAAA, CNAME, MX, TXT, NS).
	RecordType string `json:"type"`

	// Nameserver is the optional custom nameserver address (e.g., "8.8.8.8:53").
	// If empty, the system default resolver is used.
	Nameserver string `json:"nameserver,omitempty"`

	// Timeout is the query timeout in milliseconds. Default is 5000 (5s).
	Timeout int `json:"timeout_ms,omitempty"`
}

// DNSLookupResponse contains the result of a DNS lookup operation.
type DNSLookupResponse struct {
	// Error contains error information if the lookup failed.
	Error *DNSError `json:"error,omitempty"`

	// Records contains the resolved records (IP addresses, strings, etc.).
	Records []string `json:"records,omitempty"`

	// MXRecords contains MX-specific records with preference values.
	MXRecords []MXRecord `json:"mx_records,omitempty"`
}

// MXRecord represents a DNS MX record.
type MXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

// DNSError represents a DNS lookup error.
type DNSError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *DNSError) Error() string {
	return e.Message
}

// DNSOption is a functional option for configuring DNS lookup behavior.
type DNSOption func(*dnsConfig)

type dnsConfig struct {
	nameserver string
	timeout    time.Duration
}

func defaultDNSConfig() dnsConfig {
	return dnsConfig{
		timeout:    5 * time.Second,
		nameserver: "", // Use system default
	}
}

// WithDNSLookupTimeout sets the DNS query timeout.
func WithDNSLookupTimeout(d time.Duration) DNSOption {
	return func(c *dnsConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithDNSNameserver sets a custom nameserver for the lookup.
func WithDNSNameserver(ns string) DNSOption {
	return func(c *dnsConfig) {
		c.nameserver = ns
	}
}

// PerformDNSLookup performs a DNS lookup for the given request.
// This is a pure Go implementation with no WASM runtime dependencies.
//
// Example usage from a WASM host:
//
//	func handleDNSLookup(req hostfuncs.DNSLookupRequest) hostfuncs.DNSLookupResponse {
//	    return hostfuncs.PerformDNSLookup(ctx, req)
//	}
func PerformDNSLookup(ctx context.Context, req DNSLookupRequest, opts ...DNSOption) DNSLookupResponse {
	cfg := defaultDNSConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Override config from request if specified
	if req.Timeout > 0 {
		cfg.timeout = time.Duration(req.Timeout) * time.Millisecond
	}
	if req.Nameserver != "" {
		cfg.nameserver = req.Nameserver
	}

	// Create resolver with optional custom nameserver
	resolver := &net.Resolver{
		PreferGo: true,
	}

	if cfg.nameserver != "" {
		// Ensure nameserver has port
		ns := cfg.nameserver
		if !strings.Contains(ns, ":") {
			ns += ":53"
		}
		resolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: cfg.timeout}
			return d.DialContext(ctx, network, ns)
		}
	}

	// Apply timeout to context
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	// Perform lookup based on record type
	switch strings.ToUpper(req.RecordType) {
	case "A", "AAAA", "":
		return performHostLookup(ctx, resolver, req.Hostname, req.RecordType)
	case "CNAME":
		return performCNAMELookup(ctx, resolver, req.Hostname)
	case "MX":
		return performMXLookup(ctx, resolver, req.Hostname)
	case "TXT":
		return performTXTLookup(ctx, resolver, req.Hostname)
	case "NS":
		return performNSLookup(ctx, resolver, req.Hostname)
	default:
		return DNSLookupResponse{
			Error: &DNSError{
				Code:    "UNSUPPORTED_TYPE",
				Message: fmt.Sprintf("unsupported record type: %s", req.RecordType),
			},
		}
	}
}

func performHostLookup(ctx context.Context, resolver *net.Resolver, hostname, recordType string) DNSLookupResponse {
	ips, err := resolver.LookupIPAddr(ctx, hostname)
	if err != nil {
		return DNSLookupResponse{
			Error: &DNSError{
				Code:    "LOOKUP_FAILED",
				Message: err.Error(),
			},
		}
	}

	var records []string
	for _, ip := range ips {
		// Filter by record type if specified
		if recordType == "A" && ip.IP.To4() == nil {
			continue // Skip IPv6 for A records
		}
		if recordType == "AAAA" && ip.IP.To4() != nil {
			continue // Skip IPv4 for AAAA records
		}
		records = append(records, ip.IP.String())
	}

	return DNSLookupResponse{Records: records}
}

func performCNAMELookup(ctx context.Context, resolver *net.Resolver, hostname string) DNSLookupResponse {
	cname, err := resolver.LookupCNAME(ctx, hostname)
	if err != nil {
		return DNSLookupResponse{
			Error: &DNSError{
				Code:    "LOOKUP_FAILED",
				Message: err.Error(),
			},
		}
	}
	return DNSLookupResponse{Records: []string{cname}}
}

func performMXLookup(ctx context.Context, resolver *net.Resolver, hostname string) DNSLookupResponse {
	mxs, err := resolver.LookupMX(ctx, hostname)
	if err != nil {
		return DNSLookupResponse{
			Error: &DNSError{
				Code:    "LOOKUP_FAILED",
				Message: err.Error(),
			},
		}
	}

	var mxRecords []MXRecord
	for _, mx := range mxs {
		mxRecords = append(mxRecords, MXRecord{
			Host: mx.Host,
			Pref: mx.Pref,
		})
	}
	return DNSLookupResponse{MXRecords: mxRecords}
}

func performTXTLookup(ctx context.Context, resolver *net.Resolver, hostname string) DNSLookupResponse {
	txts, err := resolver.LookupTXT(ctx, hostname)
	if err != nil {
		return DNSLookupResponse{
			Error: &DNSError{
				Code:    "LOOKUP_FAILED",
				Message: err.Error(),
			},
		}
	}
	return DNSLookupResponse{Records: txts}
}

func performNSLookup(ctx context.Context, resolver *net.Resolver, hostname string) DNSLookupResponse {
	nss, err := resolver.LookupNS(ctx, hostname)
	if err != nil {
		return DNSLookupResponse{
			Error: &DNSError{
				Code:    "LOOKUP_FAILED",
				Message: err.Error(),
			},
		}
	}

	var records []string
	for _, ns := range nss {
		records = append(records, ns.Host)
	}
	return DNSLookupResponse{Records: records}
}
