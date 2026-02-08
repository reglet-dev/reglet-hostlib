package hostlib

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/reglet-dev/reglet-host-sdk/netutil"
)

// TCPConnectRequest contains parameters for a TCP connection test.
type TCPConnectRequest struct {
	// TLSConfig is an optional custom TLS configuration.
	// This field is not marshaled to JSON and is intended for internal use
	// or when calling PerformTCPConnect directly from Go code.
	TLSConfig *tls.Config `json:"-"`

	// Host is the target hostname or IP address.
	Host string `json:"host"`

	// Port is the target port number.
	Port int `json:"port"`

	// Timeout is the connection timeout in milliseconds. Default is 5000 (5s).
	Timeout int `json:"timeout_ms,omitempty"`

	// UseTLS indicates whether to use TLS for the connection.
	UseTLS bool `json:"use_tls,omitempty"`
}

// TCPConnectResponse contains the result of a TCP connection test.
type TCPConnectResponse struct {
	// Error contains error information if the connection failed.
	Error *TCPError `json:"error,omitempty"`

	// RemoteAddr is the resolved remote address if connected.
	RemoteAddr string `json:"remote_addr,omitempty"`

	// TLSVersion is the TLS version used (e.g. "TLS 1.2").
	TLSVersion string `json:"tls_version,omitempty"`

	// TLSCipherSuite is the cipher suite used.
	TLSCipherSuite string `json:"tls_cipher_suite,omitempty"`

	// TLSServerName is the server name from the TLS handshake.
	TLSServerName string `json:"tls_server_name,omitempty"`

	// TLSCertSubject is the subject of the peer certificate.
	TLSCertSubject string `json:"tls_cert_subject,omitempty"`

	// TLSCertIssuer is the issuer of the peer certificate.
	TLSCertIssuer string `json:"tls_cert_issuer,omitempty"`

	// TLSCertExpiry is the expiration time of the peer certificate.
	TLSCertExpiry string `json:"tls_cert_expiry,omitempty"`
	// LatencyMs is the connection latency in milliseconds.
	LatencyMs int64 `json:"latency_ms,omitempty"`
	// Connected indicates whether the connection was successful.
	Connected bool `json:"connected"`
}

// TCPError represents a TCP connection error.
type TCPError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *TCPError) Error() string {
	return e.Message
}

// TCPOption is a functional option for configuring TCP connection behavior.
type TCPOption func(*tcpConfig)

type tcpConfig struct {
	timeout        time.Duration
	ssrfProtection bool
	allowPrivate   bool
}

func defaultTCPConfig() tcpConfig {
	return tcpConfig{
		timeout: 5 * time.Second,
	}
}

// WithTCPTimeout sets the TCP connection timeout.
func WithTCPTimeout(d time.Duration) TCPOption {
	return func(c *tcpConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithTCPSSRFProtection enables SSRF protection.
// When enabled, private/reserved IPs are blocked unless allowPrivate is true.
// DNS is resolved once and the resolved IP is used for the connection (prevents DNS rebinding).
func WithTCPSSRFProtection(allowPrivate bool) TCPOption {
	return func(c *tcpConfig) {
		c.ssrfProtection = true
		c.allowPrivate = allowPrivate
	}
}

// PerformTCPConnect tests TCP connectivity to the specified host and port.
// This is a pure Go implementation with no WASM runtime dependencies.
//
// Example usage from a WASM host:
//
//	func handleTCPConnect(req hostfuncs.TCPConnectRequest) hostfuncs.TCPConnectResponse {
//	    return hostfuncs.PerformTCPConnect(ctx, req)
//	}
//
// PerformTCPConnect tests TCP connectivity to the specified host and port.
func PerformTCPConnect(ctx context.Context, req TCPConnectRequest, opts ...TCPOption) TCPConnectResponse {
	cfg := defaultTCPConfig()

	// Check context for default SSRF protection based on capabilities
	if allowPrivate, ok := ctx.Value("ssrf_allow_private").(bool); ok {
		WithTCPSSRFProtection(allowPrivate)(&cfg)
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	// Override config from request if specified
	if req.Timeout > 0 {
		cfg.timeout = time.Duration(req.Timeout) * time.Millisecond
	}

	// Validate request
	if err := validateTCPRequest(req); err != nil {
		return TCPConnectResponse{Connected: false, Error: err}
	}

	// SSRF Protection
	originalHost := req.Host
	if cfg.ssrfProtection {
		resolvedIP, err := resolveAndValidateTCP(req, cfg)
		if err != nil {
			return TCPConnectResponse{Connected: false, Error: err}
		}
		if resolvedIP != "" {
			req.Host = resolvedIP
		}
	}

	// Attempt connection
	start := time.Now()
	conn, err := connectTCP(ctx, req, cfg, originalHost)
	latency := time.Since(start)

	if err != nil {
		return handleTCPError(err, ctx, latency)
	}
	defer func() { _ = conn.Close() }()

	return createTCPResponse(conn, latency)
}

func validateTCPRequest(req TCPConnectRequest) *TCPError {
	if req.Host == "" {
		return &TCPError{Code: "INVALID_REQUEST", Message: "host is required"}
	}
	if req.Port <= 0 || req.Port > 65535 {
		return &TCPError{Code: "INVALID_REQUEST", Message: fmt.Sprintf("invalid port: %d", req.Port)}
	}
	return nil
}

func resolveAndValidateTCP(req TCPConnectRequest, cfg tcpConfig) (string, *TCPError) {
	addr := fmt.Sprintf("%s:%d", req.Host, req.Port)
	var opts []netutil.NetfilterOption
	if cfg.allowPrivate {
		opts = append(opts, netutil.WithBlockPrivate(false), netutil.WithBlockLocalhost(false))
	}
	result := netutil.ValidateAddress(addr, opts...)

	if !result.Allowed {
		return "", &TCPError{Code: "SSRF_BLOCKED", Message: result.Reason}
	}

	return result.ResolvedIP, nil
}

func connectTCP(ctx context.Context, req TCPConnectRequest, cfg tcpConfig, originalHost string) (net.Conn, error) {
	address := fmt.Sprintf("%s:%d", req.Host, req.Port)
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: cfg.timeout}

	if req.UseTLS {
		tlsConfig := getTLSConfig(req, originalHost)
		return tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	}
	return dialer.DialContext(ctx, "tcp", address)
}

func getTLSConfig(req TCPConnectRequest, originalHost string) *tls.Config {
	tlsConfig := req.TLSConfig
	if tlsConfig == nil {
		serverName := req.Host
		if originalHost != "" && originalHost != req.Host {
			serverName = originalHost
		}
		return &tls.Config{
			ServerName: serverName,
			MinVersion: tls.VersionTLS12,
		}
	}
	if tlsConfig.ServerName == "" {
		serverName := req.Host
		if originalHost != "" && originalHost != req.Host {
			serverName = originalHost
		}
		tlsConfig.ServerName = serverName
	}
	return tlsConfig
}

func handleTCPError(err error, ctx context.Context, latency time.Duration) TCPConnectResponse {
	code := "CONNECTION_FAILED"
	switch {
	case strings.Contains(err.Error(), "timeout"), ctx.Err() == context.DeadlineExceeded:
		code = "TIMEOUT"
	case strings.Contains(err.Error(), "refused"):
		code = "CONNECTION_REFUSED"
	case strings.Contains(err.Error(), "no such host"):
		code = "HOST_NOT_FOUND"
	case strings.Contains(err.Error(), "certificate"):
		code = "TLS_ERROR"
	}

	return TCPConnectResponse{
		Connected: false,
		LatencyMs: latency.Milliseconds(),
		Error: &TCPError{
			Code:    code,
			Message: err.Error(),
		},
	}
}

func createTCPResponse(conn net.Conn, latency time.Duration) TCPConnectResponse {
	resp := TCPConnectResponse{
		Connected:  true,
		RemoteAddr: conn.RemoteAddr().String(),
		LatencyMs:  latency.Milliseconds(),
	}

	// Extract TLS info
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		resp.TLSVersion = tlsVersionString(state.Version)
		resp.TLSCipherSuite = tls.CipherSuiteName(state.CipherSuite)
		resp.TLSServerName = state.ServerName

		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			resp.TLSCertSubject = cert.Subject.String()
			resp.TLSCertIssuer = cert.Issuer.String()
			resp.TLSCertExpiry = cert.NotAfter.Format(time.RFC3339)
		}
	}

	return resp
}
