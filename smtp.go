package hostlib

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTPConnectRequest contains parameters for an SMTP connection test.
type SMTPConnectRequest struct {
	// Host is the SMTP server hostname.
	Host string `json:"host"`

	// Port is the SMTP server port (typically 25, 465, or 587).
	Port int `json:"port"`

	// UseTLS indicates whether to use implicit TLS (port 465).
	UseTLS bool `json:"use_tls,omitempty"`

	// UseSTARTTLS indicates whether to upgrade to TLS via STARTTLS (port 587).
	UseSTARTTLS bool `json:"use_starttls,omitempty"`

	// Timeout is the connection timeout in milliseconds. Default is 30000 (30s).
	Timeout int `json:"timeout_ms,omitempty"`
}

// SMTPConnectResponse contains the result of an SMTP connection test.
type SMTPConnectResponse struct {
	// Error contains error information if the connection failed.
	Error *SMTPError `json:"error,omitempty"`

	// Banner is the SMTP server banner (greeting message).
	Banner string `json:"banner,omitempty"`

	// TLSVersion is the TLS version if TLS is used.
	TLSVersion string `json:"tls_version,omitempty"`

	// TLSCipherSuite is the cipher suite used for TLS.
	TLSCipherSuite string `json:"tls_cipher_suite,omitempty"`

	// TLSServerName is the server name used for TLS (SNI).
	TLSServerName string `json:"tls_server_name,omitempty"`

	// LatencyMs is the connection latency in milliseconds.
	LatencyMs int64 `json:"latency_ms,omitempty"`

	// Connected indicates whether the connection was successful.
	Connected bool `json:"connected"`
}

// SMTPError represents an SMTP connection error.
type SMTPError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *SMTPError) Error() string {
	return e.Message
}

// SMTPOption is a functional option for configuring SMTP connection behavior.
type SMTPOption func(*smtpConfig)

type smtpConfig struct {
	tlsConfig      *tls.Config
	timeout        time.Duration
	ssrfProtection bool
	allowPrivate   bool
}

func defaultSMTPConfig() smtpConfig {
	return smtpConfig{
		timeout:   30 * time.Second,
		tlsConfig: nil,
	}
}

// WithSMTPTimeout sets the SMTP connection timeout.
func WithSMTPTimeout(d time.Duration) SMTPOption {
	return func(c *smtpConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithSMTPTLSConfig sets custom TLS configuration.
func WithSMTPTLSConfig(cfg *tls.Config) SMTPOption {
	return func(c *smtpConfig) {
		c.tlsConfig = cfg
	}
}

// WithSMTPSSRFProtection enables SSRF protection.
// When enabled, private/reserved IPs are blocked unless allowPrivate is true.
// DNS is resolved once and the resolved IP is used for the connection (prevents DNS rebinding).
func WithSMTPSSRFProtection(allowPrivate bool) SMTPOption {
	return func(c *smtpConfig) {
		c.ssrfProtection = true
		c.allowPrivate = allowPrivate
	}
}

// PerformSMTPConnect tests SMTP connectivity to the specified server.
// This is a pure Go implementation with no WASM runtime dependencies.
//
// Example usage from a WASM host:
//
//	func handleSMTPConnect(req hostfuncs.SMTPConnectRequest) hostfuncs.SMTPConnectResponse {
//	    return hostfuncs.PerformSMTPConnect(ctx, req)
//	}
func PerformSMTPConnect(ctx context.Context, req SMTPConnectRequest, opts ...SMTPOption) SMTPConnectResponse {
	cfg := defaultSMTPConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Override config from request if specified
	if req.Timeout > 0 {
		cfg.timeout = time.Duration(req.Timeout) * time.Millisecond
	}

	// Validate request
	if req.Host == "" {
		return SMTPConnectResponse{
			Connected: false,
			Error: &SMTPError{
				Code:    "INVALID_REQUEST",
				Message: "host is required",
			},
		}
	}
	if req.Port <= 0 || req.Port > 65535 {
		return SMTPConnectResponse{
			Connected: false,
			Error: &SMTPError{
				Code:    "INVALID_REQUEST",
				Message: fmt.Sprintf("invalid port: %d", req.Port),
			},
		}
	}

	// SSRF Protection: validate and resolve address
	originalHost := req.Host
	resolvedHost := req.Host
	if cfg.ssrfProtection {
		addr := fmt.Sprintf("%s:%d", req.Host, req.Port)
		var opts []NetfilterOption
		if cfg.allowPrivate {
			opts = append(opts, WithBlockPrivate(false), WithBlockLocalhost(false))
		}
		result := ValidateAddress(addr, opts...)

		if !result.Allowed {
			return SMTPConnectResponse{
				Connected: false,
				Error: &SMTPError{
					Code:    "SSRF_BLOCKED",
					Message: result.Reason,
				},
			}
		}

		// Use resolved IP for connection to prevent DNS rebinding
		if result.ResolvedIP != "" {
			resolvedHost = result.ResolvedIP
		}
	}

	// Build address using resolved IP
	address := fmt.Sprintf("%s:%d", resolvedHost, req.Port)

	// Apply timeout to context
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	start := time.Now()

	// Connect based on TLS mode
	if req.UseTLS {
		// Implicit TLS (typically port 465)
		return connectWithTLS(ctx, address, originalHost, cfg, start)
	}

	// Plain connection (may upgrade via STARTTLS)
	return connectPlain(ctx, address, originalHost, req.UseSTARTTLS, cfg, start)
}

func connectWithTLS(ctx context.Context, address, host string, cfg smtpConfig, start time.Time) SMTPConnectResponse {
	tlsConfig := cfg.tlsConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			ServerName: host, // Use original hostname for SNI, not resolved IP
			MinVersion: tls.VersionTLS12,
		}
	} else if tlsConfig.ServerName == "" {
		tlsConfig.ServerName = host
	}

	dialer := &net.Dialer{Timeout: cfg.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", address, tlsConfig)
	latency := time.Since(start)

	if err != nil {
		return SMTPConnectResponse{
			Connected: false,
			LatencyMs: latency.Milliseconds(),
			Error:     classifySMTPError(err),
		}
	}
	defer func() { _ = conn.Close() }()

	// Read banner
	banner, err := readBanner(conn, cfg.timeout)
	if err != nil {
		return SMTPConnectResponse{
			Connected: false,
			LatencyMs: latency.Milliseconds(),
			Error: &SMTPError{
				Code:    "READ_BANNER_FAILED",
				Message: err.Error(),
			},
		}
	}

	state := conn.ConnectionState()
	return SMTPConnectResponse{
		Connected:      true,
		Banner:         banner,
		TLSVersion:     tlsVersionString(state.Version),
		TLSCipherSuite: tls.CipherSuiteName(state.CipherSuite),
		TLSServerName:  state.ServerName,
		LatencyMs:      latency.Milliseconds(),
	}
}

func connectPlain(ctx context.Context, address, host string, useSTARTTLS bool, cfg smtpConfig, start time.Time) SMTPConnectResponse {
	dialer := &net.Dialer{Timeout: cfg.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	latency := time.Since(start)

	if err != nil {
		return SMTPConnectResponse{
			Connected: false,
			LatencyMs: latency.Milliseconds(),
			Error:     classifySMTPError(err),
		}
	}
	defer func() { _ = conn.Close() }()

	// Create SMTP client
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return SMTPConnectResponse{
			Connected: false,
			LatencyMs: latency.Milliseconds(),
			Error: &SMTPError{
				Code:    "SMTP_CLIENT_FAILED",
				Message: err.Error(),
			},
		}
	}
	defer func() { _ = client.Quit() }()

	var tlsVersion string
	var tlsCipherSuite string
	var tlsServerName string

	// Upgrade to TLS if requested
	if useSTARTTLS {
		tlsConfig := cfg.tlsConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{
				ServerName: host, // Use original hostname for SNI, not resolved IP
				MinVersion: tls.VersionTLS12,
			}
		} else if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = host
		}

		if err := client.StartTLS(tlsConfig); err != nil {
			return SMTPConnectResponse{
				Connected: false,
				LatencyMs: latency.Milliseconds(),
				Error: &SMTPError{
					Code:    "STARTTLS_FAILED",
					Message: err.Error(),
				},
			}
		}

		// Get TLS version after STARTTLS
		state, ok := client.TLSConnectionState()
		if ok {
			tlsVersion = tlsVersionString(state.Version)
			tlsCipherSuite = tls.CipherSuiteName(state.CipherSuite)
			tlsServerName = state.ServerName
		}
	}

	return SMTPConnectResponse{
		Connected:      true,
		TLSVersion:     tlsVersion,
		TLSCipherSuite: tlsCipherSuite,
		TLSServerName:  tlsServerName,
		LatencyMs:      latency.Milliseconds(),
	}
}

func readBanner(conn net.Conn, timeout time.Duration) (string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

func classifySMTPError(err error) *SMTPError {
	msg := err.Error()
	code := "CONNECTION_FAILED"

	switch {
	case strings.Contains(msg, "timeout"):
		code = "TIMEOUT"
	case strings.Contains(msg, "refused"):
		code = "CONNECTION_REFUSED"
	case strings.Contains(msg, "no such host"):
		code = "HOST_NOT_FOUND"
	case strings.Contains(msg, "certificate"):
		code = "TLS_CERTIFICATE_ERROR"
	}

	return &SMTPError{
		Code:    code,
		Message: msg,
	}
}

func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return ""
	}
}
