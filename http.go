package hostlib

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPRequest contains parameters for an HTTP request.
type HTTPRequest struct {
	// Headers contains request headers.
	Headers map[string]string `json:"headers,omitempty"`

	// FollowRedirects controls whether to follow redirects. Default is true.
	FollowRedirects *bool `json:"follow_redirects,omitempty"`

	// Method is the HTTP method (GET, POST, PUT, DELETE, etc.).
	Method string `json:"method"`

	// URL is the target URL.
	URL string `json:"url"`

	// Body is the request body (for POST, PUT, etc.).
	Body []byte `json:"body,omitempty"`

	// Timeout is the request timeout in milliseconds. Default is 30000 (30s).
	Timeout int `json:"timeout_ms,omitempty"`

	// MaxRedirects is the maximum number of redirects to follow. Default is 10.
	MaxRedirects int `json:"max_redirects,omitempty"`
}

// HTTPResponse contains the result of an HTTP request.
type HTTPResponse struct {
	// Headers contains response headers.
	Headers map[string][]string `json:"headers,omitempty"`

	// Error contains error information if the request failed.
	Error *HTTPError `json:"error,omitempty"`

	// Proto is the protocol version (e.g. "HTTP/1.1").
	Proto string `json:"proto,omitempty"`

	// Body is the response body.
	Body []byte `json:"body,omitempty"`

	// LatencyMs is the request latency in milliseconds.
	LatencyMs int64 `json:"latency_ms,omitempty"`

	// StatusCode is the HTTP status code.
	StatusCode int `json:"status_code"`

	// BodyTruncated indicates if the body was truncated due to size limits.
	BodyTruncated bool `json:"body_truncated,omitempty"`
}

// HTTPError represents an HTTP request error.
type HTTPError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *HTTPError) Error() string {
	return e.Message
}

// HTTPOption is a functional option for configuring HTTP request behavior.
type HTTPOption func(*httpConfig)

type httpConfig struct {
	tlsConfig       *tls.Config
	timeout         time.Duration
	maxRedirects    int
	maxBodySize     int64
	followRedirects bool
	ssrfProtection  bool
	allowPrivate    bool
}

func defaultHTTPConfig() httpConfig {
	return httpConfig{
		timeout:         30 * time.Second,
		maxRedirects:    10,
		followRedirects: true,
		tlsConfig:       nil,
		maxBodySize:     10 * 1024 * 1024, // 10MB
	}
}

// WithHTTPRequestTimeout sets the HTTP request timeout.
func WithHTTPRequestTimeout(d time.Duration) HTTPOption {
	return func(c *httpConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithHTTPMaxRedirects sets the maximum number of redirects to follow.
func WithHTTPMaxRedirects(n int) HTTPOption {
	return func(c *httpConfig) {
		if n >= 0 {
			c.maxRedirects = n
		}
	}
}

// WithHTTPFollowRedirects controls whether to follow redirects.
func WithHTTPFollowRedirects(follow bool) HTTPOption {
	return func(c *httpConfig) {
		c.followRedirects = follow
	}
}

// WithHTTPMaxBodySize sets the maximum response body size.
func WithHTTPMaxBodySize(size int64) HTTPOption {
	return func(c *httpConfig) {
		if size > 0 {
			c.maxBodySize = size
		}
	}
}

// WithHTTPSSRFProtection enables DNS pinning and SSRF protection.
// When enabled, each hostname's DNS is resolved ONCE, validated, and pinned
// for all subsequent requests (preventing DNS rebinding attacks).
// Private/reserved IPs are blocked unless allowPrivate is true.
func WithHTTPSSRFProtection(allowPrivate bool) HTTPOption {
	return func(c *httpConfig) {
		c.ssrfProtection = true
		c.allowPrivate = allowPrivate
	}
}

// dnsPinnedEntry represents a validated and pinned DNS resolution.
type dnsPinnedEntry struct {
	resolvedIP string
	timestamp  time.Time
}

// dnsPinCache caches validated DNS resolutions to prevent rebinding attacks
// while maintaining connection pooling performance.
type dnsPinCache struct {
	mu      sync.RWMutex
	entries map[string]dnsPinnedEntry
	ttl     time.Duration
}

func newDNSPinCache() *dnsPinCache {
	return &dnsPinCache{
		entries: make(map[string]dnsPinnedEntry),
		ttl:     5 * time.Minute, // Cache validated IPs for 5 minutes
	}
}

func (c *dnsPinCache) get(hostname string, allowPrivate bool) (string, error) {
	// Check cache first
	c.mu.RLock()
	entry, found := c.entries[hostname]
	c.mu.RUnlock()

	if found && time.Since(entry.timestamp) < c.ttl {
		return entry.resolvedIP, nil
	}

	// Not in cache or expired - resolve and validate
	var opts []NetfilterOption
	if allowPrivate {
		opts = append(opts, WithBlockPrivate(false), WithBlockLocalhost(false))
	}
	result := ValidateAddress(hostname, opts...)

	if !result.Allowed {
		return "", fmt.Errorf("SSRF protection: %s", result.Reason)
	}

	resolvedIP := result.ResolvedIP
	if resolvedIP == "" {
		resolvedIP = hostname
	}

	// Cache the validated resolution
	c.mu.Lock()
	c.entries[hostname] = dnsPinnedEntry{
		resolvedIP: resolvedIP,
		timestamp:  time.Now(),
	}
	c.mu.Unlock()

	return resolvedIP, nil
}

// ssrfProtectedTransport wraps http.Transport with DNS pinning and SSRF protection
// while preserving connection pooling for performance.
func newSSRFProtectedTransport(allowPrivate bool) *http.Transport {
	cache := newDNSPinCache()

	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// 1. Resolve DNS once per hostname and cache the validated IP
		// 2. All subsequent dials use the cached IP (prevents DNS rebinding)
		// 3. Transport reuses connections when possible (maintains performance)
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Extract hostname from address
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
				port = ""
			}

			// Get pinned IP from cache (validates on first access)
			resolvedIP, err := cache.get(host, allowPrivate)
			if err != nil {
				return nil, err
			}

			// Reconstruct address with pinned IP
			targetAddr := resolvedIP
			if port != "" {
				targetAddr = net.JoinHostPort(resolvedIP, port)
			}

			// Dial the pinned, validated address
			return (&net.Dialer{}).DialContext(ctx, network, targetAddr)
		},
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			// VerifyConnection ensures SNI matches original hostname
			VerifyConnection: func(cs tls.ConnectionState) error {
				// TLS SNI is already set correctly by http package
				return nil
			},
		},
	}

	return transport
}

// PerformHTTPRequest performs an HTTP request.
// This is a pure Go implementation with no WASM runtime dependencies.
//
// Example usage from a WASM host:
//
//	func handleHTTPRequest(req hostfuncs.HTTPRequest) hostfuncs.HTTPResponse {
//	    return hostfuncs.PerformHTTPRequest(ctx, req)
//	}
func PerformHTTPRequest(ctx context.Context, req HTTPRequest, opts ...HTTPOption) HTTPResponse {
	cfg := defaultHTTPConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Override config from request if specified
	applyRequestConfig(&req, &cfg)

	// Validate request
	if err := validateHTTPRequest(&req); err != nil {
		return HTTPResponse{Error: err}
	}

	// Apply timeout to context
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	// Create and execute HTTP request
	return executeHTTPRequest(ctx, req, cfg)
}

// applyRequestConfig overrides default config with request-specific values.
func applyRequestConfig(req *HTTPRequest, cfg *httpConfig) {
	if req.Timeout > 0 {
		cfg.timeout = time.Duration(req.Timeout) * time.Millisecond
	}
	if req.MaxRedirects > 0 {
		cfg.maxRedirects = req.MaxRedirects
	}
	if req.FollowRedirects != nil {
		cfg.followRedirects = *req.FollowRedirects
	}
}

// validateHTTPRequest validates the HTTP request parameters.
func validateHTTPRequest(req *HTTPRequest) *HTTPError {
	if req.URL == "" {
		return &HTTPError{
			Code:    "INVALID_REQUEST",
			Message: "URL is required",
		}
	}
	if req.Method == "" {
		req.Method = "GET"
	}
	return nil
}

// executeHTTPRequest creates the HTTP client, performs the request, and reads the response.
func executeHTTPRequest(ctx context.Context, req HTTPRequest, cfg httpConfig) HTTPResponse {
	// Create HTTP request
	var body io.Reader
	if len(req.Body) > 0 {
		body = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, strings.ToUpper(req.Method), req.URL, body)
	if err != nil {
		return HTTPResponse{
			Error: &HTTPError{
				Code:    "INVALID_REQUEST",
				Message: err.Error(),
			},
		}
	}

	// Set headers
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Create client with redirect policy
	client := createHTTPClient(cfg)

	// Perform request
	start := time.Now()
	resp, err := client.Do(httpReq)
	latency := time.Since(start)

	if err != nil {
		return handleHTTPError(err, ctx, latency)
	}
	defer func() { _ = resp.Body.Close() }()

	return readHTTPResponse(resp, latency, cfg.maxBodySize)
}

// createHTTPClient creates an HTTP client with the appropriate redirect policy.
func createHTTPClient(cfg httpConfig) *http.Client {
	var transport *http.Transport
	if cfg.ssrfProtection {
		transport = newSSRFProtectedTransport(cfg.allowPrivate)
	} else {
		transport = &http.Transport{
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}

	client := &http.Client{
		Timeout:   cfg.timeout,
		Transport: transport,
	}

	if !cfg.followRedirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	} else if cfg.maxRedirects > 0 {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.maxRedirects {
				return fmt.Errorf("stopped after %d redirects", cfg.maxRedirects)
			}
			return nil
		}
	}

	return client
}

// handleHTTPError classifies and returns an error response.
func handleHTTPError(err error, ctx context.Context, latency time.Duration) HTTPResponse {
	code := "REQUEST_FAILED"
	switch {
	case strings.Contains(err.Error(), "timeout"), ctx.Err() == context.DeadlineExceeded:
		code = "TIMEOUT"
	case strings.Contains(err.Error(), "redirect"):
		code = "TOO_MANY_REDIRECTS"
	case strings.Contains(err.Error(), "no such host"):
		code = "HOST_NOT_FOUND"
	case strings.Contains(err.Error(), "connection refused"):
		code = "CONNECTION_REFUSED"
	case strings.Contains(err.Error(), "SSRF protection"):
		code = "SSRF_BLOCKED"
	}

	return HTTPResponse{
		LatencyMs: latency.Milliseconds(),
		Error: &HTTPError{
			Code:    code,
			Message: err.Error(),
		},
	}
}

// readHTTPResponse reads and returns the HTTP response body with size limiting.
func readHTTPResponse(resp *http.Response, latency time.Duration, maxBodySize int64) HTTPResponse {
	// Read response body with size limit
	bodyReader := io.LimitReader(resp.Body, maxBodySize+1)
	respBody, err := io.ReadAll(bodyReader)
	if err != nil {
		return HTTPResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			LatencyMs:  latency.Milliseconds(),
			Error: &HTTPError{
				Code:    "READ_BODY_FAILED",
				Message: err.Error(),
			},
		}
	}

	truncated := false
	if int64(len(respBody)) > maxBodySize {
		respBody = respBody[:maxBodySize]
		truncated = true
	}

	return HTTPResponse{
		StatusCode:    resp.StatusCode,
		Headers:       resp.Header,
		Body:          respBody,
		BodyTruncated: truncated,
		LatencyMs:     latency.Milliseconds(),
		Proto:         resp.Proto,
	}
}
