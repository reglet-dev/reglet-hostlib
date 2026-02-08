package hostlib

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/reglet-dev/reglet-host-sdk/netutil"
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

	// Check context for default SSRF protection based on capabilities
	if allowPrivate, ok := ctx.Value("ssrf_allow_private").(bool); ok {
		WithHTTPSSRFProtection(allowPrivate)(&cfg)
	}

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
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig:       netutil.TLSConfig(),
	}
	if cfg.ssrfProtection {
		dialer := &netutil.SecureDialer{
			AllowPrivateNetwork: cfg.allowPrivate,
			Timeout:             cfg.timeout,
		}
		transport.DialContext = dialer.DialContext
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
	case netutil.IsSSRFBlockedError(err):
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
	limitedReader := netutil.NewLimitedReader(resp.Body, maxBodySize)
	respBody, err := io.ReadAll(limitedReader)
	if err != nil {
		truncated := netutil.IsSizeLimitExceededError(err)
		if truncated {
			// Body was truncated at the limit
			return HTTPResponse{
				StatusCode:    resp.StatusCode,
				Headers:       resp.Header,
				Body:          respBody,
				BodyTruncated: true,
				LatencyMs:     latency.Milliseconds(),
				Proto:         resp.Proto,
			}
		}
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

	return HTTPResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       respBody,
		LatencyMs:  latency.Milliseconds(),
		Proto:      resp.Proto,
	}
}
