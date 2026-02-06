package hostlib

import (
	"context"
)

// HostFuncBundle is a pre-configured set of related host functions.
// Bundles allow registering multiple handlers at once for common use cases.
type HostFuncBundle interface {
	// Handlers returns a map of handler names to ByteHandler functions.
	Handlers() map[string]ByteHandler
}

// staticBundle implements HostFuncBundle with a fixed set of handlers.
type staticBundle struct {
	handlers map[string]ByteHandler
}

func (b *staticBundle) Handlers() map[string]ByteHandler {
	return b.handlers
}

// NetworkBundle returns a bundle with network-related host functions:
// dns_lookup, tcp_connect, http_request.
func NetworkBundle() HostFuncBundle {
	return &staticBundle{
		handlers: map[string]ByteHandler{
			"dns_lookup": NewJSONHandler(func(ctx context.Context, req DNSLookupRequest) DNSLookupResponse { return PerformDNSLookup(ctx, req) }),
			"tcp_connect": NewJSONHandler(func(ctx context.Context, req TCPConnectRequest) TCPConnectResponse {
				return PerformTCPConnect(ctx, req)
			}),
			"http_request": NewJSONHandler(func(ctx context.Context, req HTTPRequest) HTTPResponse { return PerformHTTPRequest(ctx, req) }),
		},
	}
}

// ExecBundle returns a bundle with command execution host functions:
// exec_command.
func ExecBundle() HostFuncBundle {
	return &staticBundle{
		handlers: map[string]ByteHandler{
			"exec_command": NewJSONHandler(func(ctx context.Context, req ExecCommandRequest) ExecCommandResponse {
				return PerformExecCommand(ctx, req)
			}),
		},
	}
}

// SMTPBundle returns a bundle with email-related host functions:
// smtp_connect.
func SMTPBundle() HostFuncBundle {
	return &staticBundle{
		handlers: map[string]ByteHandler{
			"smtp_connect": NewJSONHandler(func(ctx context.Context, req SMTPConnectRequest) SMTPConnectResponse {
				return PerformSMTPConnect(ctx, req)
			}),
		},
	}
}

// SSRFCheckRequest is the request type for SSRF validation.
type SSRFCheckRequest struct {
	// Address is the target address to validate (host:port format).
	Address string `json:"address"`
}

// SSRFCheckResponse is the response type for SSRF validation.
type SSRFCheckResponse struct {
	// Reason explains why the address was blocked (if not allowed).
	Reason string `json:"reason,omitempty"`

	// ResolvedIP is the resolved IP address if DNS resolution was performed.
	ResolvedIP string `json:"resolved_ip,omitempty"`

	// Allowed indicates whether the address is safe for outbound connections.
	Allowed bool `json:"allowed"`
}

// NetfilterBundle returns a bundle with network security host functions:
// ssrf_check.
func NetfilterBundle() HostFuncBundle {
	return &staticBundle{
		handlers: map[string]ByteHandler{
			"ssrf_check": NewJSONHandler(func(ctx context.Context, req SSRFCheckRequest) SSRFCheckResponse {
				result := ValidateAddress(req.Address)
				return SSRFCheckResponse(result) // Type conversion since fields match
			}),
		},
	}
}

// compositeBundle combines multiple bundles into one.
type compositeBundle struct {
	bundles []HostFuncBundle
}

func (b *compositeBundle) Handlers() map[string]ByteHandler {
	result := make(map[string]ByteHandler)
	for _, bundle := range b.bundles {
		for name, handler := range bundle.Handlers() {
			result[name] = handler
		}
	}
	return result
}

// AllBundles returns a bundle containing all built-in host functions.
// Includes: dns_lookup, tcp_connect, http_request, exec_command, smtp_send, ssrf_check.
func AllBundles() HostFuncBundle {
	return &compositeBundle{
		bundles: []HostFuncBundle{
			NetworkBundle(),
			ExecBundle(),
			SMTPBundle(),
			NetfilterBundle(),
		},
	}
}

// WithBundle registers all handlers from a bundle.
func WithBundle(bundle HostFuncBundle) RegistryOption {
	return func(b *registryBuilder) {
		for name, handler := range bundle.Handlers() {
			if err := b.addHandler(name, handler); err != nil {
				b.errors = append(b.errors, err)
			}
		}
	}
}

// WithHandler registers a typed host function with automatic JSON handling.
// The handler will be wrapped with NewJSONHandler for JSON serialization.
//
// Example usage:
//
//	WithHandler("custom_func", func(ctx context.Context, req MyRequest) MyResponse {
//	    return MyResponse{Result: req.Input}
//	})
func WithHandler[Req any, Resp any](name string, fn HostFunc[Req, Resp]) RegistryOption {
	return func(b *registryBuilder) {
		handler := NewJSONHandler(fn)
		if err := b.addHandler(name, handler); err != nil {
			b.errors = append(b.errors, err)
		}
	}
}
