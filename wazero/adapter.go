// Package wazero provides adapters for registering SDK host functions with the wazero runtime.
package wazero

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/reglet-dev/reglet-abi/hostfunc"
	hostlib "github.com/reglet-dev/reglet-host-sdk"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// AdapterConfig holds configuration for the wazero adapter.
type AdapterConfig struct {
	// ModuleName is the host module name (default: "reglet_host").
	ModuleName string

	// CustomHandlers allows adding additional wazero-specific handlers that
	// don't fit the standard ByteHandler pattern (e.g., log_message with no return).
	CustomHandlers []CustomHandler

	// MaxRequestSize limits the size of incoming requests from guest memory.
	// Default is 1MB.
	MaxRequestSize uint32
}

// CustomHandler represents a custom wazero handler that doesn't use the standard
// packed i64 request/response pattern.
type CustomHandler struct {
	// Name is the exported function name.
	Name string

	// Handler is the wazero GoModuleFunc implementation.
	Handler api.GoModuleFunc

	// ParamTypes are the WASM parameter types.
	ParamTypes []api.ValueType

	// ResultTypes are the WASM result types.
	ResultTypes []api.ValueType
}

// AdapterOption configures the adapter.
type AdapterOption func(*AdapterConfig)

// WithModuleName sets the host module name (default: "reglet_host").
func WithModuleName(name string) AdapterOption {
	return func(c *AdapterConfig) {
		c.ModuleName = name
	}
}

// WithMaxRequestSize sets the maximum request size from guest memory.
func WithMaxRequestSize(size uint32) AdapterOption {
	return func(c *AdapterConfig) {
		c.MaxRequestSize = size
	}
}

// WithCustomHandler adds a custom wazero handler.
func WithCustomHandler(h CustomHandler) AdapterOption {
	return func(c *AdapterConfig) {
		c.CustomHandlers = append(c.CustomHandlers, h)
	}
}

// defaultAdapterConfig returns the default adapter configuration.
func defaultAdapterConfig() AdapterConfig {
	return AdapterConfig{
		ModuleName:     "reglet_host",
		MaxRequestSize: hostlib.DefaultMaxRequestSize,
	}
}

// RegisterWithRuntime registers all handlers from a HandlerRegistry with a wazero runtime.
// This creates a host module with the configured name (default: "reglet_host") and
// exports all handlers from the registry.
//
// Each handler is wrapped to:
//   - Read request bytes from guest memory using the packed i64 ptr+len format
//   - Invoke the ByteHandler with the request payload
//   - Allocate response memory in the guest using the "allocate" export
//   - Write response bytes to guest memory
//   - Return packed i64 ptr+len of the response
//
// Example:
//
//	registry, _ := hostlib.NewRegistry(
//	    hostlib.WithBundle(hostlib.AllBundles()),
//	)
//	err := wazero.RegisterWithRuntime(ctx, runtime, registry,
//	    wazero.WithModuleName("reglet_host"),
//	)
func RegisterWithRuntime(ctx context.Context, runtime wazero.Runtime, registry *hostlib.HandlerRegistry, opts ...AdapterOption) error {
	cfg := defaultAdapterConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	builder := runtime.NewHostModuleBuilder(cfg.ModuleName)

	// Register all handlers from the registry
	for _, name := range registry.Names() {
		funcName := name // capture for closure
		builder.NewFunctionBuilder().
			WithGoModuleFunction(api.GoModuleFunc(func(ctx context.Context, mod api.Module, stack []uint64) {
				HandleRegistryCall(ctx, mod, stack, registry, funcName, cfg.MaxRequestSize)
			}), []api.ValueType{api.ValueTypeI64}, []api.ValueType{api.ValueTypeI64}).
			Export(funcName)
	}

	// Register any custom handlers
	for _, ch := range cfg.CustomHandlers {
		builder.NewFunctionBuilder().
			WithGoModuleFunction(ch.Handler, ch.ParamTypes, ch.ResultTypes).
			Export(ch.Name)
	}

	// Instantiate the host module
	_, err := builder.Instantiate(ctx)
	return err
}

// HandleRegistryCall handles a host function call from WASM.
// It reads the request from guest memory, invokes the handler, and writes the response.
func HandleRegistryCall(ctx context.Context, mod api.Module, stack []uint64, registry *hostlib.HandlerRegistry, name string, maxRequestSize uint32) {
	// Unpack the request pointer and length
	ptr, length := UnpackPtrLen(stack[0])

	// Validate request size
	if length > maxRequestSize {
		errMsg := fmt.Sprintf("request size %d exceeds maximum %d bytes", length, maxRequestSize)
		slog.ErrorContext(ctx, "wazero: "+errMsg, "function", name)
		stack[0] = WriteErrorResponse(ctx, mod, hostlib.NewValidationError(errMsg))
		return
	}

	// Read request bytes from guest memory
	requestBytes, ok := mod.Memory().Read(ptr, length)
	if !ok {
		errMsg := "failed to read request from guest memory"
		slog.ErrorContext(ctx, "wazero: "+errMsg, "function", name)
		stack[0] = WriteErrorResponse(ctx, mod, hostlib.NewInternalError(errMsg))
		return
	}

	// Invoke the handler
	responseBytes, err := registry.Invoke(ctx, name, requestBytes)
	if err != nil {
		slog.ErrorContext(ctx, "wazero: handler invocation failed", "function", name, "error", err)
		stack[0] = WriteErrorResponse(ctx, mod, hostlib.NewInternalError(err.Error()))
		return
	}

	// Write response to guest memory
	stack[0] = WriteResponse(ctx, mod, responseBytes)
}

// WriteResponse allocates memory in the guest and writes the response bytes.
// Returns packed ptr+len or 0 on failure.
func WriteResponse(ctx context.Context, mod api.Module, data []byte) uint64 {
	// Call the guest's allocate function
	allocateFn := mod.ExportedFunction("allocate")
	if allocateFn == nil {
		slog.ErrorContext(ctx, "wazero: guest module missing 'allocate' export")
		return 0
	}

	results, err := allocateFn.Call(ctx, uint64(len(data)))
	if err != nil {
		slog.ErrorContext(ctx, "wazero: failed to call guest allocate", "error", err)
		return 0
	}
	ptr := uint32(results[0]) //nolint:gosec // G115: WASM32 pointers are always 32-bit

	// Write data to guest memory
	if !mod.Memory().Write(ptr, data) {
		slog.ErrorContext(ctx, "wazero: failed to write response to guest memory")
		return 0
	}

	return PackPtrLen(ptr, uint32(len(data))) //nolint:gosec // G115: Data length is bounded by config
}

// WriteErrorResponse writes an error response to guest memory.
func WriteErrorResponse(ctx context.Context, mod api.Module, errResp hostlib.ErrorResponse) uint64 {
	return WriteResponse(ctx, mod, errResp.ToJSON())
}

// PackPtrLen packs a pointer and length into a single i64.
// Upper 32 bits: pointer, lower 32 bits: length.
func PackPtrLen(ptr, length uint32) uint64 {
	return (uint64(ptr) << 32) | uint64(length)
}

// UnpackPtrLen unpacks a pointer and length from a packed i64.
func UnpackPtrLen(packed uint64) (ptr, length uint32) {
	ptr = uint32(packed >> 32)           //nolint:gosec // G115: Packed format stores 32-bit values
	length = uint32(packed & 0xFFFFFFFF) //nolint:gosec // G115: Packed format stores 32-bit values
	return ptr, length
}

// CreateContextFromWire creates a new context from the wire format.
func CreateContextFromWire(parentCtx context.Context, wireCtx hostfunc.ContextWire) (context.Context, context.CancelFunc) {
	if wireCtx.Canceled {
		slog.Warn("wazero: received already canceled context from plugin")
		ctx, cancel := context.WithCancel(parentCtx)
		cancel() // Immediately cancel
		return ctx, cancel
	}

	// Apply deadline if present
	if wireCtx.Deadline != nil && !wireCtx.Deadline.IsZero() {
		return context.WithDeadline(parentCtx, *wireCtx.Deadline)
	}

	// Apply timeout if present
	if wireCtx.TimeoutMs > 0 {
		return context.WithTimeout(parentCtx, time.Duration(wireCtx.TimeoutMs)*time.Millisecond)
	}

	return context.WithCancel(parentCtx) // Default to cancellable context
}
