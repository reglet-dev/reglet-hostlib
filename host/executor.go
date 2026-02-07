// Package host provides the WASM host runtime for Reglet plugins.
package host

import (
	"context"
	"encoding/json"
	"fmt"
	"os" // Added for fmt.Fprintf to stderr

	abi "github.com/reglet-dev/reglet-abi"
	hostlib "github.com/reglet-dev/reglet-host-sdk"
	"github.com/reglet-dev/reglet-host-sdk/wazero"
	t_wazero "github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// Executor manages the lifecycle of a WASM plugin.
type Executor struct {
	runtime  t_wazero.Runtime
	registry *hostlib.HandlerRegistry
}

// NewExecutor creates a new executor with the given options.
func NewExecutor(ctx context.Context, opts ...Option) (*Executor, error) {
	e := &Executor{}
	for _, opt := range opts {
		opt(e)
	}

	// Default registry if not provided
	if e.registry == nil {
		reg, err := hostlib.NewRegistry()
		if err != nil {
			return nil, fmt.Errorf("failed to create default registry: %w", err)
		}
		e.registry = reg
	}

	rt := t_wazero.NewRuntime(ctx)
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	e.runtime = rt

	if err := e.registerHostFunctions(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("failed to register host functions: %w", err)
	}

	return e, nil
}

// registerHostFunctions registers the host functions with the runtime.
func (e *Executor) registerHostFunctions(ctx context.Context) error {
	logHandler := wazero.CustomHandler{
		Name:        "log_message",
		ParamTypes:  []api.ValueType{api.ValueTypeI64},
		ResultTypes: []api.ValueType{},
		Handler: api.GoModuleFunc(func(ctx context.Context, m api.Module, stack []uint64) {
			packed := stack[0]
			//nolint:gosec // WASM pointers are 32-bit
			ptr := uint32(packed >> 32)
			//nolint:gosec // WASM lengths are 32-bit
			length := uint32(packed)
			payload, ok := m.Memory().Read(ptr, length)
			if !ok {
				fmt.Fprintf(os.Stderr, "host: failed to read log message from WASM memory at ptr=%d, len=%d\n", ptr, length)
				return
			}

			var logMsg struct {
				Level   string `json:"level"`
				Message string `json:"message"`
			}
			if err := json.Unmarshal(payload, &logMsg); err != nil {
				fmt.Fprintf(os.Stderr, "host: failed to unmarshal log message: %v, payload: %s\n", err, string(payload))
				return
			}

			// For now, print to stderr. In a real scenario, this would integrate with a logger.
			fmt.Fprintf(os.Stderr, "WASM Log [%s]: %s\n", logMsg.Level, logMsg.Message)
		}),
	}

	// Use the adapter to register both registry functions and our custom handler
	return wazero.RegisterWithRuntime(ctx, e.runtime, e.registry,
		wazero.WithCustomHandler(logHandler),
	)
}

// Close releases resources held by the executor.
func (e *Executor) Close(ctx context.Context) error {
	return e.runtime.Close(ctx)
}

// PluginInstance represents an instantiated WASM plugin.
type PluginInstance struct {
	module api.Module
}

// LoadPlugin instantiates a WASM module.
func (e *Executor) LoadPlugin(ctx context.Context, wasmBytes []byte) (*PluginInstance, error) {
	mod, err := e.runtime.Instantiate(ctx, wasmBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate module: %w", err)
	}

	// Initialize if needed (though Instantiate usually handles start)
	if init := mod.ExportedFunction("_initialize"); init != nil {
		if _, err := init.Call(ctx); err != nil {
			return nil, fmt.Errorf("failed to call _initialize: %w", err)
		}
	}

	return &PluginInstance{module: mod}, nil
}

// Manifest returns the plugin manifest.
func (p *PluginInstance) Manifest(ctx context.Context) (abi.Manifest, error) {
	var manifest abi.Manifest
	packed, err := p.callRaw(ctx, "manifest", nil)
	if err != nil {
		return manifest, err
	}
	err = p.unmarshalPacked(packed, &manifest)
	return manifest, err
}

// Schema calls the "schema" export of the plugin.
func (p *PluginInstance) Schema(ctx context.Context) ([]byte, error) {
	packed, err := p.callRaw(ctx, "schema", nil)
	if err != nil {
		return nil, err
	}
	//nolint:gosec // WASM pointers are always 32-bit
	ptr := uint32(packed >> 32)
	//nolint:gosec // WASM lengths are always 32-bit
	length := uint32(packed)
	data, ok := p.module.Memory().Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("failed to read schema from memory")
	}
	// Copy data to avoid memory issues if wasm memory changes, though here it's read immediately
	schemaCopy := make([]byte, length)
	copy(schemaCopy, data)
	return schemaCopy, nil
}

// Check calls the "observe" export of the plugin.
func (p *PluginInstance) Check(ctx context.Context, config map[string]any) (abi.Result, error) {
	configBytes, err := json.Marshal(config)
	if err != nil {
		return abi.Result{}, err
	}

	packed, err := p.callRaw(ctx, "observe", configBytes)
	if err != nil {
		return abi.Result{}, err
	}

	var result abi.Result
	err = p.unmarshalPacked(packed, &result)
	return result, err
}

// callRaw invokes a plugin function with raw bytes.
func (p *PluginInstance) callRaw(ctx context.Context, name string, input []byte) (uint64, error) {
	fn := p.module.ExportedFunction(name)
	if fn == nil {
		return 0, fmt.Errorf("function %q not found", name)
	}

	// Allocate memory for input if needed
	var ptr uint64
	var length uint64
	if len(input) > 0 {
		allocate := p.module.ExportedFunction("allocate")
		if allocate == nil {
			return 0, fmt.Errorf("function 'allocate' not exported")
		}
		res, err := allocate.Call(ctx, uint64(len(input)))
		if err != nil {
			return 0, fmt.Errorf("allocate failed: %w", err)
		}
		ptr = res[0]
		length = uint64(len(input))

		if !p.module.Memory().Write(uint32(ptr), input) {
			return 0, fmt.Errorf("failed to write input to memory")
		}
	}

	// Pack ptr and length
	packedInput := (ptr << 32) | length

	// Call function
	res, err := fn.Call(ctx, packedInput)
	if err != nil {
		return 0, fmt.Errorf("call failed: %w", err)
	}

	return res[0], nil
}

// unmarshalPacked reads JSON from packed ptr+len and unmarshals it.
func (p *PluginInstance) unmarshalPacked(packed uint64, v any) error {
	ptr := uint32(packed >> 32)
	length := uint32(packed)

	if length == 0 {
		return nil
	}

	data, ok := p.module.Memory().Read(ptr, length)
	if !ok {
		return fmt.Errorf("failed to read result from memory")
	}

	return json.Unmarshal(data, v)
}
