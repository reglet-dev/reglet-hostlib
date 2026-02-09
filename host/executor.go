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
	verbose  bool
	cache    t_wazero.CompilationCache
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

	config := t_wazero.NewRuntimeConfig()
	if e.cache != nil {
		config = config.WithCompilationCache(e.cache)
	}

	rt := t_wazero.NewRuntimeWithConfig(ctx, config)
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
			if e.verbose {
				fmt.Fprintf(os.Stderr, "WASM Log [%s]: %s\n", logMsg.Level, logMsg.Message)
			}
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
	fn := p.module.ExportedFunction("_manifest")
	if fn == nil {
		return abi.Manifest{}, fmt.Errorf("function \"_manifest\" not found")
	}

	res, err := fn.Call(ctx)
	if err != nil {
		return abi.Manifest{}, fmt.Errorf("calling _manifest: %w", err)
	}

	if len(res) == 0 {
		return abi.Manifest{}, fmt.Errorf("_manifest returned no results")
	}

	var manifest abi.Manifest
	err = p.unmarshalPacked(res[0], &manifest)
	return manifest, err
}

// Schema calls the "_schema" export of the plugin.
func (p *PluginInstance) Schema(ctx context.Context) ([]byte, error) {
	fn := p.module.ExportedFunction("_schema")
	if fn == nil {
		// Fallback for older plugins
		fn = p.module.ExportedFunction("schema")
	}
	if fn == nil {
		return nil, fmt.Errorf("schema function not found")
	}

	res, err := fn.Call(ctx)
	if err != nil {
		return nil, fmt.Errorf("calling schema: %w", err)
	}

	if len(res) == 0 {
		return nil, fmt.Errorf("schema returned no results")
	}

	packed := res[0]
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

// Check calls the "_observe" export of the plugin.
func (p *PluginInstance) Check(ctx context.Context, config map[string]any) (abi.Result, error) {
	configBytes, err := json.Marshal(config)
	if err != nil {
		return abi.Result{}, err
	}

	fn := p.module.ExportedFunction("_observe")
	if fn == nil {
		return abi.Result{}, fmt.Errorf("function \"_observe\" not found")
	}

	// Allocate memory for config
	allocate := p.module.ExportedFunction("allocate")
	if allocate == nil {
		return abi.Result{}, fmt.Errorf("function 'allocate' not exported")
	}
	ares, err := allocate.Call(ctx, uint64(len(configBytes)))
	if err != nil {
		return abi.Result{}, fmt.Errorf("allocate failed: %w", err)
	}
	ptr := ares[0]

	if !p.module.Memory().Write(uint32(ptr), configBytes) {
		return abi.Result{}, fmt.Errorf("failed to write input to memory")
	}

	// Call _observe(ptr, len)
	res, err := fn.Call(ctx, ptr, uint64(len(configBytes)))
	if err != nil {
		return abi.Result{}, fmt.Errorf("calling _observe: %w", err)
	}

	if len(res) == 0 {
		return abi.Result{}, fmt.Errorf("_observe returned no results")
	}

	var result abi.Result
	err = p.unmarshalPacked(res[0], &result)
	return result, err
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
