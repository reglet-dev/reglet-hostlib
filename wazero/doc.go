// Package wazero provides adapters for registering SDK host functions with the wazero runtime.
//
// This package bridges the SDK's pure Go host function implementations with the wazero
// WebAssembly runtime. It handles:
//
//   - Converting between packed i64 pointer+length format and byte slices
//   - Reading request data from guest memory
//   - Allocating and writing response data to guest memory
//   - Registering handlers with the wazero host module builder
//
// # Basic Usage
//
//	// Create a handler registry with desired bundles
//	registry, err := hostfuncs.NewRegistry(
//	    hostfuncs.WithBundle(hostfuncs.AllBundles()),
//	)
//	if err != nil {
//	    return err
//	}
//
//	// Create wazero runtime
//	runtime := wazero.NewRuntime(ctx)
//
//	// Register SDK handlers with the runtime
//	err = wazero.RegisterWithRuntime(ctx, runtime, registry,
//	    wazero.WithModuleName("reglet_host"),
//	)
//
// # Custom Handlers
//
// For handlers that don't fit the standard request/response pattern (like logging),
// use WithCustomHandler:
//
//	wazero.RegisterWithRuntime(ctx, runtime, registry,
//	    wazero.WithCustomHandler(wazero.CustomHandler{
//	        Name:        "log_message",
//	        Handler:     logMessageHandler,
//	        ParamTypes:  []api.ValueType{api.ValueTypeI64},
//	        ResultTypes: []api.ValueType{},
//	    }),
//	)
package wazero
