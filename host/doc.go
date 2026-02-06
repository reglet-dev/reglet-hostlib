// Package host provides the runtime environment for executing Reglet WASM plugins.
//
// It abstracts the underlying WASM engine (wazero), manages plugin lifecycle,
// and handles the low-level ABI interactions (memory allocation, data packing/unpacking).
// This package also facilitates the registration of host functions, enabling plugins
// to securely access system capabilities exposed by the host.
package host
