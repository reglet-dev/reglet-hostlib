package host

import (
	hostlib "github.com/reglet-dev/reglet-host-sdk"
	"github.com/tetratelabs/wazero"
)

// Option defines a functional option for configuring the Executor.
type Option func(*Executor)

// WithHostFunctions configures the executor with a host function registry.
func WithHostFunctions(registry *hostlib.HandlerRegistry) Option {
	return func(e *Executor) {
		e.registry = registry
	}
}

// WithVerbose enables or disables verbose logging from the WASM runtime and plugins.
func WithVerbose(verbose bool) Option {
	return func(e *Executor) {
		e.verbose = verbose
	}
}

// WithCompilationCache configures the executor with a compilation cache.
func WithCompilationCache(cache wazero.CompilationCache) Option {
	return func(e *Executor) {
		e.cache = cache
	}
}
