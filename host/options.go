package host

import hostlib "github.com/reglet-dev/reglet-host-sdk"

// Option defines a functional option for configuring the Executor.
type Option func(*Executor)

// WithHostFunctions configures the executor with a host function registry.
func WithHostFunctions(registry *hostlib.HandlerRegistry) Option {
	return func(e *Executor) {
		e.registry = registry
	}
}
