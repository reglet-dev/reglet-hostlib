package capability

import (
	"github.com/reglet-dev/reglet-abi/hostfunc"
)

// CapabilityInfo contains metadata about a capability request.
type CapabilityInfo struct {
	PluginName     string
	IsProfileBased bool
	IsBroad        bool
}

// Request represents a single capability request for prompting constraints.
type Request struct {
	Rule        interface{}
	Kind        string
	Description string
	IsBroad     bool
}

// Requirement represents a request for capabilities by a plugin.
type Requirement struct {
	Requested  *hostfunc.GrantSet
	PluginName string
}

// Grant represents the actual capabilities granted to a plugin after policy enforcement.
type Grant struct {
	Granted    *hostfunc.GrantSet
	PluginName string
}

// GatekeeperPort grants capabilities based on security policy.
type GatekeeperPort interface {
	GrantCapabilities(
		required *hostfunc.GrantSet,
		capabilityInfo map[string]CapabilityInfo,
		trustAll bool,
	) (*hostfunc.GrantSet, error)
}

// GrantStore persists and retrieves granted capabilities.
type GrantStore interface {
	Load() (*hostfunc.GrantSet, error)
	Save(grants *hostfunc.GrantSet) error
	ConfigPath() string
}

// Prompter handles interactive capability authorization.
type Prompter interface {
	IsInteractive() bool
	PromptForCapability(req Request) (granted bool, always bool, err error)
	PromptForCapabilities(reqs []Request) (*hostfunc.GrantSet, error)
	FormatNonInteractiveError(missing *hostfunc.GrantSet) error
}
