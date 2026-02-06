package policy

import "github.com/reglet-dev/reglet-abi/hostfunc"

// Policy enforces capability grants against runtime requests.
type Policy interface {
	CheckNetwork(req hostfunc.NetworkRequest, grants *hostfunc.GrantSet) bool
	CheckFileSystem(req hostfunc.FileSystemRequest, grants *hostfunc.GrantSet) bool
	CheckEnvironment(req hostfunc.EnvironmentRequest, grants *hostfunc.GrantSet) bool
	CheckExec(req hostfunc.ExecCapabilityRequest, grants *hostfunc.GrantSet) bool
	CheckKeyValue(req hostfunc.KeyValueRequest, grants *hostfunc.GrantSet) bool

	// Evaluate methods return the decision without side effects (like logging denials).
	EvaluateNetwork(req hostfunc.NetworkRequest, grants *hostfunc.GrantSet) bool
	EvaluateFileSystem(req hostfunc.FileSystemRequest, grants *hostfunc.GrantSet) bool
	EvaluateEnvironment(req hostfunc.EnvironmentRequest, grants *hostfunc.GrantSet) bool
	EvaluateExec(req hostfunc.ExecCapabilityRequest, grants *hostfunc.GrantSet) bool
	EvaluateKeyValue(req hostfunc.KeyValueRequest, grants *hostfunc.GrantSet) bool
}

// DenialHandler is called when a policy check denies a request.
type DenialHandler interface {
	// OnDenial is called when a capability request is denied.
	OnDenial(kind string, request interface{}, reason string)
}
