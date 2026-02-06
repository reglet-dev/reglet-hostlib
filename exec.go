package hostlib

import (
	"context"
	"errors"
	"log/slog"
	"os/exec"
	"time"
)

// ExecCommandRequest contains parameters for a command execution.
type ExecCommandRequest struct {
	// Command is the command to execute.
	Command string `json:"command"`

	// Args contains command arguments.
	Args []string `json:"args"`

	// Dir is the working directory.
	Dir string `json:"dir,omitempty"`

	// Env contains environment variables (KEY=VALUE).
	Env []string `json:"env,omitempty"`

	// Timeout is the execution timeout in milliseconds. Default is 30000 (30s).
	Timeout int `json:"timeout_ms,omitempty"`
}

// ExecCommandResponse contains the result of a command execution.
type ExecCommandResponse struct {
	// Error contains error information if execution failed to start.
	Error *ExecError `json:"error,omitempty"`

	// Stdout is the standard output.
	Stdout string `json:"stdout"`

	// Stderr is the standard error.
	Stderr string `json:"stderr"`

	// DurationMs is the execution duration in milliseconds.
	DurationMs int64 `json:"duration_ms,omitempty"`

	// ExitCode is the exit code.
	ExitCode int `json:"exit_code"`

	// IsTimeout indicates if the command timed out.
	IsTimeout bool `json:"is_timeout,omitempty"`

	// StdoutTruncated indicates if stdout was truncated due to size limits.
	StdoutTruncated bool `json:"stdout_truncated,omitempty"`

	// StderrTruncated indicates if stderr was truncated due to size limits.
	StderrTruncated bool `json:"stderr_truncated,omitempty"`
}

// ExecError represents an execution error.
type ExecError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (e *ExecError) Error() string {
	return e.Message
}

// ExecOption is a functional option for configuring execution behavior.
type ExecOption func(*execConfig)

type execConfig struct {
	capabilityCheck CapabilityGetter
	pluginName      string
	timeout         time.Duration
	maxOutputSize   int
	sanitizeEnv     bool
	isolateEnv      bool
}

func defaultExecConfig() execConfig {
	return execConfig{
		timeout:       30 * time.Second,
		maxOutputSize: DefaultMaxOutputSize,
		sanitizeEnv:   false,
		isolateEnv:    false,
	}
}

// WithExecTimeout sets the execution timeout.
func WithExecTimeout(d time.Duration) ExecOption {
	return func(c *execConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithMaxOutputSize sets the maximum output size for stdout/stderr.
// If output exceeds this size, it will be truncated.
func WithMaxOutputSize(size int) ExecOption {
	return func(c *execConfig) {
		if size > 0 {
			c.maxOutputSize = size
		}
	}
}

// WithEnvSanitization enables environment variable sanitization.
// This blocks dangerous environment variables like LD_PRELOAD and
// requires explicit capabilities for sensitive variables like PATH.
func WithEnvSanitization(pluginName string, capGetter CapabilityGetter) ExecOption {
	return func(c *execConfig) {
		c.sanitizeEnv = true
		c.pluginName = pluginName
		c.capabilityCheck = capGetter
	}
}

// WithIsolatedEnv ensures the command runs with only explicitly provided
// environment variables, preventing host environment leakage.
func WithIsolatedEnv() ExecOption {
	return func(c *execConfig) {
		c.isolateEnv = true
	}
}

// PerformExecCommand executes a command on the host.
// This is a pure Go implementation with no WASM runtime dependencies.
//
// SECURITY: By default, commands run with an isolated environment (empty env).
// This prevents leaking host credentials to executed commands.
//
// Security features can be enabled via options:
//   - WithEnvSanitization: blocks dangerous environment variables
//   - WithMaxOutputSize: limits output to prevent OOM
func PerformExecCommand(ctx context.Context, req ExecCommandRequest, opts ...ExecOption) ExecCommandResponse {
	cfg := defaultExecConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if req.Timeout > 0 {
		cfg.timeout = time.Duration(req.Timeout) * time.Millisecond
	}

	// Validate request
	if req.Command == "" {
		return ExecCommandResponse{
			Error: &ExecError{
				Code:    "INVALID_REQUEST",
				Message: "command is required",
			},
		}
	}

	// Apply environment sanitization if enabled
	env := req.Env
	if cfg.sanitizeEnv {
		env = SanitizeEnv(ctx, env, cfg.pluginName, cfg.capabilityCheck)
	}

	// Apply timeout to context
	execCtx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	//nolint:gosec // G204: Command execution is the purpose of this function
	cmd := exec.CommandContext(execCtx, req.Command, req.Args...)
	if req.Dir != "" {
		cmd.Dir = req.Dir
	}

	// Set environment - either sanitized env or isolated empty env
	if len(env) > 0 {
		cmd.Env = env
	} else {
		// DEFAULT TO SAFE: Do not inherit host environment
		// This prevents leaking sensitive env vars (AWS_ACCESS_KEY_ID, DB_PASSWORD, etc.)
		cmd.Env = []string{}
	}

	// Use bounded buffers to limit output size
	stdout := NewBoundedBuffer(cfg.maxOutputSize)
	stderr := NewBoundedBuffer(cfg.maxOutputSize)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	resp := ExecCommandResponse{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		DurationMs:      duration.Milliseconds(),
		StdoutTruncated: stdout.Truncated,
		StderrTruncated: stderr.Truncated,
	}

	// Log if output was truncated
	if stdout.Truncated || stderr.Truncated {
		slog.WarnContext(ctx, "command output truncated",
			"command", req.Command,
			"stdout_truncated", stdout.Truncated,
			"stderr_truncated", stderr.Truncated,
			"max_size", cfg.maxOutputSize)
	}

	if err != nil {
		// Check for timeout
		if execCtx.Err() == context.DeadlineExceeded {
			resp.IsTimeout = true
			resp.ExitCode = -1 // Conventional timeout code
			return resp
		}

		// Check for exit code
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			resp.ExitCode = exitErr.ExitCode()
			return resp
		}

		// Failed to start or other error
		resp.Error = &ExecError{
			Code:    "EXECUTION_FAILED",
			Message: err.Error(),
		}
		return resp
	}

	resp.ExitCode = 0
	return resp
}

// PerformSecureExecCommand executes a command with full security features enabled.
// This is a convenience function that enables all security features:
//   - Environment sanitization
//   - Isolated environment (no host env leakage)
//   - Output size limiting
//
// Use this for executing commands from untrusted sources (e.g., WASM plugins).
func PerformSecureExecCommand(ctx context.Context, req ExecCommandRequest, pluginName string, capGetter CapabilityGetter, opts ...ExecOption) ExecCommandResponse {
	// Prepend security options before user options
	allOpts := make([]ExecOption, 0, len(opts)+2)
	allOpts = append(allOpts, WithEnvSanitization(pluginName, capGetter))
	allOpts = append(allOpts, WithIsolatedEnv())
	allOpts = append(allOpts, opts...)
	return PerformExecCommand(ctx, req, allOpts...)
}
