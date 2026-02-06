package hostlib

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerformExecCommand_Success(t *testing.T) {
	req := ExecCommandRequest{
		Command: "echo",
		Args:    []string{"hello", "world"},
	}

	resp := PerformExecCommand(context.Background(), req)

	assert.Nil(t, resp.Error)
	assert.Equal(t, 0, resp.ExitCode)
	assert.Equal(t, "hello world\n", resp.Stdout)
	assert.Empty(t, resp.Stderr)
	assert.False(t, resp.IsTimeout)
	assert.GreaterOrEqual(t, resp.DurationMs, int64(0))
}

func TestPerformExecCommand_InvalidCommand(t *testing.T) {
	req := ExecCommandRequest{
		Command: "nonexistentcommand12345",
	}

	resp := PerformExecCommand(context.Background(), req)

	require.NotNil(t, resp.Error)
	assert.Equal(t, "EXECUTION_FAILED", resp.Error.Code)
}

func TestPerformExecCommand_Timeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timeout test in short mode")
	}

	req := ExecCommandRequest{
		Command: "sleep",
		Args:    []string{"2"},
		Timeout: 100, // 100ms
	}

	resp := PerformExecCommand(context.Background(), req)

	assert.True(t, resp.IsTimeout)
	assert.Nil(t, resp.Error) // Timeout is a valid result state, not an execution error
}

func TestPerformExecCommand_ExitCode(t *testing.T) {
	// false command returns exit code 1
	req := ExecCommandRequest{
		Command: "false",
	}

	resp := PerformExecCommand(context.Background(), req)

	assert.Nil(t, resp.Error)
	assert.Equal(t, 1, resp.ExitCode)
}

func TestPerformExecCommand_Env(t *testing.T) {
	req := ExecCommandRequest{
		Command: "env",
		Env:     []string{"TEST_VAR=test_value"},
	}

	resp := PerformExecCommand(context.Background(), req)

	assert.Nil(t, resp.Error)
	assert.Contains(t, resp.Stdout, "TEST_VAR=test_value")
}

func TestPerformExecCommand_EmptyCommand(t *testing.T) {
	req := ExecCommandRequest{
		Command: "",
	}

	resp := PerformExecCommand(context.Background(), req)

	require.NotNil(t, resp.Error)
	assert.Equal(t, "INVALID_REQUEST", resp.Error.Code)
}

func TestPerformExecCommand_WithEnvSanitization(t *testing.T) {
	capGetter := func(plugin, cap string) bool {
		// Allow nothing
		return false
	}

	req := ExecCommandRequest{
		Command: "env",
		Env:     []string{"SAFE_VAR=value", "LD_PRELOAD=/evil.so", "PATH=/usr/bin"},
	}

	resp := PerformExecCommand(context.Background(), req,
		WithEnvSanitization("test-plugin", capGetter),
	)

	assert.Nil(t, resp.Error)
	// SAFE_VAR should be present
	assert.Contains(t, resp.Stdout, "SAFE_VAR=value")
	// LD_PRELOAD should be blocked (always blocked)
	assert.NotContains(t, resp.Stdout, "LD_PRELOAD")
	// PATH should be blocked (capability-gated and no capability granted)
	assert.NotContains(t, resp.Stdout, "PATH=")
}

func TestPerformExecCommand_WithEnvSanitization_AllowsCapability(t *testing.T) {
	capGetter := func(plugin, cap string) bool {
		// Allow PATH
		return cap == "env:PATH"
	}

	req := ExecCommandRequest{
		Command: "env",
		Env:     []string{"PATH=/custom/path"},
	}

	resp := PerformExecCommand(context.Background(), req,
		WithEnvSanitization("test-plugin", capGetter),
	)

	assert.Nil(t, resp.Error)
	// PATH should be present since capability is granted
	assert.Contains(t, resp.Stdout, "PATH=/custom/path")
}

func TestPerformExecCommand_WithIsolatedEnv(t *testing.T) {
	req := ExecCommandRequest{
		Command: "env",
		// No Env provided
	}

	resp := PerformExecCommand(context.Background(), req, WithIsolatedEnv())

	assert.Nil(t, resp.Error)
	// With isolated env and no provided env, output should be empty
	assert.Empty(t, resp.Stdout)
}

func TestPerformExecCommand_WithMaxOutputSize(t *testing.T) {
	req := ExecCommandRequest{
		Command: "yes",
		Args:    []string{"hello"},
		Timeout: 100, // 100ms to limit output
	}

	resp := PerformExecCommand(context.Background(), req,
		WithMaxOutputSize(100),
	)

	// Command will timeout, but we care about truncation
	assert.True(t, resp.StdoutTruncated)
	assert.LessOrEqual(t, len(resp.Stdout), 100)
}

func TestPerformSecureExecCommand(t *testing.T) {
	capGetter := func(plugin, cap string) bool {
		return false
	}

	req := ExecCommandRequest{
		Command: "env",
		Env:     []string{"SAFE_VAR=value", "LD_PRELOAD=/evil.so"},
	}

	resp := PerformSecureExecCommand(context.Background(), req, "test-plugin", capGetter)

	assert.Nil(t, resp.Error)
	// SAFE_VAR should be present
	assert.Contains(t, resp.Stdout, "SAFE_VAR=value")
	// LD_PRELOAD should be blocked
	assert.NotContains(t, resp.Stdout, "LD_PRELOAD")
}
