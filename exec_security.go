package hostlib

import (
	"context"
	"log/slog"
	"slices"
	"strings"
)

// Environment variable security tiers.
// Tier 1: Always blocked - no capability can grant these (linker injection vectors).
// Tier 2: Capability-gated - require explicit exec:env:<VAR> capability.
var (
	// alwaysBlockedEnvPrefixes are prefixes for variables that are NEVER allowed.
	// These are primarily used for shared library injection attacks.
	alwaysBlockedEnvPrefixes = []string{
		"LD_",   // Linux dynamic linker (LD_PRELOAD, LD_LIBRARY_PATH, LD_AUDIT, etc.)
		"DYLD_", // macOS dynamic linker (DYLD_INSERT_LIBRARIES, etc.)
	}

	// alwaysBlockedEnvExact are exact variable names that are NEVER allowed.
	alwaysBlockedEnvExact = []string{
		"IFS",      // Shell internal field separator - can alter parsing
		"LOCPATH",  // Custom locale path - can execute code via locale files
		"BASH_ENV", // Executed by non-interactive bash shells
		"ENV",      // Executed by POSIX sh
	}

	// capabilityGatedEnv are variables that require explicit capability grant.
	// A plugin needs exec:env:<VARNAME> capability to set these.
	capabilityGatedEnv = []string{
		"PATH",          // Command resolution path
		"HOME",          // User home directory
		"PYTHONPATH",    // Python module search path
		"PYTHONSTARTUP", // Python startup script
		"PYTHONHOME",    // Python installation path
		"NODE_OPTIONS",  // Node.js CLI options
		"NODE_PATH",     // Node.js module search path
		"RUBYLIB",       // Ruby library path
		"PERL5LIB",      // Perl library path
		"LUA_PATH",      // Lua module search path
		"LUA_CPATH",     // Lua C module search path
		"CDPATH",        // Shell cd search path
		"PS4",           // Shell debug prompt (can execute code in some shells)
	}
)

// CapabilityGetter is a function that checks if a specific capability is granted.
// It takes a plugin name and capability pattern (e.g., "env:PATH") and returns true if allowed.
type CapabilityGetter func(pluginName, capability string) bool

// SanitizeEnv filters environment variables according to security tiers.
// Tier 1 (always blocked): Variables like LD_PRELOAD that are never allowed.
// Tier 2 (capability-gated): Variables like PATH that require exec:env:<VAR> capability.
// Returns the sanitized environment slice.
func SanitizeEnv(ctx context.Context, env []string, pluginName string, capGetter CapabilityGetter) []string {
	if len(env) == 0 {
		return env
	}

	sanitized := make([]string, 0, len(env))

	for _, e := range env {
		// Parse "KEY=value" format
		key, _, found := strings.Cut(e, "=")
		if !found {
			// Malformed env var (no =), skip it
			slog.WarnContext(ctx, "malformed environment variable skipped",
				"env", e,
				"plugin", pluginName)
			continue
		}

		upperKey := strings.ToUpper(key)

		// Tier 1: Check always-blocked prefixes
		if IsAlwaysBlockedEnv(upperKey) {
			slog.WarnContext(ctx, "blocked dangerous environment variable",
				"env_var", key,
				"plugin", pluginName,
				"reason", "always_blocked")
			continue
		}

		// Tier 2: Check capability-gated variables
		if slices.Contains(capabilityGatedEnv, upperKey) {
			if capGetter == nil || !capGetter(pluginName, "env:"+upperKey) {
				slog.WarnContext(ctx, "blocked environment variable (missing capability)",
					"env_var", key,
					"plugin", pluginName,
					"required_capability", "exec:env:"+upperKey)
				continue
			}
			slog.DebugContext(ctx, "capability-gated environment variable allowed",
				"env_var", key,
				"plugin", pluginName)
		}

		sanitized = append(sanitized, e)
	}

	return sanitized
}

// IsAlwaysBlockedEnv checks if an environment variable key is always blocked.
func IsAlwaysBlockedEnv(upperKey string) bool {
	// Check prefixes (LD_*, DYLD_*)
	for _, prefix := range alwaysBlockedEnvPrefixes {
		if strings.HasPrefix(upperKey, prefix) {
			return true
		}
	}

	// Check exact matches
	return slices.Contains(alwaysBlockedEnvExact, upperKey)
}

// executionType represents the type of command execution.
type executionType string

const (
	execTypeSafe        executionType = "safe"
	execTypeShell       executionType = "shell"
	execTypeInterpreter executionType = "interpreter code execution"
	execTypeSuspicious  executionType = "suspicious execution"
)

// DetectExecutionType determines if the command is dangerous and what type.
func DetectExecutionType(command string, args []string) executionType {
	if IsShellExecution(command) && len(args) > 0 {
		return execTypeShell
	}
	if hasCodeExecutionFlags(command, args) {
		return execTypeInterpreter
	}
	if hasSuspiciousFlags(args) {
		return execTypeSuspicious
	}
	return execTypeSafe
}

// IsShellExecution detects if a command is a shell invocation.
// Common shells: sh, bash, dash, zsh, ksh, csh, tcsh, fish.
func IsShellExecution(command string) bool {
	base := getBasename(command)
	shells := []string{"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish"}
	return slices.Contains(shells, base)
}

// getBasename extracts the binary name from a path.
func getBasename(command string) string {
	if idx := strings.LastIndex(command, "/"); idx >= 0 {
		return command[idx+1:]
	}
	return command
}

// IsKnownInterpreter detects if a command is a known scripting interpreter.
func IsKnownInterpreter(command string) bool {
	base := getBasename(command)
	interpreters := []string{
		"python", "python2", "python3",
		"python2.7", "python3.6", "python3.7", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12",
		"perl", "perl5",
		"ruby", "irb",
		"node", "nodejs",
		"php", "php7", "php8",
		"lua", "lua5.1", "lua5.2", "lua5.3", "lua5.4",
		"awk", "gawk", "mawk", "nawk",
		"tclsh", "wish",
		"expect",
	}
	return slices.Contains(interpreters, base)
}

// hasCodeExecutionFlags detects if interpreter is being invoked with code execution flags.
func hasCodeExecutionFlags(command string, args []string) bool {
	base := getBasename(command)

	// AWK special case: BEGIN/END blocks execute arbitrary code
	if isAwkWithBlocks(base, args) {
		return true
	}

	return hasDangerousFlags(base, args)
}

// isAwkWithBlocks checks for AWK commands with BEGIN/END blocks.
func isAwkWithBlocks(base string, args []string) bool {
	if base != "awk" && base != "gawk" && base != "mawk" && base != "nawk" {
		return false
	}
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if strings.HasPrefix(trimmed, "BEGIN{") ||
			strings.HasPrefix(trimmed, "BEGIN {") ||
			strings.HasPrefix(trimmed, "END{") ||
			strings.HasPrefix(trimmed, "END {") {
			return true
		}
	}
	return false
}

// hasDangerousFlags checks if any arguments match dangerous flags for the given interpreter.
func hasDangerousFlags(base string, args []string) bool {
	dangerousFlags := map[string][]string{
		"python": {"-c", "--command"}, "python2": {"-c", "--command"}, "python3": {"-c", "--command"},
		"python2.7": {"-c", "--command"}, "python3.6": {"-c", "--command"}, "python3.7": {"-c", "--command"},
		"python3.8": {"-c", "--command"}, "python3.9": {"-c", "--command"}, "python3.10": {"-c", "--command"},
		"python3.11": {"-c", "--command"}, "python3.12": {"-c", "--command"},
		"perl": {"-e", "-E"}, "perl5": {"-e", "-E"},
		"ruby": {"-e"}, "irb": {"-e"},
		"node": {"-e", "--eval"}, "nodejs": {"-e", "--eval"},
		"php": {"-r"}, "php7": {"-r"}, "php8": {"-r"},
		"lua": {"-e"}, "lua5.1": {"-e"}, "lua5.2": {"-e"}, "lua5.3": {"-e"}, "lua5.4": {"-e"},
		"tclsh": {"-c"}, "wish": {"-c"},
	}

	flags, isTracked := dangerousFlags[base]
	if !isTracked {
		return false
	}

	for _, arg := range args {
		for _, flag := range flags {
			if arg == flag || strings.HasPrefix(arg, flag+"=") {
				return true
			}
		}
	}
	return false
}

// hasSuspiciousFlags detects code-execution flags in unrecognized commands.
func hasSuspiciousFlags(args []string) bool {
	suspiciousFlags := []string{"-c", "-e", "-E", "-r", "--eval", "--command"}
	for _, arg := range args {
		if slices.Contains(suspiciousFlags, arg) {
			return true
		}
	}
	return false
}

// IsDangerousExecution returns true if the command represents a potentially dangerous execution.
// This is useful for capability checking when shell/interpreter execution is detected.
func IsDangerousExecution(command string, args []string) bool {
	return DetectExecutionType(command, args) != execTypeSafe
}

// GetExecutionTypeDescription returns a human-readable description of the execution type.
func GetExecutionTypeDescription(command string, args []string) string {
	return string(DetectExecutionType(command, args))
}
