package hostlib

import (
	"context"
	"testing"
)

func TestIsAlwaysBlockedEnv(t *testing.T) {
	tests := []struct {
		name    string
		envKey  string
		blocked bool
	}{
		// Tier 1: Always blocked prefixes
		{"LD_PRELOAD", "LD_PRELOAD", true},
		{"LD_LIBRARY_PATH", "LD_LIBRARY_PATH", true},
		{"LD_AUDIT", "LD_AUDIT", true},
		{"DYLD_INSERT_LIBRARIES", "DYLD_INSERT_LIBRARIES", true},
		{"DYLD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", true},

		// Tier 1: Always blocked exact matches
		{"IFS", "IFS", true},
		{"LOCPATH", "LOCPATH", true},
		{"BASH_ENV", "BASH_ENV", true},
		{"ENV", "ENV", true},

		// Safe variables
		{"TERM", "TERM", false},
		{"USER", "USER", false},
		{"LANG", "LANG", false},

		// Capability-gated (not always blocked)
		{"PATH", "PATH", false},
		{"HOME", "HOME", false},
		{"PYTHONPATH", "PYTHONPATH", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsAlwaysBlockedEnv(tt.envKey)
			if got != tt.blocked {
				t.Errorf("IsAlwaysBlockedEnv(%q) = %v, want %v", tt.envKey, got, tt.blocked)
			}
		})
	}
}

func TestSanitizeEnv(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		env        []string
		pluginName string
		capGetter  CapabilityGetter
		wantEnv    []string
	}{
		{
			name:       "empty env passes through",
			env:        []string{},
			pluginName: "test",
			capGetter:  nil,
			wantEnv:    []string{},
		},
		{
			name:       "safe variables pass through",
			env:        []string{"TERM=xterm", "LANG=en_US.UTF-8"},
			pluginName: "test",
			capGetter:  nil,
			wantEnv:    []string{"TERM=xterm", "LANG=en_US.UTF-8"},
		},
		{
			name:       "LD_PRELOAD is blocked",
			env:        []string{"TERM=xterm", "LD_PRELOAD=/evil.so"},
			pluginName: "test",
			capGetter:  nil,
			wantEnv:    []string{"TERM=xterm"},
		},
		{
			name:       "DYLD_INSERT_LIBRARIES is blocked",
			env:        []string{"DYLD_INSERT_LIBRARIES=/evil.dylib", "USER=test"},
			pluginName: "test",
			capGetter:  nil,
			wantEnv:    []string{"USER=test"},
		},
		{
			name:       "IFS is blocked",
			env:        []string{"IFS=:"},
			pluginName: "test",
			capGetter:  nil,
			wantEnv:    []string{},
		},
		{
			name:       "PATH blocked without capability",
			env:        []string{"PATH=/usr/bin"},
			pluginName: "test",
			capGetter:  nil,
			wantEnv:    []string{},
		},
		{
			name:       "PATH allowed with capability",
			env:        []string{"PATH=/usr/bin"},
			pluginName: "test",
			capGetter: func(plugin, cap string) bool {
				return plugin == "test" && cap == "env:PATH"
			},
			wantEnv: []string{"PATH=/usr/bin"},
		},
		{
			name:       "malformed env var skipped",
			env:        []string{"MALFORMED", "GOOD=value"},
			pluginName: "test",
			capGetter:  nil,
			wantEnv:    []string{"GOOD=value"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeEnv(ctx, tt.env, tt.pluginName, tt.capGetter)
			if len(got) != len(tt.wantEnv) {
				t.Errorf("SanitizeEnv() = %v, want %v", got, tt.wantEnv)
				return
			}
			for i, v := range got {
				if v != tt.wantEnv[i] {
					t.Errorf("SanitizeEnv()[%d] = %q, want %q", i, v, tt.wantEnv[i])
				}
			}
		})
	}
}

func TestIsShellExecution(t *testing.T) {
	tests := []struct {
		command string
		isShell bool
	}{
		{"/bin/sh", true},
		{"/bin/bash", true},
		{"/usr/bin/bash", true},
		{"bash", true},
		{"sh", true},
		{"zsh", true},
		{"dash", true},
		{"ksh", true},
		{"csh", true},
		{"tcsh", true},
		{"fish", true},

		{"echo", false},
		{"cat", false},
		{"ls", false},
		{"/usr/bin/python", false},
		{"node", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := IsShellExecution(tt.command)
			if got != tt.isShell {
				t.Errorf("IsShellExecution(%q) = %v, want %v", tt.command, got, tt.isShell)
			}
		})
	}
}

func TestIsKnownInterpreter(t *testing.T) {
	tests := []struct {
		command       string
		isInterpreter bool
	}{
		{"python", true},
		{"python3", true},
		{"python3.11", true},
		{"/usr/bin/python3", true},
		{"perl", true},
		{"ruby", true},
		{"node", true},
		{"nodejs", true},
		{"php", true},
		{"lua", true},
		{"awk", true},
		{"gawk", true},

		{"echo", false},
		{"cat", false},
		{"ls", false},
		{"gcc", false},
		{"make", false},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := IsKnownInterpreter(tt.command)
			if got != tt.isInterpreter {
				t.Errorf("IsKnownInterpreter(%q) = %v, want %v", tt.command, got, tt.isInterpreter)
			}
		})
	}
}

func TestIsDangerousExecution(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		args      []string
		dangerous bool
	}{
		// Safe commands
		{"ls", "ls", []string{"-la"}, false},
		{"cat", "cat", []string{"/etc/passwd"}, false},
		{"echo", "echo", []string{"hello"}, false},

		// Shell with args is dangerous
		{"bash -c", "bash", []string{"-c", "rm -rf /"}, true},
		{"sh script", "/bin/sh", []string{"script.sh"}, true},

		// Interpreter with code execution flags
		{"python -c", "python", []string{"-c", "print('hello')"}, true},
		{"python3 -c", "python3", []string{"-c", "import os"}, true},
		{"perl -e", "perl", []string{"-e", "print 1"}, true},
		{"ruby -e", "ruby", []string{"-e", "puts 1"}, true},
		{"node -e", "node", []string{"-e", "console.log(1)"}, true},
		{"node --eval", "node", []string{"--eval", "console.log(1)"}, true},
		{"php -r", "php", []string{"-r", "echo 1;"}, true},
		{"lua -e", "lua", []string{"-e", "print(1)"}, true},

		// AWK with BEGIN/END blocks
		{"awk BEGIN", "awk", []string{"BEGIN{print 1}"}, true},
		{"awk END", "awk", []string{"END{print 1}"}, true},
		{"awk pattern only", "awk", []string{"/pattern/"}, false},

		// Suspicious flags on unknown commands
		{"unknown -c", "mycommand", []string{"-c", "code"}, true},
		{"unknown -e", "mycommand", []string{"-e", "code"}, true},
		{"unknown --eval", "mycommand", []string{"--eval", "code"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsDangerousExecution(tt.command, tt.args)
			if got != tt.dangerous {
				t.Errorf("IsDangerousExecution(%q, %v) = %v, want %v",
					tt.command, tt.args, got, tt.dangerous)
			}
		})
	}
}

func TestDetectExecutionType(t *testing.T) {
	tests := []struct {
		name     string
		command  string
		args     []string
		wantType executionType
	}{
		{"safe command", "ls", []string{"-la"}, execTypeSafe},
		{"shell execution", "bash", []string{"-c", "echo"}, execTypeShell},
		{"interpreter code", "python", []string{"-c", "print(1)"}, execTypeInterpreter},
		{"suspicious flags", "myapp", []string{"-e", "code"}, execTypeSuspicious},
		{"shell no args", "bash", []string{}, execTypeSafe},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectExecutionType(tt.command, tt.args)
			if got != tt.wantType {
				t.Errorf("DetectExecutionType(%q, %v) = %v, want %v",
					tt.command, tt.args, got, tt.wantType)
			}
		})
	}
}

func TestGetExecutionTypeDescription(t *testing.T) {
	tests := []struct {
		command string
		args    []string
		want    string
	}{
		{"ls", []string{}, "safe"},
		{"bash", []string{"-c", "echo"}, "shell"},
		{"python", []string{"-c", "print"}, "interpreter code execution"},
		{"myapp", []string{"-e", "code"}, "suspicious execution"},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			got := GetExecutionTypeDescription(tt.command, tt.args)
			if got != tt.want {
				t.Errorf("GetExecutionTypeDescription(%q, %v) = %q, want %q",
					tt.command, tt.args, got, tt.want)
			}
		})
	}
}
