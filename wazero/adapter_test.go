package wazero

import (
	"testing"

	hostlib "github.com/reglet-dev/reglet-hostlib"
)

func TestDefaultAdapterConfig(t *testing.T) {
	cfg := defaultAdapterConfig()

	if cfg.ModuleName != "reglet_host" {
		t.Errorf("ModuleName = %q, want %q", cfg.ModuleName, "reglet_host")
	}
	if cfg.MaxRequestSize != hostlib.DefaultMaxRequestSize {
		t.Errorf("MaxRequestSize = %d, want %d", cfg.MaxRequestSize, hostlib.DefaultMaxRequestSize)
	}
}

func TestWithModuleName(t *testing.T) {
	cfg := defaultAdapterConfig()
	WithModuleName("custom_module")(&cfg)

	if cfg.ModuleName != "custom_module" {
		t.Errorf("ModuleName = %q, want %q", cfg.ModuleName, "custom_module")
	}
}

func TestWithMaxRequestSize(t *testing.T) {
	cfg := defaultAdapterConfig()
	WithMaxRequestSize(2048)(&cfg)

	if cfg.MaxRequestSize != 2048 {
		t.Errorf("MaxRequestSize = %d, want %d", cfg.MaxRequestSize, 2048)
	}
}

func TestPackUnpackPtrLen(t *testing.T) {
	tests := []struct {
		ptr    uint32
		length uint32
	}{
		{0, 0},
		{1, 1},
		{0xFFFFFFFF, 0xFFFFFFFF},
		{0x12345678, 0x9ABCDEF0},
		{100, 50},
	}

	for _, tt := range tests {
		packed := packPtrLen(tt.ptr, tt.length)
		gotPtr, gotLen := unpackPtrLen(packed)

		if gotPtr != tt.ptr {
			t.Errorf("unpackPtrLen(%x): ptr = %x, want %x", packed, gotPtr, tt.ptr)
		}
		if gotLen != tt.length {
			t.Errorf("unpackPtrLen(%x): len = %x, want %x", packed, gotLen, tt.length)
		}
	}
}

func TestWithCustomHandler(t *testing.T) {
	cfg := defaultAdapterConfig()

	handler := CustomHandler{
		Name: "test_handler",
	}

	WithCustomHandler(handler)(&cfg)

	if len(cfg.CustomHandlers) != 1 {
		t.Errorf("len(CustomHandlers) = %d, want 1", len(cfg.CustomHandlers))
	}
	if cfg.CustomHandlers[0].Name != "test_handler" {
		t.Errorf("CustomHandlers[0].Name = %q, want %q", cfg.CustomHandlers[0].Name, "test_handler")
	}
}
