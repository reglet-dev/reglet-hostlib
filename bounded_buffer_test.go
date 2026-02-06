package hostlib

import (
	"testing"
)

func TestBoundedBuffer_Write(t *testing.T) {
	t.Run("writes within limit", func(t *testing.T) {
		buf := NewBoundedBuffer(100)
		n, err := buf.Write([]byte("hello"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if n != 5 {
			t.Errorf("Write() = %d, want 5", n)
		}
		if buf.String() != "hello" {
			t.Errorf("String() = %q, want %q", buf.String(), "hello")
		}
		if buf.Truncated {
			t.Error("Truncated should be false")
		}
	})

	t.Run("truncates at limit", func(t *testing.T) {
		buf := NewBoundedBuffer(10)
		n, err := buf.Write([]byte("hello world"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Should report writing all 11 bytes to satisfy io.Writer contract
		if n != 11 {
			t.Errorf("Write() = %d, want 11", n)
		}
		// But only first 10 should be in buffer
		if buf.String() != "hello worl" {
			t.Errorf("String() = %q, want %q", buf.String(), "hello worl")
		}
		if !buf.Truncated {
			t.Error("Truncated should be true")
		}
	})

	t.Run("multiple writes truncate", func(t *testing.T) {
		buf := NewBoundedBuffer(10)
		buf.Write([]byte("12345"))
		buf.Write([]byte("67890"))
		n, err := buf.Write([]byte("XXXXX"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Should report writing all bytes
		if n != 5 {
			t.Errorf("Write() = %d, want 5", n)
		}
		// But buffer should only have first 10
		if buf.String() != "1234567890" {
			t.Errorf("String() = %q, want %q", buf.String(), "1234567890")
		}
		if !buf.Truncated {
			t.Error("Truncated should be true")
		}
	})

	t.Run("partial write at boundary", func(t *testing.T) {
		buf := NewBoundedBuffer(8)
		buf.Write([]byte("12345"))
		n, err := buf.Write([]byte("67890"))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// Should report writing all 5 bytes
		if n != 5 {
			t.Errorf("Write() = %d, want 5", n)
		}
		// But buffer should only have 8
		if buf.String() != "12345678" {
			t.Errorf("String() = %q, want %q", buf.String(), "12345678")
		}
		if !buf.Truncated {
			t.Error("Truncated should be true")
		}
	})
}

func TestBoundedBuffer_Len(t *testing.T) {
	buf := NewBoundedBuffer(100)
	buf.Write([]byte("hello"))
	if buf.Len() != 5 {
		t.Errorf("Len() = %d, want 5", buf.Len())
	}
}

func TestBoundedBuffer_Bytes(t *testing.T) {
	buf := NewBoundedBuffer(100)
	buf.Write([]byte("hello"))
	got := buf.Bytes()
	want := []byte("hello")
	if string(got) != string(want) {
		t.Errorf("Bytes() = %q, want %q", got, want)
	}
}

func TestBoundedBuffer_Reset(t *testing.T) {
	buf := NewBoundedBuffer(5)
	buf.Write([]byte("hello world"))
	if !buf.Truncated {
		t.Error("should be truncated before reset")
	}

	buf.Reset()

	if buf.Truncated {
		t.Error("Truncated should be false after reset")
	}
	if buf.Len() != 0 {
		t.Errorf("Len() = %d, want 0 after reset", buf.Len())
	}
	if buf.String() != "" {
		t.Errorf("String() = %q, want empty after reset", buf.String())
	}
}

func TestDefaultConstants(t *testing.T) {
	// Verify default constants are reasonable
	if DefaultMaxOutputSize != 10*1024*1024 {
		t.Errorf("DefaultMaxOutputSize = %d, want 10MB", DefaultMaxOutputSize)
	}
	if DefaultMaxRequestSize != 1*1024*1024 {
		t.Errorf("DefaultMaxRequestSize = %d, want 1MB", DefaultMaxRequestSize)
	}
}
