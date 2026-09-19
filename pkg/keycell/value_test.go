package keycell

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestValueDestroy(t *testing.T) {
	raw := []byte("s3cret")
	v := NewValue(raw)
	if !bytes.Equal(v.Expose(), raw) {
		t.Fatalf("Expose = %q, want %q", v.Expose(), raw)
	}

	v.Destroy()
	if got := v.Expose(); got != nil {
		t.Fatalf("Expose after Destroy = %v, want nil", got)
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatalf("original slice not zeroed: %q", raw)
	}
	v.Destroy()

	var nilValue *Value
	if got := nilValue.Expose(); got != nil {
		t.Fatalf("nil Expose = %v, want nil", got)
	}
	nilValue.Destroy()
}

func TestValueNeverLeaks(t *testing.T) {
	v := NewValue([]byte("s3cret"))
	for _, s := range []string{fmt.Sprint(v), fmt.Sprintf("%v", v), fmt.Sprintf("%+v", v)} {
		if s != "[redacted]" {
			t.Errorf("formatted = %q, want [redacted]", s)
		}
	}

	_, err := json.Marshal(struct {
		V *Value `json:"v"`
	}{V: v})
	if err == nil {
		t.Fatal("json.Marshal succeeded, want error")
	}
}

func TestErrorUnwrap(t *testing.T) {
	tests := []struct {
		code string
		want error
	}{
		{"LOCKED", ErrLocked},
		{"NOT_FOUND", ErrNotFound},
		{"INVALID_ARGUMENT", ErrInvalidArgument},
		{"INTERNAL", ErrInternal},
		{"PROTOCOL", ErrProtocol},
		{"FUTURE_CODE", ErrProtocol},
	}
	for _, tt := range tests {
		err := error(&Error{Code: tt.code, Message: "m"})
		if !errors.Is(err, tt.want) {
			t.Errorf("code %s: errors.Is(%v) = false", tt.code, tt.want)
		}
		wrapped := fmt.Errorf("get: %w", err)
		if !errors.Is(wrapped, tt.want) {
			t.Errorf("code %s: wrapped errors.Is failed", tt.code)
		}
	}
}
