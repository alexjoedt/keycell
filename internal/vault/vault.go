// Package vault defines the plaintext schema of the vault file and the
// rules every secret must satisfy before it is written. The encrypted file
// layout lives in file.go; this file knows nothing about age or disk.
package vault

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"time"
)

// Version is the schema version this package writes. Older versions are
// read and migrated on the next write; newer ones are rejected.
const Version = 1

// Vault is the decrypted content of vault.age.
type Vault struct {
	Version int                `json:"version"`
	Secrets map[string]*Secret `json:"secrets"`
}

// Secret is one record in the vault. The name is the map key.
type Secret struct {
	Kind       string            `json:"kind"`
	Value      []byte            `json:"value"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Created    time.Time         `json:"created"`
	Updated    time.Time         `json:"updated"`
}

// ErrVersion is returned by Decode for a vault written by a newer keycell.
var ErrVersion = errors.New("vault: unsupported schema version")

// New returns an empty vault of the current version.
func New() *Vault {
	return &Vault{Version: Version, Secrets: map[string]*Secret{}}
}

// Encode writes v as JSON. The returned buffer holds plaintext values; the
// caller clears it when done.
func Encode(v *Vault) ([]byte, error) {
	if v.Secrets == nil {
		v.Secrets = map[string]*Secret{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("vault: encode: %w", err)
	}
	return b, nil
}

// Decode parses JSON produced by Encode or by an older schema version.
// A version above Version fails with ErrVersion. The input is not retained.
func Decode(b []byte) (*Vault, error) {
	var head struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("vault: decode: %w", err)
	}
	if head.Version > Version {
		return nil, fmt.Errorf("%w: file has %d, this keycell supports up to %d", ErrVersion, head.Version, Version)
	}
	v := New()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return nil, fmt.Errorf("vault: decode: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("vault: decode: trailing data after document")
	}
	if v.Secrets == nil {
		v.Secrets = map[string]*Secret{}
	}
	v.Version = Version
	return v, nil
}

// Wipe zeroes every value in v and the buffer b, if given. It is the
// caller's last act with a decrypted vault.
func Wipe(v *Vault, b []byte) {
	if v != nil {
		for _, s := range v.Secrets {
			clear(s.Value)
		}
	}
	clear(b)
	runtime.KeepAlive(v)
	runtime.KeepAlive(b)
}
