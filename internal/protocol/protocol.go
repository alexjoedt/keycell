// Package protocol defines the wire format between keycelld and its
// clients: one JSON object per line over a Unix socket (ADR 0003). The
// types here are shared by internal/daemon and pkg/keycell so both sides
// agree on field names, method names and error codes. The human-readable
// specification is docs/PROTOCOL.md.
package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"
)

// Version is reported by status.protocol. It only changes on a breaking
// change, which also moves the socket path (ADR 0008).
const Version = 1

// Method names.
const (
	MethodGet    = "get"
	MethodStore  = "store"
	MethodDelete = "delete"
	MethodList   = "list"
	MethodUnlock = "unlock"
	MethodLock   = "lock"
	MethodStatus = "status"
)

// Error codes. Programs match on the code, humans read the message.
const (
	CodeProtocol        = "PROTOCOL"
	CodeInvalidArgument = "INVALID_ARGUMENT"
	CodeNotFound        = "NOT_FOUND"
	CodeLocked          = "LOCKED"
	CodeInternal        = "INTERNAL"
)

// Request is one line from client to daemon. ID is any JSON value except
// null; it is echoed back untouched and never interpreted.
type Request struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response is one line from daemon to client. Exactly one of Result and
// Error is set. A request whose id could not be parsed is answered with
// a null id.
type Response struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// Error is the error object of a Response. Mapping codes to client
// sentinels is the client's job, not this package's.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf builds an Error with a formatted message.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// SecretInfo is the metadata of one secret as list returns it.
type SecretInfo struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Created    time.Time         `json:"created"`
	Updated    time.Time         `json:"updated"`
}

// GetParams selects a secret by name.
type GetParams struct {
	Name string `json:"name"`
}

// GetResult is SecretInfo plus the value. Value is base64 on the wire and
// the caller's to clear after use.
type GetResult struct {
	SecretInfo

	Value []byte `json:"value"`
}

// ListParams filters the listing. Every given filter must match; a nil
// Attributes map matches everything.
type ListParams struct {
	Kind       string            `json:"kind,omitempty"`
	Prefix     string            `json:"prefix,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// ListResult never contains values.
type ListResult []SecretInfo

// StoreParams creates or replaces a secret. Value is base64 on the wire.
type StoreParams struct {
	Name       string            `json:"name"`
	Kind       string            `json:"kind"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Value      []byte            `json:"value"`
}

// DeleteParams selects the secret to remove.
type DeleteParams struct {
	Name string `json:"name"`
}

// UnlockParams carries the decrypted age identity, base64 on the wire.
// For is the auto-lock duration in seconds: nil means the daemon's
// configured default, 0 disables auto-lock for this session.
type UnlockParams struct {
	Identity []byte `json:"identity"`
	For      *int64 `json:"for,omitempty"`
}

// StatusResult describes the daemon. LocksAt is set while unlocked with
// auto-lock active.
type StatusResult struct {
	Protocol int        `json:"protocol"`
	Locked   bool       `json:"locked"`
	LocksAt  *time.Time `json:"locks_at,omitempty"`
}

// Empty is the result of store, delete, unlock and lock, and the params
// of lock and status.
type Empty struct{}

// Bind decodes the request's params into v. Missing or null params decode
// as an empty object. Unknown fields and type mismatches are reported as
// INVALID_ARGUMENT so a newer client cannot have a field silently ignored.
func (r *Request) Bind(v any) error {
	if len(r.Params) == 0 || bytes.Equal(r.Params, []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(r.Params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return Errorf(CodeInvalidArgument, "params: %v", err)
	}
	return nil
}

// NewRequest marshals params into a Request.
func NewRequest(id json.RawMessage, method string, params any) (*Request, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("protocol: marshal %s params: %w", method, err)
	}
	return &Request{ID: id, Method: method, Params: raw}, nil
}

// NewResult marshals result into a success Response for id.
func NewResult(id json.RawMessage, result any) (*Response, error) {
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("protocol: marshal result: %w", err)
	}
	return &Response{ID: id, Result: raw}, nil
}

// NewError builds an error Response for id. A nil id is sent as null.
func NewError(id json.RawMessage, e *Error) *Response {
	if id == nil {
		id = json.RawMessage("null")
	}
	return &Response{ID: id, Error: e}
}
