package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/alexjoedt/keycell/pkg/keycell"
)

// notFound is the string docker expects on stdout when a registry has
// no login; anything else makes the CLI report an error instead of
// falling back to anonymous access.
const notFound = "credentials not found in native keychain"

// get answers docker's credential lookup for one server URL.
func (h *helper) get(ctx context.Context) error {
	server, err := readServerURL(h.stdin)
	if err != nil {
		return err
	}
	c, err := h.connect(ctx)
	if err != nil {
		return daemonError(err)
	}
	s, err := match(ctx, c, server)
	if errors.Is(err, errNoMatch) {
		fmt.Fprintln(h.stdout, notFound)
		return &exitError{code: 1}
	}
	if err != nil {
		return daemonError(err)
	}
	full, err := c.Get(ctx, s.Name)
	if err != nil {
		return daemonError(err)
	}
	defer full.Value.Destroy()
	return writeCredential(h.stdout, server, s.Attributes["username"], full.Value.Expose())
}

// writeCredential emits {"ServerURL","Username","Secret"}. The secret
// is quoted into a buffer that is wiped afterwards and written as
// bytes, never through fmt or json.Marshal, so no string copy stays.
func writeCredential(w io.Writer, server, username string, secret []byte) error {
	serverJSON, err := json.Marshal(server)
	if err != nil {
		return err
	}
	userJSON, err := json.Marshal(username)
	if err != nil {
		return err
	}
	q := quote(secret)
	defer clear(q)
	for _, part := range [][]byte{[]byte(`{"ServerURL":`), serverJSON, []byte(`,"Username":`), userJSON, []byte(`,"Secret":`), q, []byte("}\n")} {
		if _, err := w.Write(part); err != nil {
			return exitf("write: %v", err)
		}
	}
	return nil
}

// quote encodes b as a JSON string literal the way encoding/json does:
// control characters as \uXXXX except the short forms, invalid UTF-8
// as U+FFFD. HTML characters stay as they are; docker parses JSON.
func quote(b []byte) []byte {
	const hex = "0123456789abcdef"
	out := make([]byte, 0, len(b)+2)
	out = append(out, '"')
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == '"' || c == '\\':
			out = append(out, '\\', c)
			i++
		case c == '\n':
			out = append(out, '\\', 'n')
			i++
		case c == '\r':
			out = append(out, '\\', 'r')
			i++
		case c == '\t':
			out = append(out, '\\', 't')
			i++
		case c < 0x20:
			out = append(out, '\\', 'u', '0', '0', hex[c>>4], hex[c&0xf])
			i++
		case c < utf8.RuneSelf:
			out = append(out, c)
			i++
		default:
			r, n := utf8.DecodeRune(b[i:])
			if r == utf8.RuneError && n == 1 {
				out = append(out, `�`...)
			} else {
				out = append(out, b[i:i+n]...)
			}
			i += n
		}
	}
	return append(out, '"')
}

// list reports every stored registry login as {"<server>":"<username>"}.
// A locked daemon yields {} with a hint on stderr and exit 0, so docker
// build does not fail on the listing; the get that follows fails loudly.
func (h *helper) list(ctx context.Context) error {
	c, err := h.connect(ctx)
	if err != nil {
		return daemonError(err)
	}
	secs, err := c.List(ctx, keycell.Filter{Kind: kind})
	if errors.Is(err, keycell.ErrLocked) {
		fmt.Fprintln(h.stdout, "{}")
		fmt.Fprintf(h.stderr, "%s: daemon is locked, run 'keycell unlock'\n", prog)
		return nil
	}
	if err != nil {
		return daemonError(err)
	}
	out := make(map[string]string, len(secs))
	for _, s := range secs {
		if server := s.Attributes["server"]; server != "" {
			out[server] = s.Attributes["username"]
		}
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	fmt.Fprintf(h.stdout, "%s\n", b)
	return nil
}

// store saves a docker login. A secret matching the server is updated
// in place, name and other attributes kept, so a renewed token replaces
// the old one; without a match a new docker/<host> is created. Anything
// that prevents storing fails loudly, docker login must not succeed
// with nothing saved.
func (h *helper) store(ctx context.Context) error {
	req, buf, err := readStoreRequest(h.stdin)
	defer clear(buf)
	if err != nil {
		return err
	}
	secret, err := unquote(req.Secret)
	if err != nil {
		return err
	}
	v := keycell.NewValue(secret)
	defer v.Destroy()
	c, err := h.connect(ctx)
	if err != nil {
		return daemonError(err)
	}
	s, err := match(ctx, c, req.ServerURL)
	switch {
	case errors.Is(err, errNoMatch):
		s = &keycell.Secret{Name: secretName(req.ServerURL), Kind: kind, Attributes: map[string]string{"server": req.ServerURL}}
	case err != nil:
		return daemonError(err)
	}
	s.Attributes["username"] = req.Username
	s.Value = v
	return daemonError(c.Store(ctx, *s))
}

// erase deletes the one secret matching the server URL docker logs out
// of; no match is fine, ambiguous deletes nothing and fails.
func (h *helper) erase(ctx context.Context) error {
	server, err := readServerURL(h.stdin)
	if err != nil {
		return err
	}
	c, err := h.connect(ctx)
	if err != nil {
		return daemonError(err)
	}
	s, err := match(ctx, c, server)
	switch {
	case errors.Is(err, errNoMatch):
		return nil
	case err != nil:
		return daemonError(err)
	}
	if err := c.Delete(ctx, s.Name); err != nil && !errors.Is(err, keycell.ErrNotFound) {
		return daemonError(err)
	}
	return nil
}
