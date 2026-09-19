package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/alexjoedt/keycell/pkg/keycell"
)

// maxRequest bounds what the helper reads from docker: a server URL or
// a login JSON, never more than a few KiB.
const maxRequest = 64 << 10

var (
	errNoServerURL = errors.New("server URL missing")
	errNoUsername  = errors.New("username missing")
	errNoMatch     = errors.New("no match")
)

// readServerURL reads the request of get and erase: the server URL as
// docker sends it, surrounding whitespace stripped, nothing else.
func readServerURL(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxRequest))
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	switch {
	case s == "":
		return "", errNoServerURL
	case strings.ContainsAny(s, " \t\r\n"):
		return "", fmt.Errorf("server URL %q: whitespace", s)
	}
	return s, nil
}

// storeRequest is the login docker sends with store. Secret stays raw
// so the caller can unquote it into a buffer it wipes.
type storeRequest struct {
	ServerURL string          `json:"ServerURL"`
	Username  string          `json:"Username"`
	Secret    json.RawMessage `json:"Secret"`
}

// readStoreRequest decodes the store JSON and checks the fields docker
// requires. buf is the raw input; the caller wipes it after use, the
// secret lives nowhere else until unquote copies it.
func readStoreRequest(r io.Reader) (req storeRequest, buf []byte, err error) {
	buf, err = io.ReadAll(io.LimitReader(r, maxRequest))
	if err != nil {
		return req, buf, err
	}
	dec := json.NewDecoder(bytes.NewReader(buf))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, buf, fmt.Errorf("store request: %w", err)
	}
	switch {
	case req.ServerURL == "":
		return req, buf, errNoServerURL
	case req.Username == "":
		return req, buf, errNoUsername
	case len(req.Secret) == 0:
		return req, buf, errors.New("secret missing")
	}
	return req, buf, nil
}

// unquote decodes a JSON string literal into a fresh byte slice, so the
// secret never becomes a Go string. Escapes follow RFC 8259.
func unquote(raw []byte) ([]byte, error) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return nil, errors.New("secret is not a JSON string")
	}
	raw = raw[1 : len(raw)-1]
	out := make([]byte, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c != '\\' {
			out = append(out, c)
			continue
		}
		i++
		if i >= len(raw) {
			clear(out)
			return nil, errors.New("secret: dangling escape")
		}
		switch raw[i] {
		case '"', '\\', '/':
			out = append(out, raw[i])
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, n, err := unquoteRune(raw[i-1:])
			if err != nil {
				clear(out)
				return nil, err
			}
			out = utf8.AppendRune(out, r)
			i += n - 2
		default:
			clear(out)
			return nil, fmt.Errorf("secret: bad escape \\%c", raw[i])
		}
	}
	return out, nil
}

// unquoteRune decodes \uXXXX at the start of s, joining a surrogate
// pair, and returns the rune and the bytes consumed.
func unquoteRune(s []byte) (rune, int, error) {
	hex4 := func(b []byte) (rune, bool) {
		if len(b) < 6 || b[0] != '\\' || b[1] != 'u' {
			return 0, false
		}
		var r rune
		for _, c := range b[2:6] {
			switch {
			case '0' <= c && c <= '9':
				r = r<<4 | rune(c-'0')
			case 'a' <= c && c <= 'f':
				r = r<<4 | rune(c-'a'+10)
			case 'A' <= c && c <= 'F':
				r = r<<4 | rune(c-'A'+10)
			default:
				return 0, false
			}
		}
		return r, true
	}
	r, ok := hex4(s)
	if !ok {
		return 0, 0, errors.New("secret: bad \\u escape")
	}
	if !utf16.IsSurrogate(r) {
		return r, 6, nil
	}
	r2, ok := hex4(s[6:])
	if !ok {
		return 0, 0, errors.New("secret: lone surrogate")
	}
	if r = utf16.DecodeRune(r, r2); r == utf8.RuneError {
		return 0, 0, errors.New("secret: bad surrogate pair")
	}
	return r, 12, nil
}

// secretName is the name a login gets when no secret matches its
// server: docker/<host>, the URL without scheme and path. Docker Hub's
// https://index.docker.io/v1/ becomes docker/index.docker.io.
func secretName(server string) string {
	host := server
	if _, rest, ok := strings.Cut(host, "://"); ok {
		host = rest
	}
	host, _, _ = strings.Cut(host, "/")
	if host == "" {
		host = server
	}
	return "docker/" + host
}

// ambiguousError names the secrets that share a server URL.
type ambiguousError struct {
	names []string
}

func (e *ambiguousError) Error() string {
	return "ambiguous match: " + strings.Join(e.names, ", ")
}

// match lists the docker-registry secrets whose server attribute equals
// the URL, compared literally. One hit is the answer, none is errNoMatch,
// more is an ambiguousError. Daemon errors come back unwrapped.
func match(ctx context.Context, c *keycell.Client, server string) (*keycell.Secret, error) {
	secs, err := c.List(ctx, keycell.Filter{Kind: kind, Attributes: map[string]string{"server": server}})
	if err != nil {
		return nil, err
	}
	switch len(secs) {
	case 0:
		return nil, errNoMatch
	case 1:
		return &secs[0], nil
	}
	names := make([]string, len(secs))
	for i, s := range secs {
		names[i] = s.Name
	}
	sort.Strings(names)
	return nil, &ambiguousError{names: names}
}
