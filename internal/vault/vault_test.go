package vault

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEncodeEmpty(t *testing.T) {
	b, err := Encode(New())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(b), `{"version":1,"secrets":{}}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	ts := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	v := New()
	v.Secrets["github/token"] = &Secret{
		Kind:       "git-credential",
		Value:      []byte("ghp_secret"),
		Attributes: map[string]string{"host": "github.com", "username": "alex"},
		Created:    ts,
		Updated:    ts,
	}
	b, err := Encode(v)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":1,"secrets":{"github/token":{"kind":"git-credential","value":"Z2hwX3NlY3JldA==","attributes":{"host":"github.com","username":"alex"},"created":"2026-09-20T12:00:00Z","updated":"2026-09-20T12:00:00Z"}}}`
	if string(b) != want {
		t.Fatalf("schema drift:\n got %s\nwant %s", b, want)
	}

	got, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	s := got.Secrets["github/token"]
	if s == nil || s.Kind != "git-credential" || string(s.Value) != "ghp_secret" || s.Attributes["host"] != "github.com" || !s.Created.Equal(ts) {
		t.Fatalf("round trip lost data: %+v", s)
	}
}

func TestDecodeVersion(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		error error
	}{
		{"current", `{"version":1,"secrets":{}}`, nil},
		{"older", `{"version":0,"secrets":{}}`, nil},
		{"newer", `{"version":2,"secrets":{}}`, ErrVersion},
		{"missing secrets", `{"version":1}`, nil},
		{"unknown field", `{"version":1,"secrets":{},"extra":1}`, errors.New("any")},
		{"trailing data", `{"version":1,"secrets":{}} {}`, errors.New("any")},
		{"garbage", `nope`, errors.New("any")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := Decode([]byte(tt.in))
			switch {
			case tt.error == nil && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tt.error == nil && (v.Version != Version || v.Secrets == nil):
				t.Fatalf("decoded vault not normalised: %+v", v)
			case tt.error != nil && err == nil:
				t.Fatal("expected error")
			case errors.Is(tt.error, ErrVersion) && !errors.Is(err, ErrVersion):
				t.Fatalf("got %v, want ErrVersion", err)
			}
		})
	}
}

func TestDecodeNewerMessage(t *testing.T) {
	_, err := Decode([]byte(`{"version":7,"secrets":{}}`))
	if err == nil || !strings.Contains(err.Error(), "file has 7") || !strings.Contains(err.Error(), "up to 1") {
		t.Fatalf("message should name both versions: %v", err)
	}
}

func TestWipe(t *testing.T) {
	v := New()
	v.Secrets["a"] = &Secret{Kind: "token", Value: []byte("secret")}
	b := []byte("plaintext")
	Wipe(v, b)
	for _, c := range append(v.Secrets["a"].Value, b...) {
		if c != 0 {
			t.Fatal("not wiped")
		}
	}
	Wipe(nil, nil)
}

func TestValidate(t *testing.T) {
	long := strings.Repeat("a", MaxNameLen+1)
	tests := []struct {
		name string
		s    Secret
		key  string
		err  error
	}{
		{"ok", Secret{Kind: "token", Value: []byte("x")}, "github/token", nil},
		{"ok max name", Secret{Kind: "token"}, strings.Repeat("n", MaxNameLen), nil},
		{"ok unicode name", Secret{Kind: "token"}, "schlüssel/übung", nil},
		{"empty name", Secret{Kind: "token"}, "", ErrEmptyName},
		{"long name", Secret{Kind: "token"}, long, ErrNameTooLong},
		{"bad utf8", Secret{Kind: "token"}, "a\xffb", ErrInvalidUTF8},
		{"control char", Secret{Kind: "token"}, "a\nb", ErrControlChar},
		{"leading space", Secret{Kind: "token"}, " a", ErrEdgeWhitespace},
		{"trailing tab", Secret{Kind: "token"}, "a\t", ErrControlChar},
		{"empty kind", Secret{Kind: ""}, "a", ErrInvalidKind},
		{"upper kind", Secret{Kind: "Token"}, "a", ErrInvalidKind},
		{"long kind", Secret{Kind: strings.Repeat("k", MaxKindLen+1)}, "a", ErrInvalidKind},
		{"ok kind", Secret{Kind: "docker-registry-2"}, "a", nil},
		{"attr key upper", Secret{Kind: "token", Attributes: map[string]string{"Host": "x"}}, "a", ErrInvalidAttrKey},
		{"attr key underscore", Secret{Kind: "token", Attributes: map[string]string{"server_url": "x"}}, "a", ErrInvalidAttrKey},
		{"attr value empty", Secret{Kind: "token", Attributes: map[string]string{"host": ""}}, "a", ErrEmptyName},
		{"attr value long", Secret{Kind: "token", Attributes: map[string]string{"host": long}}, "a", ErrNameTooLong},
		{"attr value control", Secret{Kind: "token", Attributes: map[string]string{"host": "a\x00"}}, "a", ErrControlChar},
		{"attr ok", Secret{Kind: "token", Attributes: map[string]string{"host": "github.com", "path": "org/repo"}}, "a", nil},
		{"value max", Secret{Kind: "token", Value: make([]byte, MaxValueLen)}, "a", nil},
		{"value too large", Secret{Kind: "token", Value: make([]byte, MaxValueLen+1)}, "a", ErrValueTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateSecret(tt.key, &tt.s)
			if tt.err == nil && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.err != nil && !errors.Is(err, tt.err) {
				t.Fatalf("got %v, want %v", err, tt.err)
			}
		})
	}
}
