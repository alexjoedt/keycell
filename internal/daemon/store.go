package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"filippo.io/age"

	"github.com/alexjoedt/keycell/internal/vault"
)

// Sentinels the protocol layer maps to error codes.
var (
	ErrNotFound        = errors.New("daemon: secret not found")
	ErrInvalidArgument = errors.New("daemon: invalid argument")
)

// Secret is one record as the operations return it. List leaves Value nil.
type Secret struct {
	Name       string
	Kind       string
	Attributes map[string]string
	Value      []byte
	Created    time.Time
	Updated    time.Time
}

// Filter narrows List; every set field must match.
type Filter struct {
	Kind       string
	Prefix     string
	Attributes map[string]string
}

// wipeVault is a test hook around vault.Wipe.
var wipeVault = vault.Wipe

// Store runs the secret operations against one vault file, decrypting
// on demand under the session's read lock (ADR 0005). Writers serialize
// on their own mutex for the read-modify-write cycle.
type Store struct {
	path    string
	session *Session
	log     *slog.Logger
	now     func() time.Time
	writeMu sync.Mutex
}

// NewStore returns a Store over the vault at path.
func NewStore(path string, s *Session, log *slog.Logger) *Store {
	return &Store{path: path, session: s, log: log, now: time.Now}
}

// Get returns the secret called name. The returned Value is the only
// copy left in memory; the caller clears it after use.
func (st *Store) Get(name string) (*Secret, error) {
	var out *Secret
	err := st.session.With(func(id *age.X25519Identity) error {
		if err := vault.ValidateName(name); err != nil {
			return invalid(err)
		}
		v, err := st.read(id)
		if err != nil {
			return err
		}
		defer wipeVault(v, nil)
		s, ok := v.Secrets[name]
		if !ok {
			return ErrNotFound
		}
		out = toSecret(name, s)
		out.Value = slices.Clone(s.Value)
		return nil
	})
	return out, err
}

// List returns the metadata of every secret matching f, sorted by name.
func (st *Store) List(f Filter) ([]Secret, error) {
	var out []Secret
	err := st.session.With(func(id *age.X25519Identity) error {
		if f.Kind != "" {
			if err := vault.ValidateKind(f.Kind); err != nil {
				return invalid(err)
			}
		}
		if err := vault.ValidateAttributes(f.Attributes); err != nil {
			return invalid(err)
		}
		v, err := st.read(id)
		if err != nil {
			return err
		}
		defer wipeVault(v, nil)
		out = make([]Secret, 0, len(v.Secrets))
		for name, s := range v.Secrets {
			if f.matches(name, s) {
				out = append(out, *toSecret(name, s))
			}
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return nil
	})
	return out, err
}

// Store creates or replaces a secret. value is consumed: it is zeroed
// together with the vault plaintext once written.
func (st *Store) Store(name, kind string, attrs map[string]string, value []byte) error {
	return st.write(func(v *vault.Vault) error {
		s := &vault.Secret{Kind: kind, Value: value, Attributes: attrs}
		if err := vault.ValidateSecret(name, s); err != nil {
			return invalid(err)
		}
		now := st.now().UTC()
		s.Created, s.Updated = now, now
		if old, ok := v.Secrets[name]; ok {
			s.Created = old.Created
		}
		v.Secrets[name] = s
		return nil
	})
}

// Delete removes the secret called name.
func (st *Store) Delete(name string) error {
	return st.write(func(v *vault.Vault) error {
		if err := vault.ValidateName(name); err != nil {
			return invalid(err)
		}
		if _, ok := v.Secrets[name]; !ok {
			return ErrNotFound
		}
		delete(v.Secrets, name)
		return nil
	})
}

// write runs one read-modify-write cycle. A non-nil error from modify
// leaves the file untouched.
func (st *Store) write(modify func(v *vault.Vault) error) error {
	st.writeMu.Lock()
	defer st.writeMu.Unlock()
	return st.session.With(func(id *age.X25519Identity) error {
		v, err := st.read(id)
		if err != nil {
			return err
		}
		defer wipeVault(v, nil)
		if err := modify(v); err != nil {
			return err
		}
		if err := vault.Write(st.path, id, v); err != nil {
			st.log.Error("vault write failed", "path", st.path, "err", err)
			return err
		}
		return nil
	})
}

func (st *Store) read(id *age.X25519Identity) (*vault.Vault, error) {
	v, err := vault.Read(st.path, id)
	if err != nil {
		st.log.Error("vault read failed", "path", st.path, "err", err)
		return nil, err
	}
	return v, nil
}

func (f Filter) matches(name string, s *vault.Secret) bool {
	if f.Kind != "" && s.Kind != f.Kind {
		return false
	}
	if !strings.HasPrefix(name, f.Prefix) {
		return false
	}
	for k, want := range f.Attributes {
		if got, ok := s.Attributes[k]; !ok || got != want {
			return false
		}
	}
	return true
}

func toSecret(name string, s *vault.Secret) *Secret {
	return &Secret{
		Name:       name,
		Kind:       s.Kind,
		Attributes: maps.Clone(s.Attributes),
		Created:    s.Created,
		Updated:    s.Updated,
	}
}

func invalid(err error) error {
	return fmt.Errorf("%w: %w", ErrInvalidArgument, err)
}
