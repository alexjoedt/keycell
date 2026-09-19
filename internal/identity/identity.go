// Package identity manages the X25519 identity the vault is encrypted to.
// On disk it is either identity.age (passphrase-protected, the default) or
// identity.txt (plain). In memory and on the wire it is the age secret key
// string ("AGE-SECRET-KEY-1...") as bytes; the daemon never learns which
// form protected it (ADR 0007).
package identity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"filippo.io/age"

	"github.com/alexjoedt/keycell/internal/atomicfile"
)

// File names inside the data directory.
const (
	EncryptedFile = "identity.age"
	PlainFile     = "identity.txt"
)

// Form is how the identity is stored.
type Form string

// The forms Detect can report.
const (
	FormEncrypted Form = "encrypted"
	FormPlain     Form = "plain"
	FormNone      Form = "none"
)

// scryptWorkFactor is age's default (about one second); tests lower it.
var scryptWorkFactor = 18

var (
	// ErrWrongPassphrase: identity.age did not decrypt with the passphrase.
	ErrWrongPassphrase = errors.New("identity: wrong passphrase")
	// ErrNotFound: neither identity file exists.
	ErrNotFound = errors.New("identity: no identity file")
	// ErrAmbiguous: both identity files exist; an aborted form change.
	ErrAmbiguous = errors.New("identity: both identity.age and identity.txt exist")
	// ErrMalformed: the file content is not an age X25519 secret key.
	ErrMalformed = errors.New("identity: malformed secret key")
)

// Generate creates a new identity and returns its encoded form.
func Generate() ([]byte, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("identity: generate: %w", err)
	}
	return []byte(id.String()), nil
}

// Parse turns encoded bytes into an age identity for encrypting and
// decrypting the vault. The input is not retained.
func Parse(encoded []byte) (*age.X25519Identity, error) {
	id, err := age.ParseX25519Identity(string(bytes.TrimSpace(encoded)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return id, nil
}

// WriteEncrypted stores the identity passphrase-protected at path.
func WriteEncrypted(path string, encoded, passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("identity: empty passphrase")
	}
	r, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	r.SetWorkFactor(scryptWorkFactor)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		return fmt.Errorf("identity: encrypt: %w", err)
	}
	if _, err := w.Write(encoded); err != nil {
		return fmt.Errorf("identity: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("identity: encrypt: %w", err)
	}
	return atomicfile.Write(path, buf.Bytes(), 0o600, true)
}

// WritePlain stores the identity unprotected at path.
func WritePlain(path string, encoded []byte) error {
	key := bytes.TrimSpace(encoded)
	data := make([]byte, 0, len(key)+1)
	data = append(append(data, key...), '\n')
	err := atomicfile.Write(path, data, 0o600, true)
	clear(data)
	runtime.KeepAlive(data)
	return err
}

// Detect reports which form exists in dir. Both files present is an
// error, as is neither when required.
func Detect(dir string) (Form, error) {
	enc := exists(filepath.Join(dir, EncryptedFile))
	plain := exists(filepath.Join(dir, PlainFile))
	switch {
	case enc && plain:
		return FormNone, ErrAmbiguous
	case enc:
		return FormEncrypted, nil
	case plain:
		return FormPlain, nil
	}
	return FormNone, nil
}

// Load reads the identity from dir, whichever form Detect finds. For
// identity.age the passphrase is required and wiped before returning;
// for identity.txt it is ignored. The result is the caller's to wipe.
func Load(dir string, passphrase []byte) ([]byte, error) {
	form, err := Detect(dir)
	if err != nil {
		return nil, err
	}
	switch form {
	case FormPlain:
		return LoadFile(filepath.Join(dir, PlainFile), passphrase)
	case FormEncrypted:
		return LoadFile(filepath.Join(dir, EncryptedFile), passphrase)
	case FormNone:
		return nil, ErrNotFound
	}
	return nil, ErrNotFound
}

// LoadFile reads one identity file; its base name decides the form
// (identity.age is passphrase-protected, identity.txt is plain). Any
// other name is ErrMalformed, a missing file is ErrNotFound. The
// passphrase is wiped when it was needed.
func LoadFile(path string, passphrase []byte) ([]byte, error) {
	switch filepath.Base(path) {
	case PlainFile:
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, wrapNotFound(err)
		}
		return validate(data)
	case EncryptedFile:
		defer wipe(passphrase)
		f, err := os.Open(path)
		if err != nil {
			return nil, wrapNotFound(err)
		}
		defer f.Close()
		if len(passphrase) == 0 {
			return nil, ErrWrongPassphrase
		}
		id, err := age.NewScryptIdentity(string(passphrase))
		if err != nil {
			return nil, fmt.Errorf("identity: %w", err)
		}
		r, err := age.Decrypt(f, id)
		if err != nil {
			if _, ok := errors.AsType[*age.NoIdentityMatchError](err); ok {
				return nil, ErrWrongPassphrase
			}
			return nil, fmt.Errorf("identity: decrypt: %w", err)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("identity: decrypt: %w", err)
		}
		return validate(data)
	}
	return nil, fmt.Errorf("%w: %s is neither %s nor %s", ErrMalformed, filepath.Base(path), EncryptedFile, PlainFile)
}

func wrapNotFound(err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	}
	return fmt.Errorf("identity: %w", err)
}

func validate(data []byte) ([]byte, error) {
	defer wipe(data)
	out := bytes.Clone(bytes.TrimSpace(data))
	if _, err := Parse(out); err != nil {
		wipe(out)
		return nil, err
	}
	return out, nil
}

func wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return !errors.Is(err, fs.ErrNotExist)
}
