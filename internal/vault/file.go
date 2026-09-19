package vault

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	"filippo.io/age"

	"github.com/alexjoedt/keycell/internal/atomicfile"
)

// File is the name of the encrypted vault inside the data directory.
const File = "vault.age"

// ErrWrongIdentity: the file is not encrypted to the given identity.
var ErrWrongIdentity = errors.New("vault: file does not match identity")

// Read decrypts the vault at path with id. The plaintext buffer is wiped
// before returning; the values inside the result are the caller's to Wipe.
func Read(path string, id *age.X25519Identity) (*Vault, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	defer f.Close()
	r, err := age.Decrypt(f, id)
	if err != nil {
		if _, ok := errors.AsType[*age.NoIdentityMatchError](err); ok {
			return nil, ErrWrongIdentity
		}
		return nil, fmt.Errorf("vault: decrypt %s: %w", path, err)
	}
	plain, err := io.ReadAll(r)
	defer wipe(plain)
	if err != nil {
		return nil, fmt.Errorf("vault: decrypt %s: %w", path, err)
	}
	return Decode(plain)
}

// Write encrypts v to id and replaces path atomically, keeping the
// previous file as path+".bak". On failure the old file is untouched.
func Write(path string, id *age.X25519Identity, v *Vault) error {
	plain, err := Encode(v)
	if err != nil {
		return err
	}
	defer wipe(plain)
	var enc bytes.Buffer
	w, err := age.Encrypt(&enc, id.Recipient())
	if err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}
	if _, err := w.Write(plain); err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("vault: encrypt: %w", err)
	}
	if err := atomicfile.Write(path, enc.Bytes(), 0o600, true); err != nil {
		return fmt.Errorf("vault: %w", err)
	}
	return nil
}

func wipe(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}
