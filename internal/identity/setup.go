package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alexjoedt/keycell/internal/vault"
)

// removeFile is os.Remove; tests replace it to abort a form change.
var removeFile = os.Remove

var (
	// ErrExists: Init found a vault or identity file in the directory.
	ErrExists = errors.New("identity: directory already initialized")
	// ErrWrongForm: the operation needs the other identity form.
	ErrWrongForm = errors.New("identity: wrong identity form")
)

// Init creates dir (0700), a fresh identity and an empty vault encrypted
// to it. A nil passphrase stores the identity as identity.txt; anything
// else as identity.age. It refuses if any of the files already exist.
func Init(dir string, passphrase []byte) error {
	defer wipe(passphrase)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: init: %w", err)
	}
	if form, err := Detect(dir); err != nil || form != FormNone {
		return ErrExists
	}
	vaultPath := filepath.Join(dir, vault.File)
	if exists(vaultPath) {
		return ErrExists
	}
	encoded, err := Generate()
	if err != nil {
		return err
	}
	defer wipe(encoded)
	id, err := Parse(encoded)
	if err != nil {
		return err
	}
	if passphrase == nil {
		err = WritePlain(filepath.Join(dir, PlainFile), encoded)
	} else {
		err = WriteEncrypted(filepath.Join(dir, EncryptedFile), encoded, passphrase)
	}
	if err != nil {
		return err
	}
	return vault.Write(vaultPath, id, vault.New())
}

// ChangePassphrase re-encrypts identity.age with next, keeping the previous
// file as identity.age.bak. A wrong old passphrase changes nothing.
func ChangePassphrase(dir string, old, next []byte) error {
	defer wipe(next)
	encoded, err := load(dir, FormEncrypted, old)
	if err != nil {
		return err
	}
	defer wipe(encoded)
	return WriteEncrypted(filepath.Join(dir, EncryptedFile), encoded, next)
}

// SetPassphrase turns identity.txt into identity.age. The new file is
// written before the old one is removed; an abort in between leaves both,
// which Load reports as ErrAmbiguous.
func SetPassphrase(dir string, passphrase []byte) error {
	defer wipe(passphrase)
	encoded, err := load(dir, FormPlain, nil)
	if err != nil {
		return err
	}
	defer wipe(encoded)
	if err := WriteEncrypted(filepath.Join(dir, EncryptedFile), encoded, passphrase); err != nil {
		return err
	}
	return remove(filepath.Join(dir, PlainFile))
}

// RemovePassphrase turns identity.age into identity.txt, in the same
// write-then-remove order as SetPassphrase.
func RemovePassphrase(dir string, passphrase []byte) error {
	encoded, err := load(dir, FormEncrypted, passphrase)
	if err != nil {
		return err
	}
	defer wipe(encoded)
	if err := WritePlain(filepath.Join(dir, PlainFile), encoded); err != nil {
		return err
	}
	return remove(filepath.Join(dir, EncryptedFile))
}

func load(dir string, want Form, passphrase []byte) ([]byte, error) {
	form, err := Detect(dir)
	if err != nil {
		wipe(passphrase)
		return nil, err
	}
	if form != want {
		wipe(passphrase)
		return nil, fmt.Errorf("%w: have %s, need %s", ErrWrongForm, form, want)
	}
	return Load(dir, passphrase)
}

func remove(path string) error {
	if err := removeFile(path); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	return nil
}
