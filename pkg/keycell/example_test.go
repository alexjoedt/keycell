package keycell_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/pkg/keycell"
)

// TestMain runs the examples against a real daemon: unlocked, seeded with
// the two secrets they use, socket published via KEYCELL_SOCKET, and an
// identity.age with passphrase "..." under $XDG_DATA_HOME/keycell.
func TestMain(m *testing.M) {
	code, err := runExamples(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "example setup:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runExamples(m *testing.M) (int, error) {
	tmp, err := os.MkdirTemp("", "keycell-examples")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)
	dataDir := filepath.Join(tmp, "keycell")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return 0, err
	}

	socket, id, stop, err := keycell.StartTestDaemon(dataDir, tmp)
	if err != nil {
		return 0, err
	}
	defer func() { _ = stop() }()
	os.Setenv("KEYCELL_SOCKET", socket)
	os.Setenv("XDG_DATA_HOME", tmp)

	if err := identity.WriteEncrypted(filepath.Join(dataDir, identity.EncryptedFile), bytes.Clone(id), []byte("...")); err != nil {
		return 0, err
	}

	ctx := context.Background()
	client, err := keycell.ConnectSocket(ctx, socket)
	if err != nil {
		return 0, err
	}
	if err := client.Unlock(ctx, id); err != nil {
		return 0, err
	}
	seed := []keycell.Secret{
		{Name: "github/token", Kind: "api-token", Value: keycell.NewValue([]byte("ghp_example"))},
		{Name: "github.com/alex", Kind: "git-credential", Attributes: map[string]string{"host": "github.com", "username": "alex"}, Value: keycell.NewValue([]byte("ghp_example"))},
	}
	for _, s := range seed {
		if err := client.Store(ctx, s); err != nil {
			return 0, err
		}
		s.Value.Destroy()
	}
	return m.Run(), nil
}

// Der Common Case: ein Token holen, benutzen, freigeben.
func Example_get() {
	ctx := context.Background()
	client, err := keycell.Connect(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	s, err := client.Get(ctx, "github/token")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	defer s.Value.Destroy()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	req.Header.Set("Authorization", "Bearer "+string(s.Value.Expose()))
	fmt.Println(s.Name, s.Kind, req.Header.Get("Authorization") != "")
	// Output: github/token api-token true
}

// Fehler unterscheiden: nicht gestartet, gesperrt, unbekannt.
func Example_errors() {
	ctx := context.Background()
	_, err := keycell.ConnectSocket(ctx, "/nonexistent/keycell.sock")
	if errors.Is(err, keycell.ErrNotRunning) {
		fmt.Println("start with: systemctl --user start keycell")
	}

	client, err := keycell.Connect(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
	_, err = client.Get(ctx, "no/such/secret")
	switch {
	case errors.Is(err, keycell.ErrLocked):
		fmt.Println("run: keycell unlock")
	case errors.Is(err, keycell.ErrNotFound):
		fmt.Println("no such secret")
	}
	// Output:
	// start with: systemctl --user start keycell
	// no such secret
}

// Ein Secret anlegen; der Value gehört dem Aufrufer.
func Example_store() {
	ctx := context.Background()
	client, _ := keycell.Connect(ctx)

	token := keycell.NewValue([]byte("ghp_..."))
	defer token.Destroy()

	err := client.Store(ctx, keycell.Secret{
		Name:       "github.com/alex",
		Kind:       "git-credential",
		Attributes: map[string]string{"host": "github.com", "username": "alex"},
		Value:      token,
	})
	fmt.Println(err)
	// Output: <nil>
}

// Suchen ohne Values über den Socket zu ziehen.
func Example_list() {
	ctx := context.Background()
	client, _ := keycell.Connect(ctx)

	secrets, _ := client.List(ctx, keycell.Filter{
		Kind:       "git-credential",
		Attributes: map[string]string{"host": "github.com"},
	})
	for _, s := range secrets {
		fmt.Println(s.Name, s.Attributes["username"], s.Value == nil) // List trägt keine Values
	}
	// Output: github.com/alex alex true
}

// Entsperren aus einer Anwendung heraus, ohne age-Import.
func Example_unlock() {
	ctx := context.Background()
	client, _ := keycell.Connect(ctx)

	passphrase := []byte("...") // vom TTY gelesen
	identity, err := keycell.LoadIdentity(os.ExpandEnv("$XDG_DATA_HOME/keycell/identity.age"), passphrase)
	if err != nil {
		fmt.Println(err)
		return
	}
	err = client.Unlock(ctx, identity) // nullt identity nach dem Senden
	fmt.Println(err)
	// Output: <nil>
}
