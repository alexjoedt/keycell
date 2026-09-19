package keycell

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/alexjoedt/keycell/internal/config"
	"github.com/alexjoedt/keycell/internal/identity"
	"github.com/alexjoedt/keycell/internal/protocol"
)

// Fehlerwerte. Antworten des Daemons werden auf diese Werte abgebildet und
// sind mit errors.Is prüfbar; die Originalmeldung bleibt über %w erhalten.
var (
	// ErrNotRunning: kein Daemon am Socket. Nicht zu verwechseln mit ErrLocked.
	ErrNotRunning = errors.New("daemon not running")
	// ErrLocked: der Daemon läuft, ist aber gesperrt.
	ErrLocked = errors.New("daemon is locked")
	// ErrNotFound: kein Secret mit diesem Namen.
	ErrNotFound = errors.New("secret not found")
	// ErrInvalidArgument: Name, Kind, Attribute oder Value verletzen die
	// Regeln des Protokolls (z.B. Value über 1 MiB).
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrProtocol: Client und Daemon verstehen sich nicht.
	ErrProtocol = errors.New("protocol error")
	// ErrInternal: Fehler im Daemon, nichts, was der Aufrufer beheben kann.
	ErrInternal = errors.New("internal daemon error")
)

// Secret ist ein Datensatz im Vault. In Ergebnissen von List ist Value nil.
type Secret struct {
	Name       string
	Kind       string
	Attributes map[string]string
	Value      *Value
	Created    time.Time
	Updated    time.Time
}

// Filter schränkt List ein. Nullwerte filtern nicht. Alle gesetzten
// Bedingungen müssen zutreffen.
type Filter struct {
	Kind       string
	Prefix     string
	Attributes map[string]string
}

// Status ist die Antwort des Daemons auf eine Statusanfrage.
type Status struct {
	Protocol int
	Locked   bool
	// LocksAt ist der Zeitpunkt des nächsten Auto-Lock; Nullwert, wenn
	// gesperrt oder Auto-Lock deaktiviert.
	LocksAt time.Time
}

// Client spricht mit einem keycelld über dessen Unix-Socket.
// Ein Client hält keine offene Verbindung; jeder Aufruf öffnet eine.
type Client struct {
	socket string
}

// Connect findet den Socket wie die CLI ($KEYCELL_SOCKET, dann config.json,
// dann $XDG_RUNTIME_DIR/keycell/keycell.sock) und prüft per Statusanfrage,
// dass ein Daemon antwortet. Kein Daemon: ErrNotRunning.
func Connect(ctx context.Context) (*Client, error) {
	cfg, err := config.Load("", os.Getenv, config.Flags{})
	if err != nil {
		return nil, fmt.Errorf("keycell: connect: %w", err)
	}
	return ConnectSocket(ctx, cfg.Socket)
}

// ConnectSocket ist Connect mit explizitem Socket-Pfad (Tests, Zweit-Setups).
func ConnectSocket(ctx context.Context, path string) (*Client, error) {
	c := &Client{socket: path}
	if _, err := c.Status(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

// Socket ist der Pfad, den dieser Client benutzt.
func (c *Client) Socket() string { return c.socket }

// Get holt ein Secret samt Value. Der Aufrufer besitzt den Value und ruft
// Destroy, sobald er ihn nicht mehr braucht.
func (c *Client) Get(ctx context.Context, name string) (*Secret, error) {
	var res protocol.GetResult
	if err := c.call(ctx, protocol.MethodGet, protocol.GetParams{Name: name}, &res); err != nil {
		return nil, err
	}
	sec := fromInfo(res.SecretInfo)
	sec.Value = NewValue(res.Value)
	return &sec, nil
}

// Store legt ein Secret an oder überschreibt es (Upsert). Gelesen werden
// Name, Kind, Attributes und Value; Created und Updated setzt der Daemon.
// Der Value bleibt im Besitz des Aufrufers.
func (c *Client) Store(ctx context.Context, s Secret) error {
	if s.Value == nil || s.Value.Expose() == nil {
		return fmt.Errorf("keycell: store: %w: value is nil", ErrInvalidArgument)
	}
	return c.call(ctx, protocol.MethodStore, protocol.StoreParams{
		Name:       s.Name,
		Kind:       s.Kind,
		Attributes: s.Attributes,
		Value:      s.Value.Expose(),
	}, nil)
}

// Delete entfernt ein Secret. Unbekannter Name: ErrNotFound.
func (c *Client) Delete(ctx context.Context, name string) error {
	return c.call(ctx, protocol.MethodDelete, protocol.DeleteParams{Name: name}, nil)
}

// List liefert die passenden Secrets ohne Value.
func (c *Client) List(ctx context.Context, f Filter) ([]Secret, error) {
	var res protocol.ListResult
	if err := c.call(ctx, protocol.MethodList, protocol.ListParams(f), &res); err != nil {
		return nil, err
	}
	secs := make([]Secret, len(res))
	for i, info := range res {
		secs[i] = fromInfo(info)
	}
	return secs, nil
}

func fromInfo(info protocol.SecretInfo) Secret {
	return Secret{
		Name:       info.Name,
		Kind:       info.Kind,
		Attributes: info.Attributes,
		Created:    info.Created,
		Updated:    info.Updated,
	}
}

// Unlock entsperrt den Daemon mit einer Identity (32 Byte, siehe
// LoadIdentity) und der konfigurierten Auto-Lock-Dauer. Bei bereits
// entsperrtem Daemon passiert nichts. Die Identity wird nach dem Senden
// genullt.
func (c *Client) Unlock(ctx context.Context, identity []byte) error {
	return c.unlock(ctx, identity, nil)
}

// UnlockFor ist Unlock mit eigener Auto-Lock-Dauer; 0 schaltet den
// Auto-Lock für diese Sitzung ab.
func (c *Client) UnlockFor(ctx context.Context, identity []byte, d time.Duration) error {
	secs := int64(d / time.Second)
	return c.unlock(ctx, identity, &secs)
}

func (c *Client) unlock(ctx context.Context, identity []byte, secs *int64) error {
	defer clear(identity)
	return c.call(ctx, protocol.MethodUnlock, protocol.UnlockParams{Identity: identity, For: secs}, nil)
}

// Lock sperrt den Daemon. Laufende Requests werden noch beantwortet.
func (c *Client) Lock(ctx context.Context) error {
	return c.call(ctx, protocol.MethodLock, protocol.Empty{}, nil)
}

// Status fragt den Zustand des Daemons ab; funktioniert auch gesperrt.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var res protocol.StatusResult
	if err := c.call(ctx, protocol.MethodStatus, protocol.Empty{}, &res); err != nil {
		return Status{}, err
	}
	st := Status{Protocol: res.Protocol, Locked: res.Locked}
	if res.LocksAt != nil {
		st.LocksAt = *res.LocksAt
	}
	return st, nil
}

// LoadIdentity liest eine Identity-Datei und liefert die rohen 32 Byte.
// Eine passphrase-verschlüsselte Datei (identity.age) braucht die
// Passphrase; eine unverschlüsselte ignoriert sie. Falsche Passphrase:
// ErrInvalidArgument. Passphrase und Zwischenpuffer werden genullt.
func LoadIdentity(path string, passphrase []byte) ([]byte, error) {
	id, err := identity.LoadFile(path, passphrase)
	switch {
	case err == nil:
		return id, nil
	case errors.Is(err, identity.ErrNotFound):
		return nil, fmt.Errorf("keycell: load identity: %w: %w", ErrNotFound, err)
	case errors.Is(err, identity.ErrWrongPassphrase), errors.Is(err, identity.ErrMalformed):
		return nil, fmt.Errorf("keycell: load identity: %w: %w", ErrInvalidArgument, err)
	}
	return nil, fmt.Errorf("keycell: load identity: %w", err)
}

// Error ist die Fehlerantwort des Daemons mit Code und Meldung. Unwrap
// liefert den passenden Sentinel, sodass errors.Is(err, ErrLocked) greift.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func (e *Error) Unwrap() error {
	switch e.Code {
	case protocol.CodeLocked:
		return ErrLocked
	case protocol.CodeNotFound:
		return ErrNotFound
	case protocol.CodeInvalidArgument:
		return ErrInvalidArgument
	case protocol.CodeInternal:
		return ErrInternal
	default:
		// PROTOCOL und unbekannte Codes (Daemon neuer als Client).
		return ErrProtocol
	}
}
