package keycell

import (
	"errors"
	"runtime"
)

// Value trägt den geheimen Payload eines Secrets und gibt ihn wieder frei.
//
// Expose liefert den internen Puffer ohne Kopie; er ist gültig, bis Destroy
// gerufen wird, und darf nicht darüber hinaus behalten werden. Destroy
// nullt den Puffer und ist idempotent; danach liefert Expose nil.
//
// Value ist nie über fmt oder JSON lesbar: String liefert "[redacted]",
// MarshalJSON einen Fehler. Wird Destroy vergessen, nullt ein GC-Cleanup
// den Puffer irgendwann; das ist Best-Effort, keine Garantie.
type Value struct {
	b []byte
}

// NewValue nimmt b in Besitz; der Aufrufer benutzt b danach nicht mehr.
func NewValue(b []byte) *Value {
	v := &Value{b: b}
	runtime.AddCleanup(v, func(b []byte) { clear(b) }, b)
	return v
}

// Expose liefert den Payload; nil nach Destroy.
func (v *Value) Expose() []byte {
	if v == nil {
		return nil
	}
	return v.b
}

// Destroy nullt den Payload. Idempotent.
func (v *Value) Destroy() {
	if v == nil || v.b == nil {
		return
	}
	clear(v.b)
	runtime.KeepAlive(v.b)
	v.b = nil
}

// String implementiert fmt.Stringer und verrät nichts.
func (v *Value) String() string { return "[redacted]" }

// MarshalJSON verweigert; Werte verlassen den Prozess nur bewusst.
func (v *Value) MarshalJSON() ([]byte, error) {
	return nil, errors.New("keycell: Value is not serialisable")
}
