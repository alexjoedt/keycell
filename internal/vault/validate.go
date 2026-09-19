package vault

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Limits from the protocol specification (wayfinder ticket 06).
const (
	MaxNameLen  = 256         // bytes
	MaxKindLen  = 64          // bytes
	MaxValueLen = 1024 * 1024 // bytes
)

// Validation errors. Each is wrapped with the offending field so callers
// can both match with errors.Is and show the message as is.
var (
	ErrEmptyName      = errors.New("name is empty")
	ErrNameTooLong    = errors.New("name exceeds 256 bytes")
	ErrInvalidUTF8    = errors.New("not valid UTF-8")
	ErrControlChar    = errors.New("contains a control character")
	ErrEdgeWhitespace = errors.New("has leading or trailing whitespace")
	ErrInvalidKind    = errors.New("kind must match [a-z0-9-]{1,64}")
	ErrInvalidAttrKey = errors.New("attribute key must match [a-z0-9-]{1,64}")
	ErrValueTooLarge  = errors.New("value exceeds 1 MiB")
)

// ValidateName checks a secret name. Hierarchy with "/" is convention, not
// syntax, so the only rules are size and printable UTF-8.
func ValidateName(name string) error {
	return validateText("name", name, ErrEmptyName, ErrNameTooLong)
}

// ValidateKind checks a kind identifier.
func ValidateKind(kind string) error {
	if !isSlug(kind) {
		return fmt.Errorf("kind %q: %w", kind, ErrInvalidKind)
	}
	return nil
}

// ValidateAttributes checks keys as identifiers and values like names.
func ValidateAttributes(attrs map[string]string) error {
	for k, v := range attrs {
		if !isSlug(k) {
			return fmt.Errorf("attribute %q: %w", k, ErrInvalidAttrKey)
		}
		if err := validateText("attribute "+k, v, ErrEmptyName, ErrNameTooLong); err != nil {
			return err
		}
	}
	return nil
}

// ValidateValue checks the size limit.
func ValidateValue(value []byte) error {
	if len(value) > MaxValueLen {
		return fmt.Errorf("value is %d bytes: %w", len(value), ErrValueTooLarge)
	}
	return nil
}

// ValidateSecret checks all fields of s under the given name.
func ValidateSecret(name string, s *Secret) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := ValidateKind(s.Kind); err != nil {
		return err
	}
	if err := ValidateAttributes(s.Attributes); err != nil {
		return err
	}
	return ValidateValue(s.Value)
}

func validateText(field, s string, empty, tooLong error) error {
	switch {
	case s == "":
		return fmt.Errorf("%s: %w", field, empty)
	case len(s) > MaxNameLen:
		return fmt.Errorf("%s: %w", field, tooLong)
	case !utf8.ValidString(s):
		return fmt.Errorf("%s: %w", field, ErrInvalidUTF8)
	case strings.ContainsFunc(s, unicode.IsControl):
		return fmt.Errorf("%s: %w", field, ErrControlChar)
	case strings.TrimSpace(s) != s:
		return fmt.Errorf("%s: %w", field, ErrEdgeWhitespace)
	}
	return nil
}

func isSlug(s string) bool {
	if s == "" || len(s) > MaxKindLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}
