package keycell

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/alexjoedt/keycell/internal/vault"
)

func TestSecretLifecycle(t *testing.T) {
	ctx := context.Background()
	d := startDaemon(t)
	c := d.client(t)
	d.unlock(t, c)

	token := NewValue([]byte("ghp_first"))
	defer token.Destroy()
	sec := Secret{
		Name:       "github.com/alex",
		Kind:       "git-credential",
		Attributes: map[string]string{"host": "github.com", "username": "alex"},
		Value:      token,
	}
	if err := c.Store(ctx, sec); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(token.Expose(), []byte("ghp_first")) {
		t.Fatal("Store touched the caller's value")
	}

	got, err := c.Get(ctx, sec.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Value.Destroy()
	if !bytes.Equal(got.Value.Expose(), []byte("ghp_first")) {
		t.Fatalf("Get value = %q", got.Value.Expose())
	}
	if got.Kind != sec.Kind || got.Attributes["username"] != "alex" || got.Created.IsZero() || got.Updated.IsZero() {
		t.Fatalf("Get = %+v", got)
	}

	second := NewValue([]byte("ghp_second"))
	defer second.Destroy()
	sec.Value = second
	if err := c.Store(ctx, sec); err != nil {
		t.Fatal(err)
	}
	again, err := c.Get(ctx, sec.Name)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Value.Destroy()
	if !bytes.Equal(again.Value.Expose(), []byte("ghp_second")) {
		t.Fatalf("upsert: Get value = %q", again.Value.Expose())
	}

	list, err := c.List(ctx, Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != sec.Name || list[0].Value != nil {
		t.Fatalf("List = %+v", list)
	}
	filtered, err := c.List(ctx, Filter{Kind: "docker-registry"})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 0 {
		t.Fatalf("filtered List = %+v", filtered)
	}
	filtered, err = c.List(ctx, Filter{Prefix: "github.com/", Attributes: map[string]string{"host": "github.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(filtered) != 1 {
		t.Fatalf("attribute List = %+v", filtered)
	}

	if err := c.Delete(ctx, sec.Name); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx, sec.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second Delete = %v, want ErrNotFound", err)
	}
	if _, err := c.Get(ctx, sec.Name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
}

func TestSecretErrors(t *testing.T) {
	ctx := context.Background()
	d := startDaemon(t)
	c := d.client(t)

	if _, err := c.Get(ctx, "x"); !errors.Is(err, ErrLocked) {
		t.Fatalf("Get locked = %v, want ErrLocked", err)
	}
	if _, err := c.List(ctx, Filter{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("List locked = %v, want ErrLocked", err)
	}
	if err := c.Store(ctx, Secret{Name: "x", Kind: "k"}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Store nil value = %v, want ErrInvalidArgument", err)
	}

	d.unlock(t, c)
	v := NewValue([]byte("v"))
	defer v.Destroy()
	if err := c.Store(ctx, Secret{Name: " padded", Kind: "k", Value: v}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Store bad name = %v, want ErrInvalidArgument", err)
	}
	if err := c.Store(ctx, Secret{Name: "ok", Kind: "", Value: v}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Store empty kind = %v, want ErrInvalidArgument", err)
	}
}

func TestSecretMaxValue(t *testing.T) {
	ctx := context.Background()
	d := startDaemon(t)
	c := d.client(t)
	d.unlock(t, c)

	big := bytes.Repeat([]byte{0xab}, vault.MaxValueLen)
	v := NewValue(bytes.Clone(big))
	defer v.Destroy()
	if err := c.Store(ctx, Secret{Name: "big", Kind: "blob", Value: v}); err != nil {
		t.Fatal(err)
	}
	got, err := c.Get(ctx, "big")
	if err != nil {
		t.Fatal(err)
	}
	defer got.Value.Destroy()
	if !bytes.Equal(got.Value.Expose(), big) {
		t.Fatalf("1 MiB value round trip differs (len %d)", len(got.Value.Expose()))
	}

	over := NewValue(bytes.Repeat([]byte{1}, vault.MaxValueLen+1))
	defer over.Destroy()
	if err := c.Store(ctx, Secret{Name: "over", Kind: "blob", Value: over}); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("Store over limit = %v, want ErrInvalidArgument", err)
	}
}
